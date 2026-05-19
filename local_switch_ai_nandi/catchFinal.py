#!/usr/bin/env python3
import time
import json
import subprocess
import threading
import re
from collections import deque
import os

import urllib.request
from event_schema import build_event
from config_manager import load_config, get_config

def send_telemetry_to_central(data):
    try:
        req = urllib.request.Request(
            "http://10.95.131.72:5000/telemetry",
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        urllib.request.urlopen(req, timeout=0.2)

    except Exception:
        pass


# --- CONFIG ---
FAST_INTERVAL = 1
SLOW_INTERVAL = 1
BASELINE_WINDOW = 60
ENV_CACHE_INTERVAL = 10
MAC_CACHE_INTERVAL = 10
UPLINK_CACHE_INTERVAL = 10
SNMP_FAIL_BACKOFF = 30 
JSON_LOG = "/flash/ai_agent/telemetry.jsonl"
CFG_RELOAD_INTERVAL = 5

# --- STATE ---
env_cache = {"temp": "?", "fan_ok": False, "fan_rpms": "0/0"}
env_cache_cycle = 0
port_hist = {}       
port_state_hist = {} 
flap_ts_hist = {}    
flap_count_hist = {}
ewma_stats = {}      
snmp_fail_cache = {} 
mac_cache = {}
mac_cache_ts = 0
uplink_cache = []
uplink_cache_ts = 0

cpu_hist = deque(maxlen=BASELINE_WINDOW)
mem_hist = deque(maxlen=BASELINE_WINDOW)
flash_hist = deque(maxlen=BASELINE_WINDOW)

ifindex_to_name = {}
latest_system = {"cpu": 0.0, "mem": 0.0, "flash": 0.0}
start_ts = time.time()
last_cfg_load_ts = 0

# --- UI COLORS ---
PINK = "\033[95m"
GRAY = "\033[90m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m" # Dark Blue
BOLD = "\033[1m"
RESET = "\033[0m"
WHITE = "\033[97m"

# --- HELPERS ---
def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except: return ""

def uptime():
    return int(time.time() - start_ts)

def get_timestamp():
    return f"[+{uptime():02d}]"

def fmt_bps(bps):
    bps = float(bps)
    if bps >= 1_000_000: return f"{bps/1_000_000:.1f} Mbps"
    elif bps >= 1_000: return f"{bps/1_000:.1f} kbps"
    else: return f"{bps:.0f} bps"


def runtime_config():
    global last_cfg_load_ts
    now = time.time()

    if now - last_cfg_load_ts > CFG_RELOAD_INTERVAL:
        load_config()
        last_cfg_load_ts = now

    return get_config()


def cfg_interval(name, default):
    cfg = runtime_config()
    perf = cfg.get("performance", {})
    value = perf.get(name, default)
    try:
        return max(0.5, float(value))
    except Exception:
        return float(default)


def cfg_flag(section, key, default=True):
    cfg = runtime_config()
    sec = cfg.get(section, {})
    return bool(sec.get(key, default))

# --- METRIC ENGINES ---
def update_system_metrics():
    global latest_system
    # CPU Logic
    try:
        with open("/proc/stat") as f:
            fields = [float(column) for column in f.readline().strip().split()[1:]]
        idle, total = fields[3], sum(fields)
        if hasattr(update_system_metrics, "prev"):
            prev_idle, prev_total = update_system_metrics.prev
            cpu = 100.0 * (1.0 - (idle - prev_idle) / (total - prev_total))
        else: cpu = 0.0
        update_system_metrics.prev = (idle, total)
    except: cpu = 0.0

    # Memory Logic
    try:
        with open("/proc/meminfo") as f:
            m = {l.split(':')[0]: int(l.split()[1]) for l in f.readlines()[:3]}
            mem = 100.0 * (1 - m['MemAvailable'] / m['MemTotal'])
    except: mem = 0.0

    # Flash Logic
    try:
        df = run("df /flash | tail -1").split()
        flash = float(df[4].strip('%'))
    except: flash = 0.0

    latest_system = {"cpu": round(cpu,1), "mem": round(mem,1), "flash": round(flash,1)}
    cpu_hist.append(cpu); mem_hist.append(mem); flash_hist.append(flash)
    return latest_system

def get_bulk_snmp():
    def walk(oid):
        data = run(f"snmpwalk -t 1 -r 0 -v2c -c public 127.0.0.1 {oid}")
        res = {}
        for l in data.splitlines():
            m = re.search(r'\.(\d+) = \w+: (.*)', l)
            if m: res[int(m.group(1))] = m.group(2).strip().split('(')[-1].split(')')[0]
        return res

    bulk = {
        "oper": walk("IF-MIB::ifOperStatus"), "speed": walk("IF-MIB::ifHighSpeed"),
        "in_oct": walk("IF-MIB::ifHCInOctets"), "out_oct": walk("IF-MIB::ifHCOutOctets"),
        "in_uc": walk("IF-MIB::ifHCInUcastPkts"), "out_uc": walk("IF-MIB::ifHCOutUcastPkts"),
        "in_mc": walk("IF-MIB::ifHCInMulticastPkts"), "out_mc": walk("IF-MIB::ifHCOutMulticastPkts"),
        "in_bc": walk("IF-MIB::ifHCInBroadcastPkts"), "out_bc": walk("IF-MIB::ifHCOutBroadcastPkts"),
        "in_err": walk("IF-MIB::ifInErrors"), "out_err": walk("IF-MIB::ifOutErrors"),
        "in_disc": walk("IF-MIB::ifInDiscards"), "out_disc": walk("IF-MIB::ifOutDiscards")
    }
    return bulk if bulk["oper"] else None

def get_mac_count():
    out = run("snmpwalk -v2c -c public 127.0.0.1 BRIDGE-MIB::dot1dTpFdbPort")
    mac_count = {}
    for l in out.splitlines():
        m = re.search(r'INTEGER: (\d+)', l)
        if m:
            port = int(m.group(1))
            mac_count[port] = mac_count.get(port, 0) + 1
    return mac_count

def get_port_stats(uplinks=None, macs=None, max_ports=None):
    if uplinks is None:
        uplinks = []
    if macs is None:
        macs = {}

    now_t = time.time()
    bulk = get_bulk_snmp()
    if not bulk: return {}
    
    # 4. Dead Port Cleanup
    valid_indexes = set(bulk["oper"].keys())
    for d in [port_hist, ewma_stats, flap_ts_hist, flap_count_hist, snmp_fail_cache, port_state_hist]:
        for idx in list(d.keys()):
            if idx not in valid_indexes:
                d.pop(idx, None)

    rates = {}
    items = sorted(ifindex_to_name.items(), key=lambda x: x[1])
    analyzed = 0

    for idx, name in items:
        if max_ports is not None and analyzed >= max_ports:
            break

        # Skip during active backoff
        if now_t - snmp_fail_cache.get(idx, 0) < SNMP_FAIL_BACKOFF:
            continue

        # If SNMP walk did not include this port → mark failure
        required_keys = ["in_oct", "out_oct"]
        if any(idx not in bulk[k] for k in required_keys):
            snmp_fail_cache[idx] = now_t
            continue

        # --- SUCCESS PATH ---
        # Port is present in bulk walk → clear any previous failure
        snmp_fail_cache.pop(idx, None)

        c = {k: int(bulk[k].get(idx, 0)) for k in [
            "in_oct", "out_oct", "in_uc", "out_uc",
            "in_mc", "out_mc", "in_bc", "out_bc",
            "in_err", "out_err", "in_disc", "out_disc"
        ]}
        in_pps, out_pps, in_bps, out_bps, pps_dev, reset, flap = 0.0, 0.0, 0.0, 0.0, 0.0, False, False
        curr_ewma = 0.0
        burst = False
        in_bc_ratio, in_err_rate, discard_rate, error_ratio = 0.0, 0.0, 0.0, 0.0
        out_err_rate, out_disc_rate = 0.0, 0.0
        
        oper = "up" if str(bulk["oper"].get(idx, "2")).startswith("1") else "down"
        if idx in port_state_hist and port_state_hist[idx] != oper:
            flap_ts_hist[idx] = now_t
            flap_count_hist[idx] = flap_count_hist.get(idx, 0) + 1
            flap = True
        port_state_hist[idx] = oper

        flap_count = flap_count_hist.get(idx, 0)
        recent_flap = (now_t - flap_ts_hist.get(idx, 0)) < 300

        if not recent_flap:
            flap_count_hist[idx] = max(0, flap_count - 1)

        effective_flaps = flap_count_hist.get(idx, 0)
        
        stability_score = max(0, 100 - (effective_flaps * 10))

        if idx in port_hist:
            prev_c, prev_t = port_hist[idx]
            
            # 3. dt Guard with Upper Bound Limit
            dt = now_t - prev_t
            if dt <= 0 or dt > 3: dt = 1.0

            if c["in_oct"] < prev_c["in_oct"] or c["out_oct"] < prev_c["out_oct"]: reset = True

            d_in = max(0, (c["in_uc"] + c["in_mc"] + c["in_bc"]) - (prev_c["in_uc"] + prev_c["in_mc"] + prev_c["in_bc"]))
            d_out = max(0, (c["out_uc"] + c["out_mc"] + c["out_bc"]) - (prev_c["out_uc"] + prev_c["out_mc"] + prev_c["out_bc"]))
            d_bc = max(0, c["in_bc"] - prev_c["in_bc"])
            d_err = max(0, c["in_err"] - prev_c["in_err"])
            d_in_disc = max(0, c["in_disc"] - prev_c["in_disc"])
            d_out_disc = max(0, c["out_disc"] - prev_c["out_disc"])
            d_out_err = max(0, c["out_err"] - prev_c["out_err"])
            
            in_pps, out_pps = d_in / dt, d_out / dt
            in_bps, out_bps = (max(0, c["in_oct"] - prev_c["in_oct"]) * 8) / dt, (max(0, c["out_oct"] - prev_c["out_oct"]) * 8) / dt
            
            alpha = 0.2

            # --- EWMA Handling ---
            if idx not in ewma_stats or reset:
                # Initialize or re-seed after counter reset
                ewma_stats[idx] = in_pps
                curr_ewma = in_pps
            else:
                prev_ewma = ewma_stats[idx]
                curr_ewma = (alpha * in_pps) + ((1 - alpha) * prev_ewma)
                ewma_stats[idx] = curr_ewma

            pps_dev = round(in_pps - curr_ewma, 2)

            burst_threshold = max(curr_ewma * 2, 500)
            burst = in_pps > burst_threshold
            
            # 1. Restored ML Logic
            in_bc_ratio = round(d_bc / d_in, 4) if d_in > 0 else 0.0
            in_err_rate = round(d_err / dt, 2)
            discard_rate = round(d_in_disc / dt, 2)
            out_err_rate = round(d_out_err / dt, 2)
            out_disc_rate = round(d_out_disc / dt, 2)
            error_ratio = round(in_err_rate / max(in_pps, 10.0), 4)

        port_hist[idx] = (c, now_t)
        speed = int(bulk["speed"].get(idx, 0))
        util = min(100.0, round((in_bps / (speed * 1_000_000)) * 100, 2)) if speed > 0 else 0.0

        role = "access"
        if name in uplinks:
            role = "uplink"
        elif in_pps < 1 and out_pps < 1:
            role = "idle"

        rates[name] = {
            "oper": oper, "speed": speed, "util": util, 
            "in_p": round(in_pps, 1), "out_p": round(out_pps, 1), 
            "in_b": in_bps, "out_b": out_bps, "dev": pps_dev, 
            "reset": reset, "flap": (now_t - flap_ts_hist.get(idx, 0)) < 60,
            "stability": stability_score, "burst": burst, "role": role,
            "in_disc": c["in_disc"], "out_disc": c["out_disc"], "mac_count": macs.get(idx, 0),
            "in_bc_ratio": in_bc_ratio, "discard_rate": discard_rate, 
            "in_err_rate": in_err_rate, "out_err_rate": out_err_rate,
            "out_discard_rate": out_disc_rate, "error_ratio": error_ratio, "is_saturated": util > 80
        }
        analyzed += 1
    return rates

# --- LOOPS ---
def fast_loop():
    while True:
        fast_interval = cfg_interval("fast_interval", FAST_INTERVAL)
        if not cfg_flag("metrics", "system", True):
            time.sleep(fast_interval)
            continue

        sys = update_system_metrics()
        cb, mb, fb = sum(cpu_hist)/len(cpu_hist), sum(mem_hist)/len(mem_hist), sum(flash_hist)/len(flash_hist)
        cc, mc, fc = (RED if sys['cpu']>75 else PINK), (RED if sys['mem']>85 else PINK), (RED if sys['flash']>90 else PINK)
        print(f"{get_timestamp()} FAST CPU={cc}{sys['cpu']:.1f}%{RESET}(base {cb:.1f}%) MEM={mc}{sys['mem']:.1f}%{RESET}(base {mb:.1f}%) FLASH={fc}{sys['flash']:.1f}%{RESET}(base {fb:.1f}%)", flush=True)
        
        cfg = runtime_config()

        log = build_event(
            source="telemetry",
            event_type="system_metrics",
            metrics=sys
        )
        log["device"] = cfg.get("device_id", "UNKNOWN")
        log["device_id"] = log["device"]
        log["type"] = "fast"
        log["sys"] = sys
        log["cpu_dev"] = round(sys['cpu']-cb, 2)
        try:
            with open(JSON_LOG, "a") as f: f.write(json.dumps(log) + "\n")
        except: pass
        send_telemetry_to_central(log)

        time.sleep(fast_interval)

def slow_loop():
    global env_cache, env_cache_cycle, mac_cache, mac_cache_ts, uplink_cache, uplink_cache_ts
    while True:
        slow_interval = cfg_interval("slow_interval", SLOW_INTERVAL)
        metrics_cfg = runtime_config().get("metrics", {})
        collect_system = bool(metrics_cfg.get("system", True))
        collect_traffic = bool(metrics_cfg.get("traffic", True))
        collect_env = bool(metrics_cfg.get("environment", False))
        if not (collect_system or collect_traffic or collect_env):
            # All metric domains are disabled: no live metric data should be emitted.
            time.sleep(slow_interval)
            continue

        max_ports = runtime_config().get("performance", {}).get("max_ports_analyzed", 32)

        try:
            max_ports = int(max_ports)
        except Exception:
            max_ports = 32

        if collect_traffic and time.time() - uplink_cache_ts > UPLINK_CACHE_INTERVAL:
            uplinks = []
            out_u = run("snmpwalk -t 1 -r 0 -v2c -c public 127.0.0.1 LLDP-MIB::lldpRemSysCapEnabled")
            for l in out_u.splitlines():
                if any(x in l for x in ["bridge", "router"]):
                    m = re.search(r"\.1\.(\d+)\.\d+", l)
                    if m: uplinks.append(f"1/1/{m.group(1)}")
            uplink_cache = uplinks
            uplink_cache_ts = time.time()
        uplinks = uplink_cache if collect_traffic else []

        if collect_env and env_cache_cycle % ENV_CACHE_INTERVAL == 0:
            out_t = run("snmpwalk -t 1 -r 0 -v2c -c public 127.0.0.1 ALCATEL-IND1-CHASSIS-MIB::chasEntTempCurrent")
            t_m = re.search(r'INTEGER: (\d+)', out_t)
            out_s = run("snmpwalk -t 1 -r 0 -v2c -c public 127.0.0.1 ALCATEL-IND1-CHASSIS-MIB::alaChasEntPhysFanSpeed")
            speeds = re.findall(r'Gauge32: (\d+)', out_s)
            env_cache = {"temp": t_m.group(1) if t_m else "?", "fan_rpms": "/".join(speeds) if speeds else "0/0", "fan_ok": "RUNNING" in run("snmpwalk -v2c -c public 127.0.0.1 ALCATEL-IND1-CHASSIS-MIB::alaChasEntPhysFanStatus").upper()}
        env_cache_cycle += 1
        
        if collect_traffic and time.time() - mac_cache_ts > MAC_CACHE_INTERVAL:
            mac_cache = get_mac_count()
            mac_cache_ts = time.time()
        macs = mac_cache

        ports = {}
        if collect_traffic:
            ports = get_port_stats(uplinks=uplinks, macs=macs, max_ports=max_ports)

        sys_payload = latest_system if collect_system else {}
        env_payload = env_cache if collect_env else {}

        if ports:
            print(f"\n{get_timestamp()} {BOLD}SYSTEM STATUS{RESET}")
            print(f"  CPU: {PINK}{latest_system['cpu']}%{RESET}  MEM: {PINK}{latest_system['mem']}%{RESET}  FLASH: {PINK}{latest_system['flash']}%{RESET}")
            # Adjusted header spacing for the new traffic width
            print(f"\n{GRAY}{'Port':<12} {'Status':<10} {'Speed':<10} {'Util%':<10} {'Traffic (PPS / BPS)':<42}     {'Discards'}{RESET}")
            print(f"{GRAY}{'-'*105}{RESET}")

            for p in sorted(ports.keys()):
                d = ports[p]
                if d['oper'] == 'down' and p not in uplinks: continue
                
                # --- 1. Identify Activity & Set Row Color ---
                is_active = d['in_p'] > 0 or d['out_p'] > 0
                row_color = "" if is_active else GRAY # No color (white) if active, else Gray
                
                # --- 2. Port Name Color Logic ---
                if p in uplinks: 
                    p_name = f"{BLUE}{p:<12}{RESET}"
                elif is_active: 
                    p_name = f"{CYAN}{p:<12}{RESET}"
                else: 
                    p_name = f"{GRAY}{p:<12}{RESET}"
                
                # --- 3. Traffic Formatting (Added space after /) ---
                if is_active:
                    rx_txt = f"{PINK}Rx:{RESET}{d['in_p']:>4.0f}p / {fmt_bps(d['in_b']):<11}"
                    tx_txt = f"{PINK}Tx:{RESET}{d['out_p']:>4.0f}p / {fmt_bps(d['out_b']):<11}"
                else:
                    # Entire traffic block stays grey if idle
                    rx_txt = f"{GRAY}Rx:{d['in_p']:>4.0f}p / {fmt_bps(d['in_b']):<11}{RESET}"
                    tx_txt = f"{GRAY}Tx:{d['out_p']:>4.0f}p / {fmt_bps(d['out_b']):<11}{RESET}"
                
                # --- 4. Apply row_color to middle columns & Shift Discards ---
                # Added 4 spaces before {d['disc']} to move it right
                oper_str = f"{row_color}{d['oper']:<10}{RESET}"
                speed_str = f"{row_color}{str(d['speed'])+'M':<10}{RESET}"
                util_str = f"{row_color}{str(d['util'])+'%':<10}{RESET}"
                disc_str = f"{row_color}{d['in_disc']}/{d['out_disc']}{RESET}"

                row = f"{p_name} {oper_str} {speed_str} {util_str} {rx_txt}  {tx_txt}    {disc_str}"
                
                if d['reset']: row += f" {RED}RESET{RESET}"
                if d['flap']: row += f" {YELLOW}FLAP{RESET}"
                print(row)

            f_ok = f"{GREEN}OK{RESET}" if env_cache['fan_ok'] else f"{RED}FAIL{RESET}"
            print(f"\n{BOLD}ENV{RESET}  Temp={GREEN}{env_cache['temp']}°C{RESET}  Fans: {f_ok} ({env_cache['fan_rpms']} rpm)")
            up_styled = [f"{BLUE}{u}{RESET}" for u in uplinks]
            print(f"     {WHITE}Uplinks (current):{RESET} {', '.join(up_styled)}")

            # 2. Add Chassis Aggregates + JSON telemetry output
            tot_rx = sum(p['in_b']/1_000_000 for p in ports.values())
            tot_tx = sum(p['out_b']/1_000_000 for p in ports.values())
            active_ports = sum(1 for p in ports.values() if p['in_p'] > 1 or p['out_p'] > 1)
            saturated_ports = sum(1 for p in ports.values() if p['is_saturated'])
            
            cfg = runtime_config()

            log = {
                "type": "slow", "ts": int(time.time()),
                "device_id": cfg.get("device_id", "UNKNOWN"),
                "device": cfg.get("device_id", "UNKNOWN"),
                "sys": sys_payload,
                "ports": ports, "env": env_payload, "uplinks": uplinks,
                "enabled_metrics": {
                    "system": collect_system,
                    "traffic": collect_traffic,
                    "environment": collect_env
                },
                "chassis": {
                    "rx_mbps": round(tot_rx, 2), "tx_mbps": round(tot_tx, 2),
                    "active_ports": active_ports, "saturated_ports": saturated_ports
                }
            }
            try:
                with open(JSON_LOG, "a") as f: f.write(json.dumps(log) + "\n")
            except: pass
            send_telemetry_to_central(log)

        else:
            # Keep heartbeat telemetry for all metric permutations.
            cfg = runtime_config()
            log = {
                "type": "slow", "ts": int(time.time()),
                "device_id": cfg.get("device_id", "UNKNOWN"),
                "device": cfg.get("device_id", "UNKNOWN"),
                "sys": sys_payload,
                "ports": {}, "env": env_payload, "uplinks": uplinks,
                "enabled_metrics": {
                    "system": collect_system,
                    "traffic": collect_traffic,
                    "environment": collect_env
                },
                "chassis": {
                    "rx_mbps": 0.0, "tx_mbps": 0.0,
                    "active_ports": 0, "saturated_ports": 0
                }
            }
            try:
                with open(JSON_LOG, "a") as f: f.write(json.dumps(log) + "\n")
            except:
                pass
            send_telemetry_to_central(log)

        time.sleep(slow_interval)

if __name__ == "__main__":
    os.makedirs("/flash/ai_agent", exist_ok=True)
    cfg = runtime_config()
    walk = run("snmpwalk -v2c -c public 127.0.0.1 IF-MIB::ifName")
    for l in walk.splitlines():
        m = re.search(r'ifName\.(\d+) = STRING: (.+)', l)
        if m: ifindex_to_name[int(m.group(1))] = m.group(2)

    threading.Thread(target=fast_loop, daemon=True).start()
    threading.Thread(target=slow_loop, daemon=True).start()
    while True: time.sleep(60)