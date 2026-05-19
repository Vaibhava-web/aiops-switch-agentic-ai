#!/usr/bin/env python3
import json
import re
import subprocess
import time
from datetime import datetime, timedelta
import urllib.request
from datetime import datetime, timedelta, timezone

#from torch import device
from config_manager import load_config, get_config

IST_OFFSET = timedelta(hours=5, minutes=30)


def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors="ignore")
    except Exception:
        return ""


def ist_timestamp(ts=None):
    if ts is None:
        ts = time.time()

    utc_dt = datetime.fromtimestamp(ts, timezone.utc)   # timezone-aware UTC
    ist_dt = utc_dt.astimezone(timezone(IST_OFFSET))    # convert to IST

    return ist_dt.strftime("%Y-%m-%d %H:%M:%S")

def normalize_proc_name(name):
    return name.lower().strip()


def extract_base_process(cmdline):
    cmdline = cmdline.strip()

    # Case 1: /bin/process
    if cmdline.startswith("/"):
        return cmdline.split("/")[-1].split()[0].lower()

    # Case 2: sshd: something
    if ":" in cmdline:
        return cmdline.split(":")[0].lower()

    return cmdline.split()[0].lower()

def list_target_pids(target_processes):
    output = run("ps -ef")
    pid_map = {}

    for line in output.splitlines():
        line = line.strip()
        if not line or "grep" in line or line.startswith("PID"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        pid = parts[0]
        cmdline = line
        #print("DEBUG LINE:", cmdline)

        base_proc = extract_base_process(cmdline)

        # skip kernel threads
        if base_proc.startswith("[") and base_proc.endswith("]"):
            continue

        for proc in target_processes:
            proc_norm = normalize_proc_name(proc)

            #  SPECIAL CASE: sshd (config-based process)
            if proc_norm == "sshd":
                if "sshd:" in cmdline and "[listener]" in cmdline:
                    # ignore sshfs variant
                    if "sshfs" in cmdline:
                        continue

                    # prefer sshd_cfg_* only
                    if "sshd_cfg_" in cmdline:
                        pid_map[proc_norm] = {pid}  # override with correct instance
                    else:
                        pid_map.setdefault(proc_norm, set()).add(pid)
                continue

            #  GENERIC CASE: /bin processes
            if cmdline.startswith("/bin/"):
                base = cmdline.split("/")[-1].split()[0].lower()
                if base == proc_norm:
                    pid_map.setdefault(proc_norm, set()).add(pid)

    return {k: sorted(v) for k, v in pid_map.items()}


def read_heap_kb(pid):
    smaps_path = f"/proc/{pid}/smaps"
    total_heap = 0
    inside_heap = False

    try:
        with open(smaps_path, "r") as f:
            for line in f:
                line = line.strip()

                if "[heap]" in line:
                    inside_heap = True
                    continue

                if inside_heap and "Size:" in line:
                    m = re.search(r"Size:\s+(\d+)\s+kB", line)
                    if m:
                        total_heap += int(m.group(1))
                    inside_heap = False

    except Exception as e:
        print(f"[HEAP ERROR] PID {pid}:", e)
        return 0

    return total_heap


def post_heap(record, heap_url):
    try:
        req = urllib.request.Request(
            heap_url,
            data=json.dumps(record).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception as e:
        print(f"[HEAP POST ERROR] {record.get('process')} PID {record.get('pid')}: {e}")


def monitor():
    while True:
        load_config()
        cfg = get_config()

        metrics = cfg.get("metrics", {})
        heap_enabled = bool(metrics.get("heap", False))

        heap_cfg = cfg.get("heap", {})
        target_processes = heap_cfg.get("processes", ["sshd"]) or []
        try:
            interval = max(1, int(heap_cfg.get("interval_sec", 5)))
        except Exception:
            interval = 5

        heap_url = cfg.get("central", {}).get("heap_url", "http://127.0.0.1:5000/heap")

        if not heap_enabled:
            time.sleep(interval)
            continue

        print("\n[CONFIG] mode={} interval={}s targets={}".format(
            cfg.get("mode", "unknown"),
            interval,
            target_processes
        ))
        print(" SCANNING PROCESSES...")

        if not isinstance(target_processes, list):
            target_processes = [target_processes]

        pid_map = list_target_pids(target_processes)
        print("PID MAP:", pid_map if pid_map else "❌ EMPTY")
        print()
        now_epoch = int(time.time())
        now_ist = ist_timestamp(now_epoch)

        for proc_name in target_processes:
            proc_name = str(proc_name).strip()
            if not proc_name:
                continue

            pids = pid_map.get(proc_name, [])
            if not pids:
                print(f" No PID found for {proc_name}")
                continue

            print(f"\n PROCESS: {proc_name}")

            device = cfg.get("device_id")

            if not device:
                raise Exception("device_id missing in config.json")
            for pid in pids:
                heap_kb = read_heap_kb(pid)

                if heap_kb <= 0:
                    print(f"  PID {pid} →  no heap")
                    continue

                print(f"  PID {pid} → HEAP {heap_kb} kB")

                record = {
                    "timestamp": now_ist,
                    "ts": now_epoch,
                    "device": device,
                    "type": "heap_usage",
                    "event": "heap_usage",
                    "process": proc_name,
                    "pid": str(pid),
                    "heap_kb": heap_kb
                }

                post_heap(record, heap_url)

            print("\n----------------------------------------")
        time.sleep(interval)

        print("DEVICE:", device)
        print("HEAP URL:", heap_url)
        print("RECORD:", record)


if __name__ == "__main__":
    monitor()
