import subprocess
import time
import threading
import json
import urllib.request
import re

CENTRAL_ML_URL = "http://10.95.131.72:5000/ml"

WATCH_PORTS = {}   # port -> expiry timestamp
ACTIVE_VIOLATIONS = set()

LOCK = threading.Lock()
ROW_RE = re.compile(
    r"(\d+/\d+/\d+)\s+(\S+)\s+(\S.*?\S)\s{2,}(\S.*?\S)\s+(\S+)\s+(\d+)\s+(\S+)"
)


def run_cmd():
    try:
        out = subprocess.check_output(
            ["/vroot/bin/show", "violation"],
            stderr=subprocess.DEVNULL
        ).decode()
        return out
    except Exception:
        return ""


def parse(output):
    results = []

    for line in output.splitlines():
        m = ROW_RE.match(line.strip())
        if not m:
            continue

        try:
            recovery = int(m.group(6))
        except Exception:
            recovery = 300

        results.append({
            "port": m.group(1),
            "reason": m.group(4),
            "recovery": recovery,
            "action": m.group(3)
        })

    return results


def send_violation_message(v):
    ts_epoch = int(time.time())
    ts = time.strftime("%H:%M:%S", time.localtime(ts_epoch))
    msg = (
        f"[ALERT {ts}] CRITICAL (confidence=0.95)\n"
        f"  - Link violation on {v['port']}\n"
        f"  - Reason: {v['reason']}\n"
        f"  - Recovery time: {v['recovery']} sec\n"
    )

    payload = {
        "timestamp": ts,
        "severity": "CRITICAL",
        "message": msg,
        "device": "NANDI",
        "alert_type": "link_violation_cli",
        "timestamp_epoch": ts_epoch,
        "recovery_time": int(v.get("recovery", 300)),
        "violation_port": v.get("port"),
        "violation_reason": v.get("reason")
    }

    try:
        req = urllib.request.Request(
            CENTRAL_ML_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass


def start_watch(port):
    with LOCK:
        WATCH_PORTS[port] = time.time() + 600   # 10 min


def stop_watch(port):
    with LOCK:
        WATCH_PORTS.pop(port, None)
        ACTIVE_VIOLATIONS.discard(port)


def monitor_loop():
    while True:
        time.sleep(10)

        with LOCK:
            now = time.time()

            # remove expired
            expired = [p for p, t in WATCH_PORTS.items() if now > t]
            for p in expired:
                WATCH_PORTS.pop(p, None)

            if not WATCH_PORTS:
                continue

        output = run_cmd()
        violations = parse(output)

        active_ports = set(v["port"] for v in violations)

        for v in violations:
            port = v["port"]

            with LOCK:
                if port not in WATCH_PORTS:
                    continue

                if port in ACTIVE_VIOLATIONS:
                    continue

                ACTIVE_VIOLATIONS.add(port)

            send_violation_message(v)

        # cleanup recovered
        with LOCK:
            recovered = ACTIVE_VIOLATIONS - active_ports
            for p in list(recovered):
                ACTIVE_VIOLATIONS.remove(p)


def start_background():
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()


# AUTO START
start_background()