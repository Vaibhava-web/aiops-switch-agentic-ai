#!/usr/bin/env python3
import random
import math
from sys import prefix
import time
import json
import os
from collections import defaultdict, deque
import statistics
import socket
import threading
import re
import atexit
import urllib.request

from event_schema import build_event
from sequence_model import update_sequence, predict_next
from remediation_engine import decide_action, generate_advisory

from alert_local import send_alert as send_local_alert
from config_manager import load_config, get_config

# ================================
# EDGE VISIBILITY CONTROL
# ================================
EDGE_VISIBILITY = os.getenv("EDGE_VISIBILITY", "true").lower() == "true"

def edge_print(*args, **kwargs):
    if EDGE_VISIBILITY:
        print(*args, **kwargs)

def get_central_ml_url():
    return CONFIG.get("central", {}).get("ml_url", "http://10.95.131.72:5000/ml")

def get_central_ml_timeout():
    try:
        return max(1, float(CONFIG.get("central", {}).get("ml_timeout_sec", 2)))
    except Exception:
        return 2.0

def send_ml_to_central(data):
    url = get_central_ml_url()
    timeout_sec = get_central_ml_timeout()

    for attempt in range(3):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=timeout_sec)
            return True
        except Exception as e:
            edge_print(
                f"[CENTRAL SEND ERROR] url={url} attempt={attempt + 1}/3 "
                f"device={data.get('device_id') or data.get('device') or CONFIG.get('device_id', 'UNKNOWN')} "
                f"err={e}"
            )
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))

    return False

CAUSAL_GRAPH = defaultdict(lambda: defaultdict(int))
PREDICTION_MODEL = defaultdict(lambda: defaultdict(int))
LAST_PREDICT_EVENT = None

LAST_EVENTS = deque(maxlen=20)

STATE_FILE = "/flash/ai_agent/ml_state.jsonl"
IFOREST_WARMUP = 5  # number of initial samples to ignore for stable baseline

TELEMETRY_LOG = "/flash/ai_agent/telemetry.jsonl"
AI_LOG = "/flash/ai_agent/ml_alerts.jsonl"

HISTORY = deque(maxlen=120)

PORT_STATE = {}   # pname -> {"last_state": "up/down", "up_since": ts}
UPTIME_THRESHOLD_SEC = 7 * 24 * 3600   # 7 days

SUPER_CRITICAL_PORTS = set()   # will be filled from LLDP uplinks dynamically

# --- Learned uplink confidence (anti-flap memory) ---
UPLINK_CONFIDENCE = {}   # pname -> score
UPLINK_PROMOTE_SCORE = 5   # require N confirmations before marking super-critical
UPLINK_DOMINANCE_RATIO = 2.5  # ewma must be > 2.5x average traffic

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

STATE = {
    "cpu_spikes": 0,
    "last_cpu_anomaly_ts": None,
    "cpu_samples": 0,
    "last_cpu_cp_alert_ts": 0,
    "last_cpu_alerted": False
}

WARMUP_SAMPLES = 20          # ignore ML alerts until baseline stabilizes
ALERT_COOLDOWN_SEC = 60     # one CPU changepoint alert per minute max

# --- EWMA + CUSUM state (lightweight ML) ---
EWMA_ALPHA = 0.1     # how fast baseline adapts (0.1 slow, 0.3 fast)
CUSUM_K = 5.0        # ignore small fluctuations
CUSUM_H = 20.0        # only large shifts trigger

EWMA_BASELINES = {
    "cpu": None,
    "ports": {}   # pname -> ewma traffic baseline
}

CUSUM_STATE = {
    "cpu_pos": 0.0,
    "cpu_neg": 0.0,
    "ports": {}   # pname -> {"pos": 0.0, "neg": 0.0}
}

ML_RESUME_MESSAGE = None

CORR_WINDOW = 10  # seconds for correlation window

LAST_SAVE_TS = 0

LAST_ALERT_TIME = 0
ALERT_COOLDOWN = 30  # seconds

ACTIVE_ALERTS = {}  # key=alert_type, value={"count": N, "ts": last_alert_time}

RECENT_ANOMALIES = deque(maxlen=20)

PRIORITY_ORDER = [
    "uplink_down",
    "silent_uplink",
    "ml_anomaly",
    "cpu_spike"
]

TOPOLOGY = {}
# format:
# {
#   "switch-1": ["switch-2", "switch-3"],
#   "switch-2": ["switch-1"]
# }

SWLOG_PATH = "/flash/swlog_chassis1"   # adjust if needed

DEVICE_HISTORY = {}   # device_id → recent entries
DEVICE_ANOMALIES = {}  # device_id → anomalies

TRAP_EVENTS = deque(maxlen=100)
SWLOG_BUFFER = deque(maxlen=200)

TRAP_FILE = "/home/tec/working/vaibhav/ai_agent/traps.jsonl"
trap_offset = 0

RECENT_TRAPS = deque(maxlen=50)

# NEW: trap trigger queue (real-time)
TRAP_TRIGGER_QUEUE = deque(maxlen=50)

TRAP_HISTORY = deque(maxlen=20)
UNKNOWN_TRAPS = defaultdict(list)

UNKNOWN_FEATURES = defaultdict(list)
UNKNOWN_LABELS = {}
LOG_COUNTER = defaultdict(int)
LOG_HISTORY = deque(maxlen=100)
LAST_LOG_SENT = 0
LAST_CONFIG_LOAD = 0
ML_SAMPLE_COUNTER = 0

# --- CONFIG ---
load_config()
CONFIG = get_config()
CENTRAL_LOG_URL = CONFIG.get("central", {}).get("log_url", "http://127.0.0.1:5000/ingest_logs")

def send_formatted_alert_to_central(decision, sev):
    try:
        ts = time.strftime("%H:%M:%S", time.localtime(decision.get("timestamp_epoch", time.time())))
        # Create the exact string from your terminal logic
        is_violation = "link_violation" in decision.get("observations", {})

        prefix = "[VIOLATION]" if is_violation else "[ALERT]"
        violation_tag = " link_violation" if is_violation else ""

        text_msg = f"{prefix} {ts} {sev} (confidence={decision['confidence']}){violation_tag}\n"
        for rec in decision.get("recommendations", []):
            text_msg += f"  - {rec}\n"

        payload = {
            "timestamp": ts,
            "severity": sev,
            "message": text_msg,
            "device": decision.get("device_id") or CONFIG.get("device_id", "UNKNOWN"),
            "is_alert": True,
            "is_violation": "link_violation" in decision.get("observations", {})
        }
        # Re-use your existing send_ml_to_central logic but change the path
        send_ml_to_central(payload) # We will handle the routing on the server side
    except Exception as e:
        edge_print(f"[UI SEND ERROR] {e}")

def send_log_to_central(log):
    for attempt in range(3):
        try:
            payload = json.dumps(log).encode("utf-8")
            req = urllib.request.Request(
                CENTRAL_LOG_URL,
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=1)
            return
        except Exception:
            time.sleep(0.5 * (attempt + 1))


def normalize_log(line):
    return re.sub(r"\d+", "N", line).lower()


def score_log(line):
    l = line.lower()
    key = normalize_log(line)
    score = 0

    if len(LOG_COUNTER) > 10000:
        LOG_COUNTER.clear()

    # 1) Rarity
    LOG_COUNTER[key] += 1
    if LOG_COUNTER[key] < 3:
        score += 2

    # 2) Structure signals
    if "event:" in l:
        score += 2
    if "error" in l or "fail" in l:
        score += 2
    if "down" in l or "up" in l:
        score += 1

    # 3) Burst detection
    now = time.time()
    LOG_HISTORY.append((now, key))

    recent = [t for t, _ in LOG_HISTORY if now - t < 3]
    if len(recent) > 5:
        score += 2

    return score

class ITreeNode:
    __slots__ = ("feature", "threshold", "left", "right", "size", "depth")

    def __init__(self, feature=None, threshold=None, left=None, right=None, size=0, depth=0):
        self.feature = feature
        self.threshold = threshold
        self.left = left
        self.right = right
        self.size = size
        self.depth = depth

def c_factor(n):
    # Average path length of unsuccessful search in BST
    if n <= 1:
        return 0
    return 2 * (math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n)

class IsolationForestLite:
    def __init__(self, n_trees=25, sample_size=64, max_depth=10):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.max_depth = max_depth
        self.trees = []
        self.window = deque(maxlen=500)  # rolling training window

    def _build_tree(self, X, depth):
        if depth >= self.max_depth or len(X) <= 1:
            return ITreeNode(size=len(X), depth=depth)

        n_features = len(X[0])
        q = random.randrange(n_features)

        col = [x[q] for x in X]
        min_v, max_v = min(col), max(col)
        if min_v == max_v:
            return ITreeNode(size=len(X), depth=depth)

        p = random.uniform(min_v, max_v)

        left = [x for x in X if x[q] < p]
        right = [x for x in X if x[q] >= p]

        return ITreeNode(
            feature=q,
            threshold=p,
            left=self._build_tree(left, depth + 1),
            right=self._build_tree(right, depth + 1),
            size=len(X),
            depth=depth
        )

    def fit(self):
        self.trees = []
        if len(self.window) < 20:
            return

        for _ in range(self.n_trees):
            sample = random.sample(list(self.window), min(self.sample_size, len(self.window)))
            self.trees.append(self._build_tree(sample, 0))

    def _path_length(self, x, node):
        if node.left is None and node.right is None:
            return node.depth + c_factor(node.size)

        if node.feature is None:
            return node.depth + c_factor(node.size)

        if x[node.feature] < node.threshold:
            return self._path_length(x, node.left)
        else:
            return self._path_length(x, node.right)

    def score(self, x):
        if not self.trees:
            return 0.0

        paths = [self._path_length(x, t) for t in self.trees]
        avg_path = sum(paths) / len(paths)
        cn = c_factor(self.sample_size)

        # Higher score = more anomalous
        score = 2 ** (-avg_path / cn)
        return score

    def update(self, x):
        self.window.append(x)

        # Train as soon as we have enough samples, and retrain periodically
        if len(self.window) >= 20:
            if not self.trees or len(self.window) % 50 == 0:
                self.fit()

# Split models to avoid "noise masking"
SYS_MODEL = IsolationForestLite(n_trees=20, sample_size=64)
TRAF_MODEL = IsolationForestLite(n_trees=20, sample_size=64)
ENV_MODEL  = IsolationForestLite(n_trees=20, sample_size=64)





def read_traps():
    global trap_offset, RECENT_TRAPS

    try:
        with open(TRAP_FILE, "r") as f:
            f.seek(trap_offset)

            try:
                lines = f.readlines()
            except Exception:
                return

            for line in lines:
                try:
                    trap = json.loads(line.strip())

                    # normalize
                    trap["device_id"] = trap.get("src", CONFIG.get("device_id"))
                    trap["source"] = "snmp"
                    if "_processed" not in trap:
                        trap["_processed"] = False

                    RECENT_TRAPS.append(trap)

                    # 🚀 NEW: push to trigger queue
                    if not trap.get("_triggered"):
                        TRAP_TRIGGER_QUEUE.append(trap)
                        trap["_triggered"] = True
                except:
                    continue

            trap_offset = f.tell()

    except FileNotFoundError:
        pass

def map_ifindex_to_port(ifIndex, ifindex_map):
    return ifindex_map.get(ifIndex, f"ifIndex-{ifIndex}")

def correlate_trap_with_telemetry(port, telemetry):

    p = telemetry.get(port, {})

    if not p:
        return None

    # Strong root cause signals
    if p.get("in_err_rate", 0) > 10:
        return "high_errors"

    if p.get("discard_rate", 0) > 10:
        return "congestion"

    if p.get("mac_count", 0) > 50:
        return "possible_flooding"

    return "unknown"

def compute_blast_radius(root_device, max_depth=3):
    """
    Find impacted devices using BFS traversal
    max_depth prevents infinite spread
    """
    visited = set()
    queue = [(root_device, 0)]
    impacted = set()

    while queue:
        current, depth = queue.pop(0)

        if depth > max_depth:
            continue

        if current in visited:
            continue

        visited.add(current)

        neighbors = list(TOPOLOGY.get(current, []))

        for n in neighbors:
            if n not in visited:
                impacted.add(n)
                queue.append((n, depth + 1))

    return list(impacted)

def estimate_blast_radius():
    now = time.time()
    results = []

    for dev, events in DEVICE_ANOMALIES.items():
        recent = [e for e in events if now - e["ts"] < CORR_WINDOW]

        # Only consider strong root signals
        if any(e["type"] in ("uplink", "link") for e in recent):
            impacted = compute_blast_radius(dev)

            if impacted:
                results.append({
                    "root": dev,
                    "impacted": impacted,
                    "count": len(impacted)
                })

    return results

def tail_swlog():
    try:
        global LAST_LOG_SENT
        with open(SWLOG_PATH, "r") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                score = score_log(line)

                if score >= 3:
                    entry = {
                        "ts": time.time(),
                        "msg": line.strip(),
                        "score": score
                    }

                    SWLOG_BUFFER.append(entry)
                    process_syslog(entry["msg"])

                    # Forward scored logs with rate limiting to central analysis.
                    now = time.time()
                    if entry["score"] >= 3 and now - LAST_LOG_SENT > 1:
                        send_log_to_central(entry)
                        LAST_LOG_SENT = now
    except Exception as e:
        edge_print("[SWLOG ERROR]", e)

def get_recent_swlog(window_sec=10):
    now = time.time()
    return [
        l["msg"]
        for l in SWLOG_BUFFER
        if now - l["ts"] <= window_sec
    ]


def read_recent_swlogs(n=20):
    try:
        with open(SWLOG_PATH, "r") as f:
            lines = f.readlines()
            return [ln.strip() for ln in lines[-n:] if ln.strip()]
    except Exception:
        return []

def correlate_topology():
    now = time.time()

    impacts = []

    for dev, neighbors in TOPOLOGY.items():
        dev_events = DEVICE_ANOMALIES.get(dev, [])

        recent_dev = [e for e in dev_events if now - e["ts"] < CORR_WINDOW]

        if not recent_dev:
            continue

        # Check if this device has uplink issue
        has_link_issue = any(e["type"] in ("link", "uplink") for e in recent_dev)

        if not has_link_issue:
            continue

        # Check neighbors for impact
        for n in neighbors:
            n_events = DEVICE_ANOMALIES.get(n, [])
            recent_n = [e for e in n_events if now - e["ts"] < CORR_WINDOW]

            if any(e["type"] == "traffic" for e in recent_n):
                impacts.append((dev, n))

    if impacts:
        msgs = [
            f"{src or 'Network'} issue impacting {dst}"
            for src, dst in impacts
        ]
        return msgs
    return None

def update_topology(device_id, uplinks):
    """
    Very simple topology learning:
    assume uplink ports connect to other switches
    """
    if device_id not in TOPOLOGY:
        TOPOLOGY[device_id] = set()

    # naive mapping: treat each uplink as connection
    # (later you can map LLDP neighbor names)
    for u in uplinks:
        neighbor = f"neighbor-{u}"   # placeholder mapping
        TOPOLOGY[device_id].add(neighbor)
        # prevent uncontrolled growth
        if len(TOPOLOGY[device_id]) > 50:
            TOPOLOGY[device_id] = set(list(TOPOLOGY[device_id])[:50])

        if neighbor not in TOPOLOGY:
            TOPOLOGY[neighbor] = set()

        TOPOLOGY[neighbor].add(device_id)

def pick_root(observations):
    for p in PRIORITY_ORDER:
        if p in observations:
            return p
    return "unknown"

def ewma(prev, x, alpha=EWMA_ALPHA):
    if prev is None:
        return x
    return alpha * x + (1 - alpha) * prev

def cusum_update(prev_pos, prev_neg, x, baseline, k=CUSUM_K, h=CUSUM_H):
    diff = x - baseline
    pos = max(0, prev_pos + diff - k)
    neg = max(0, prev_neg - diff - k)
    triggered = pos > h or neg > h
    return pos, neg, triggered

def tail_file(path):
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)   # start from end

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line

def process_syslog(msg):
    entry = {
        "type": "event",
        "source": "syslog",
        "message": msg.strip(),
        "timestamp_epoch": int(time.time()),
        "device_id": CONFIG.get("device_id")
    }
    print("\n[SYSLOG RAW]", msg.strip())

    try:
        decision = analyze(entry)
        if decision:
            intel_cfg = CONFIG.get("intelligence", {})
            if intel_cfg.get("remediation", False):
                remediate(decision, {})

            with open(AI_LOG, "a") as f:
                f.write(json.dumps(decision) + "\n")

            ts = time.strftime("%H:%M:%S", time.localtime(decision["timestamp_epoch"]))
            sev, color = severity_from_conf(decision["confidence"])

            print(f"{BOLD}{color}[ALERT {ts}] {sev} (confidence={decision['confidence']}){RESET}")
            for rec in decision["recommendations"]:
                print(f"  - {rec}")
            print("")

            # Ensure syslog-origin alerts also reach dashboard_alerts.jsonl via /ml message payload.
            send_formatted_alert_to_central(decision, sev)
            #send_ml_to_central(decision)
    except Exception as e:
        edge_print("[SYSLOG ERROR]", repr(e))

def start_syslog_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))

    edge_print(f"[SYSLOG] Listening on UDP {port}")

    while True:
        data, _ = sock.recvfrom(4096)
        msg = data.decode(errors="ignore")
        process_syslog(msg)

def correlate_multi_switch():
    now = time.time()
    active_devices = []

    for dev, events in DEVICE_ANOMALIES.items():
        recent = [e for e in events if now - e["ts"] < CORR_WINDOW]

        if any(e["type"] == "traffic" for e in recent):
            active_devices.append(dev)

    if len(active_devices) >= 2:
        return f"Network-wide traffic surge across {len(active_devices)} switches"

    return None

def compute_zscore(values, current):
    if len(values) < 10:
        return 0.0
    try:
        mean = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0.001
        return (current - mean) / stdev
    except:
        return 0.0

def ensure_port_state(pname):
    if pname not in PORT_STATE:
        PORT_STATE[pname] = {
            "last_state": None,
            "up_since": None,
            "last_cp_alert_ts": 0,
            "last_silent_alert_ts": 0
        }
    else:
        PORT_STATE[pname].setdefault("last_state", None)
        PORT_STATE[pname].setdefault("up_since", None)
        PORT_STATE[pname].setdefault("last_cp_alert_ts", 0)
        PORT_STATE[pname].setdefault("last_silent_alert_ts", 0)

    return PORT_STATE[pname]

def severity_from_conf(conf):
    if conf >= 0.9:
        return "CRITICAL", RED
    elif conf >= 0.75:
        return "MAJOR", YELLOW
    else:
        return "MINOR", GREEN

def is_physical_port(p):
    return p.startswith("1/1/")

def build_system_features(system):
    cpu = float(system.get("cpu", 0))
    mem = float(system.get("mem", 0))
    flash = float(system.get("flash", 0))

    baseline = EWMA_BASELINES.get("cpu")
    cpu_delta = cpu - baseline if baseline else 0.0

    cpu_norm = normalize(cpu, 100)
    mem_norm = normalize(mem, 100)
    flash_norm = normalize(flash, 100)
    cpu_delta_norm = normalize(cpu_delta, 50)  # assume delta up to 50

    return [cpu_norm, mem_norm, flash_norm, cpu_delta_norm]

def build_traffic_features(ports, uplinks):
    total_mbps = 0
    total_pps = 0
    errors = 0
    discards = 0
    silent_uplinks = 0

    for pname, pd in ports.items():
        if not is_physical_port(pname):
            continue

        traffic = (pd.get("in_b", 0) + pd.get("out_b", 0)) / 1_000_000
        total_mbps += traffic
        total_pps += pd.get("in_p", 0) + pd.get("out_p", 0)
        errors += pd.get("in_err_rate", 0)
        discards += pd.get("discard_rate", 0)

        if pname in uplinks and traffic < 1:
            silent_uplinks += 1

    total_mbps_norm = normalize(total_mbps, 1000)  # assume max 1000 Mbps
    total_pps_norm = normalize(total_pps, 10000)  # assume max 10k pps
    errors_norm = normalize(errors, 100)  # assume max 100 errors
    discards_norm = normalize(discards, 100)
    silent_uplinks_norm = normalize(silent_uplinks, 10)  # max 10 uplinks

    return [total_mbps_norm, total_pps_norm, errors_norm, discards_norm, silent_uplinks_norm]

def build_env_features(env):
    try:
        temp = float(env.get("temp", 0))
    except Exception:
        temp = 0.0
    fan_rpms = env.get("fan_rpms", "0/0").split("/")
    fan_rpms = [int(x) for x in fan_rpms if x.isdigit()]
    min_rpm = min(fan_rpms) if fan_rpms else 0
    temp_norm = normalize(temp, 100)
    min_rpm_norm = normalize(min_rpm, 10000)

    return [temp_norm, min_rpm_norm]

def normalize(x, max_val):
    return min(x / max_val, 1.0) if max_val else 0

def explain_anomaly(features, baseline):
    explanations = []
    for i, (f, b) in enumerate(zip(features, baseline)):
        if b is None:
            continue
        diff = f - b
        if abs(diff) > 0.3 * (abs(b) + 1):
            explanations.append((i, round(diff, 2)))

    return sorted(explanations, key=lambda x: abs(x[1]), reverse=True)[:3]

def save_ml_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({
                "ewma": EWMA_BASELINES,
                "uplink_conf": UPLINK_CONFIDENCE,

                # 🚀 NEW: persistent intelligence
                "causal_graph": {
                    k: dict(v) for k, v in CAUSAL_GRAPH.items()
                },
                "prediction_model": {
                    k: dict(v) for k, v in PREDICTION_MODEL.items()
                },
                "unknown_labels": UNKNOWN_LABELS

            }, f)
    except Exception as e:
            edge_print("[STATE SAVE ERROR]", e)
def load_ml_state():
    if not os.path.exists(STATE_FILE):
        return

    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)

            EWMA_BASELINES.update(data.get("ewma", {}))
            UPLINK_CONFIDENCE.update(data.get("uplink_conf", {}))

            # 🚀 NEW: restore intelligence

            cg = data.get("causal_graph", {})
            for k, v in cg.items():
                CAUSAL_GRAPH[k].update(v)

            pm = data.get("prediction_model", {})
            for k, v in pm.items():
                PREDICTION_MODEL[k].update(v)

            UNKNOWN_LABELS.update(data.get("unknown_labels", {}))

        print("[STATE] ML state restored successfully")

    except Exception as e:
            edge_print("[STATE LOAD ERROR]", e)
def correlate():
    global RECENT_ANOMALIES
    now = time.time()

    # remove old entries in-place
    while RECENT_ANOMALIES and now - RECENT_ANOMALIES[0]["ts"] > CORR_WINDOW:
        RECENT_ANOMALIES.popleft()

    recent = list(RECENT_ANOMALIES)

    cpu_events = [a for a in recent if a["type"] == "cpu"]
    traf_events = [a for a in recent if a["type"] == "traffic"]

    if cpu_events and traf_events:
        if traf_events[-1]["ts"] <= cpu_events[-1]["ts"]:
            return "Traffic surge (multiple ports) likely caused CPU spike"

    return None

def finalize_decision(decision, confidence, root_cause):
    conf = round(confidence, 2)

    decision["confidence"] = conf
    decision["severity"] = severity_from_conf(conf)[0]
    if not decision.get("device_id"):
        decision["device_id"] = CONFIG.get("device_id")
    decision["root_cause"] = root_cause

    return decision

def finalize_and_alert(decision, confidence, reason):
    print("[FINALIZE CALLED]", decision.get("observations"))
    global LAST_ALERT_TIME
    decision.setdefault("device_id", CONFIG.get("device_id"))
    result = finalize_decision(decision, confidence, reason)

    #  Check for violation BEFORE cooldown
    is_violation = "link_violation" in result.get("observations", {})

    now = time.time()
    if not is_violation and now - LAST_ALERT_TIME < ALERT_COOLDOWN:
        return None

    LAST_ALERT_TIME = now

    if result:
        try:
            observations = result.get("observations", {})
            is_ml_alert = reason == "ml_anomaly" or "ml_anomaly" in observations
            is_violation = "link_violation" in observations
            recent_logs = read_recent_swlogs(20)
            ml_logs = recent_logs if is_ml_alert or is_violation else recent_logs[:5]

            # LOCAL VISIBILITY
            edge_print("\n[EDGE AI ALERT]")
            edge_print(f"Device: {CONFIG.get('device_id')}")
            edge_print(f"Type: {'ML' if is_ml_alert or is_violation else 'Telemetry'}")
            edge_print(f"Confidence: {round(confidence, 2)}")
            edge_print(f"Observations: {observations}")
            edge_print(f"Recommendations: {result.get('recommendations', [])}")

            if ml_logs:
                edge_print("Logs:")
                for l in ml_logs[:5]:
                    edge_print("  -", l)

            edge_print("--------------------------------------------------")

            if is_violation:
                alert_type = "link_violation"
                alert_event = "link_violation"
                alert_source = "telemetry"
            elif is_ml_alert:
                alert_type = "ml_anomaly"
                alert_event = "ml_anomaly"
                alert_source = "ml"
            else:
                alert_type = result.get("type", "anomaly")
                alert_event = result.get("event", alert_type)
                alert_source = "telemetry"

            send_local_alert({
                "device_id": result.get("device_id") or CONFIG.get("device_id", "UNKNOWN"),
                "type": alert_type,
                "event": alert_event,
                "confidence": result.get("confidence", confidence),
                "observations": observations,
                "recommendations": result.get("recommendations", []),
                "logs": ml_logs,
                "source": alert_source
            })
            if confidence > 0.7 or is_violation:
                sev, _ = severity_from_conf(confidence)
                send_formatted_alert_to_central(result, sev)

        except Exception as e:
            edge_print("[ALERT ERROR]", e)

    # --- SEQUENCE ENGINE ---
    cfg = get_config()
    seq_cfg = cfg.get("sequence", {})
    intel_cfg = cfg.get("intelligence", {})

    if seq_cfg.get("enabled", True) and intel_cfg.get("prediction", True):
        event_type = result.get("type") if result else None

        if event_type:
            update_sequence(event_type, time_window=seq_cfg.get("time_window_sec", 10))

            preds = predict_next(
                event_type,
                top_k=seq_cfg.get("prediction_top_k", 3)
            )

            if preds:
                result["predictions"] = preds

    # --- REMEDIATION (ADVISORY ONLY) ---
    rem_cfg = cfg.get("remediation", {})

    if intel_cfg.get("remediation", False) and rem_cfg.get("enabled"):
        action = decide_action(result)

        if action:
            advisory = generate_advisory(action)

            if advisory:
                result.setdefault("recommendations", []).append(advisory)
    return result

def build_root_cause(observations, ports, confidence):
    causes = []

    # --- Traffic-driven root cause ---
    if ("high_traffic" in observations or "ml_anomaly" in observations) and confidence > 0.75:
        contribs = compute_port_contributions(ports)

        if contribs:
            top_port, mbps, ratio = contribs[0]

            if ratio > 0.5:  # dominant port
                causes.append({
                    "cause": f"Port {top_port} dominating traffic ({mbps:.1f} Mbps, {ratio*100:.0f}%)",
                    "confidence": min(0.95, 0.7 + ratio)
                })

    # --- Error-driven cause ---
    if "error_spike" in observations:
        causes.append({
            "cause": "High error rate detected on ports",
            "confidence": 0.8
        })

    # --- Link / uplink issues ---
    if "unexpected_down" in observations:
        causes.append({
            "cause": "Critical port/uplink went down",
            "confidence": 0.9
        })

    if not causes:
        return None

    # pick strongest cause
    causes.sort(key=lambda x: x["confidence"], reverse=True)

    return causes[:2]

def remediate(decision, ports):
    rem_cfg = CONFIG.get("remediation", {})

    if not rem_cfg.get("enabled", False):
        return

    mode = rem_cfg.get("mode", "dry_run")
    actions = rem_cfg.get("actions", {})

    root = decision.get("root_cause", "")
    detail = decision.get("root_cause_detail", "")
    observations = decision.get("observations", {})

    # --- Traffic flood ---
    if "high_traffic" in observations and decision.get("confidence", 0) > 0.75:
        action = actions.get("traffic_flood", "log_only")

        if action == "rate_limit":
            port = extract_port_from_text(detail or root)

            if port != "unknown":
                cmd = f"rate-limit port {port}"
                reason = detail or root
                execute_action(cmd, mode, reason=reason)
            else:
                print(f"{YELLOW}[REMEDIATION SKIPPED]{RESET} No valid port found | reason: {root}")

    # --- Uplink down ---
    elif "uplink" in root or "unexpected_down" in decision.get("observations", {}):
        action = actions.get("uplink_down", "log_only")

        if action == "log_only":
            execute_action("log uplink issue", mode, reason=root)

    # --- CPU high ---
    elif "cpu" in root.lower():
        action = actions.get("cpu_high", "log_only")

        if action == "log_only":
            execute_action("log cpu issue", mode, reason=root)

    # --- Errors ---
    elif "errors" in root.lower() or "error" in root.lower():
        action = actions.get("error_spike", "log_only")

        if action == "log_only":
            execute_action("log error spike", mode, reason=root)

def extract_port_from_text(text):
    match = re.search(r"\d+/\d+/\d+", text)
    return match.group(0) if match else "unknown"

def execute_action(command, mode, reason=""):
    if mode == "off":
        return

    elif mode == "dry_run":
        print(f"{YELLOW}[REMEDIATION][DRY-RUN]{RESET} {command} | reason: {reason}")

    elif mode == "active":
        print(f"{RED}[REMEDIATION][EXEC]{RESET} {command} | reason: {reason}")

        # PLACEHOLDER: integrate with CLI/API here
        # Example:
        # os.system(f"cli -c '{command}'")

def compute_port_contributions(ports):
    port_traffic = {}

    total = 0.0

    for pname, pd in ports.items():
        if not is_physical_port(pname):
            continue

        traffic = (pd.get("in_b", 0) + pd.get("out_b", 0)) / 1_000_000
        port_traffic[pname] = traffic
        total += traffic

    if total == 0:
        return []

    contributions = []

    for pname, val in port_traffic.items():
        ratio = val / total
        contributions.append((pname, val, ratio))

    # sort by highest contributor
    contributions.sort(key=lambda x: x[2], reverse=True)

    return contributions[:3]  # top 3

def build_causal_chain(observations, ports):
    chain = []

    # --- 1. Find dominant traffic source ---
    if "high_traffic" in observations:
        contribs = compute_port_contributions(ports)

        if contribs:
            port, mbps, ratio = contribs[0]

            if ratio > 0.4:
                chain.append(
                    f"Port {port} dominating traffic ({mbps:.1f} Mbps, {ratio*100:.0f}%)"
                )

    # --- 2. Traffic → CPU ---
    if "high_traffic" in observations and "cpu_spike" in observations:
        chain.append("Traffic surge likely caused CPU spike")

    # --- 3. CPU → drops ---
    if "cpu_spike" in observations and "discard_spike" in observations:
        chain.append("CPU spike likely causing packet drops")

    # --- 4. Errors → degradation ---
    if "error_spike" in observations:
        chain.append("High error rate degrading network performance")

    # --- 5. Uplink failure ---
    if "unexpected_down" in observations:
        for p in observations["unexpected_down"]:
            if "uplink" in p:
                chain.append(f"Critical uplink {p} went down")

    return chain

def detect_flap():
    recent = [(t, ts) for t, ts in TRAP_HISTORY if time.time() - ts < 10]
    downs = [t for t, ts in recent if t == "linkDown"]
    return len(downs) >= 3

def detect_unknown_patterns():
    results = []

    for t_type, times in UNKNOWN_TRAPS.items():
        recent = [t for t in times if time.time() - t < 10]

        if len(recent) >= 3:
            results.append(t_type)

    return results

def render_causal_graph():
    lines = []
    for src, targets in CAUSAL_GRAPH.items():
        for dst, count in targets.items():
            if count >= 2:
                lines.append(f"{src} --> {dst} ({count})")
    return lines

def auto_label_unknown():
    for t_type, feats in UNKNOWN_FEATURES.items():

        if t_type in UNKNOWN_LABELS:
            continue

        if len(feats) < 5:
            continue

        has_if_ratio = sum(1 for f in feats if f["has_if"]) / len(feats)

        # heuristic clustering
        if has_if_ratio > 0.7:
            UNKNOWN_LABELS[t_type] = "interface_event"

        elif has_if_ratio < 0.3:
            UNKNOWN_LABELS[t_type] = "system_event"

        else:
            UNKNOWN_LABELS[t_type] = "mixed_event"

def detect_trap_sequence():
    seq = [t for t, ts in TRAP_HISTORY if time.time() - ts < 10]

    # pattern 1: flapping
    if seq.count("linkDown") >= 2 and seq.count("linkUp") >= 2:
        return "flapping"

    # pattern 2: repeated failures
    if seq.count("linkDown") >= 3:
        return "unstable_link"

    # pattern 3: security burst
    if seq.count("authenticationFailure") >= 3:
        return "auth_attack"

    return None

def process_trap_immediately(trap):
    print("[REALTIME TRAP]", trap.get("type"))

    decision = {
        "timestamp_epoch": int(time.time()),
        "uptime_sec": 0,
        "observations": {"trap_event": trap.get("type")},
        "recommendations": [f"Immediate trap received: {trap.get('type')}"],
        "ai_mode": "REALTIME_TRAP"
    }

    return finalize_and_alert(decision, 0.9, "trap_event")

def analyze(entry):
    print("[ANALYZE ENTRY]", entry.get("type"), entry.get("message"))
    global ACTIVE_ALERTS
    global CONFIG, LAST_CONFIG_LOAD
    global ML_SAMPLE_COUNTER
    observations = {}
    recommendations = []
    confidence = 0.3
    device_id = (
        entry.get("device_id")
        or entry.get("device")
        or CONFIG.get("device_id")
    )

    entry["device_id"] = device_id

    # 🚀 NEW: trap urgency boost
    recent_triggers = []
    now = time.time()
    if now - LAST_CONFIG_LOAD > 5:
        load_config()
        CONFIG = get_config()
        LAST_CONFIG_LOAD = now

    source_cfg = CONFIG.get("sources", {})
    intel_cfg = CONFIG.get("intelligence", {})
    perf_cfg = CONFIG.get("performance", {})
    traps_enabled = bool(source_cfg.get("snmp_traps", True))
    ewma_enabled = bool(intel_cfg.get("ewma", True))
    cusum_enabled = bool(intel_cfg.get("cusum", True))
    ml_enabled = bool(intel_cfg.get("ml", True))
    correlation_enabled = bool(intel_cfg.get("correlation", True))
    prediction_enabled = bool(intel_cfg.get("prediction", True))

    if traps_enabled and os.path.exists(TRAP_FILE):
        read_traps()

    while TRAP_TRIGGER_QUEUE:
        recent_triggers.append(TRAP_TRIGGER_QUEUE.pop())

    if recent_triggers:
        print("[TRAP BURST]", [t.get("type") for t in recent_triggers])

    entry_type = entry.get("type")
    ports = entry.get("ports", {}) if entry_type == "slow" else {}

    # --- read SNMP traps ---

    for trap in (list(RECENT_TRAPS) if traps_enabled else []):

        if trap.get("_processed"):
            continue

        trap_ts = trap.get("ts")

        if not trap_ts:
            trap["_processed"] = True
            continue

        if time.time() - trap_ts > 5:
            trap["_processed"] = True
            continue

        t_type = trap.get("type")
        TRAP_HISTORY.append((t_type, time.time()))

        if t_type not in (
            "linkDown", "linkUp",
            "authenticationFailure",
            "coldStart", "warmStart",
            "healthMonCmmTrap", "healthMonModuleTrap",
            "alaDoSTrap"
        ):
            UNKNOWN_TRAPS[t_type].append(time.time())
            # extract simple features
            feat = {
                "has_if": trap.get("ifIndex") is not None,
                "time": time.time()
            }
            UNKNOWN_FEATURES[t_type].append(feat)

        ifIndex = trap.get("ifIndex")

        if not t_type:
            trap["_processed"] = True
            continue

        ifindex_map = entry.get("ifindex_map", {})
        port = map_ifindex_to_port(ifIndex, ifindex_map)

        # --- LINK DOWN ---
        if t_type == "linkDown":
            observations.setdefault("trap_link_down", []).append(port)
            recommendations.append(f"SNMP: Link down detected on {port}")

            #  BOOST if recent trigger
            if any(t.get("type") == "linkDown" for t in recent_triggers):
                confidence = max(confidence, 0.95)
            else:
                confidence = max(confidence, 0.9)

            DEVICE_ANOMALIES.setdefault(device_id, deque(maxlen=20)).append({
                "ts": time.time(),
                "type": "link"
            })

            trap["_processed"] = True

        # --- LINK UP ---
        elif t_type == "linkUp":
            observations.setdefault("trap_link_up", []).append(port)
            recommendations.append(f"SNMP: Link up detected on {port}")
            confidence = max(confidence, 0.7)

            trap["_processed"] = True

        # --- CPU / HEALTH TRAPS ---
        elif t_type in ("healthMonCmmTrap", "healthMonModuleTrap"):
            observations.setdefault("trap_cpu", []).append(t_type)
            recommendations.append("SNMP: CPU threshold crossed")

            if any(t.get("type") in ("healthMonCmmTrap", "healthMonModuleTrap") for t in recent_triggers):
                confidence = max(confidence, 0.95)

            trap["_processed"] = True

        # --- SECURITY TRAPS ---
        elif t_type == "alaDoSTrap":
            observations.setdefault("trap_security", []).append("dos")
            recommendations.append("SNMP: DoS attack detected")

            if any(t.get("type") == "alaDoSTrap" for t in recent_triggers):
                confidence = max(confidence, 0.95)

            trap["_processed"] = True

        # --- SYSTEM / SECURITY TRAPS ---
        elif t_type in ("authenticationFailure", "coldStart", "warmStart"):
            observations.setdefault("trap_system", []).append(t_type)
            recommendations.append(f"SNMP: {t_type} detected")
            confidence = max(confidence, 0.85)

            DEVICE_ANOMALIES.setdefault(device_id, deque(maxlen=20)).append({
                "ts": time.time(),
                "type": "system"
            })

            trap["_processed"] = True

    unknown_patterns = []
    if traps_enabled:
        # ================================
        # LINK VIOLATION DETECTION
        # ================================
        now = time.time()

        recent_traps = [
            t for t, ts in TRAP_HISTORY
            if now - ts < 10
        ]

        down_count = recent_traps.count("linkDown")
        up_count = recent_traps.count("linkUp")

        # HARD VIOLATION (unstable link)
        if down_count >= 3:
            observations["link_violation"] = "unstable_link"
            recommendations.append("Repeated linkDown → link violation")
            confidence = max(confidence, 0.95)

        # FLAPPING
        elif down_count >= 2 and up_count >= 2:
            observations["link_violation"] = "flapping"
            recommendations.append("Interface flapping detected")
            confidence = max(confidence, 0.95)

        if unknown_patterns:
            observations["unknown_trap_pattern"] = unknown_patterns
            recommendations.append(f"Frequent unknown traps: {unknown_patterns}")
            confidence = max(confidence, 0.8)

        seq = detect_trap_sequence()

        if seq == "flapping":
            observations["flapping"] = True
            observations["link_violation"] = "flapping"

            recommendations.append("Interface flapping detected (trap sequence)")
            confidence = max(confidence, 0.95)

        elif seq == "unstable_link":
            observations["unstable_link"] = True
            observations["link_violation"] = "unstable_link"

            recommendations.append("Repeated linkDown → link violation")
            confidence = max(confidence, 0.95)

        elif seq == "auth_attack":
            observations["security"] = True
            recommendations.append("Multiple authentication failures → possible attack")
            confidence = 0.95

        auto_label_unknown()

        for t in unknown_patterns:
            label = UNKNOWN_LABELS.get(t)

            if label:
                observations.setdefault("unknown_trap_class", []).append(f"{t}:{label}")
                recommendations.append(f"Unknown trap '{t}' classified as {label}")

    current_events = list(observations.keys())

    for ev in current_events:
        LAST_EVENTS.append((ev, time.time()))

    for i in range(len(LAST_EVENTS) - 1):
        e1, t1 = LAST_EVENTS[i]
        e2, t2 = LAST_EVENTS[i + 1]

        if t2 - t1 < 5:
            CAUSAL_GRAPH[e1][e2] += 1
            if prediction_enabled:
                PREDICTION_MODEL[e1][e2] += 1

    # extract causal insights
    causal_insights = []

    for e1, targets in CAUSAL_GRAPH.items():
        for e2, count in targets.items():
            if count >= 3:   # pattern must repeat 3 times
                causal_insights.append(f"{e1} → {e2}")

    # apply causal insights
    if causal_insights:
        observations["causal_chain_learned"] = causal_insights
        recommendations.append(f"Learned causal patterns: {causal_insights}")
        confidence = max(confidence, 0.9)

    graph_lines = render_causal_graph()

    if graph_lines:
        recommendations.append("Causal Graph:")
        recommendations.extend(graph_lines[:5])  # limit output

    # --- trap + telemetry correlation ---
    if "trap_link_down" in observations and ports:
        for p in observations["trap_link_down"]:
            pdata = ports.get(p, {})

            if not pdata:
                continue

            if pdata.get("in_err_rate", 0) > 10:
                recommendations.append(f"{p}: high errors before link down")
                confidence = min(0.95, confidence + 0.05)

            if pdata.get("discard_rate", 0) > 10:
                recommendations.append(f"{p}: congestion before link down")
                confidence = min(0.95, confidence + 0.05)

    # Decay old alerts
    now = time.time()
    ACTIVE_ALERTS = {k: v for k, v in ACTIVE_ALERTS.items() if now - v["ts"] < 300}

    # --- Handle syslog events ---
    if entry_type == "event":
        print("[SYSLOG DETECTED IN ANALYZE]", entry)
        msg = entry.get("message", "")
        msg_l = msg.lower()

        print("[SYSLOG MESSAGE]", msg_l) 

        confidence = 0.6

        # NEW: VIOLATION FROM LOGS
        if "in violation" in msg_l:
            port_match = re.search(r"\d+/\d+/\d+", msg)
            port = port_match.group(0) if port_match else "unknown"

            #  CLEAN MESSAGE EXTRACTION
            clean_match = re.search(r"(Port\s+\d+/\d+/\d+\s+in violation.*)", msg)
            clean_msg = clean_match.group(1) if clean_match else msg.strip()

            observations["link_violation"] = port
            recommendations.append(clean_msg)

            confidence = 0.95

            decision = {
                "timestamp_epoch": int(time.time()),
                "uptime_sec": 0,
                "observations": observations,
                "recommendations": recommendations,
                "ai_mode": "LOG_VIOLATION",
                "device_id": device_id
            }

            return finalize_and_alert(decision, confidence, "link_violation")

        if "link down" in msg_l:
            observations["link_down"] = msg
            recommendations.append("Link down detected from syslog")

        elif "error" in msg_l:
            observations["syslog_error"] = msg
            recommendations.append("Error reported in syslog")

        elif "stp" in msg_l:
            observations["topology_change"] = msg
            recommendations.append("STP topology change detected")

        if not observations:
            return None

        decision = {
            "timestamp_epoch": int(time.time()),
            "uptime_sec": 0,
            "observations": observations,
            "recommendations": recommendations,
            "ai_mode": "EVENT_DRIVEN",
            "device_id": device_id
        }

        return finalize_and_alert(decision, confidence, "syslog_event")

    system = entry.get("sys", {})
    env = entry.get("env", {}) if entry_type == "slow" else {}

    global ML_RESUME_MESSAGE
    if entry_type == "slow" and ML_RESUME_MESSAGE:
        print(f"{YELLOW}{ML_RESUME_MESSAGE}{RESET}")
        ML_RESUME_MESSAGE = None

    # --- Maintain super-critical uplinks from LLDP + learned uplinks ---
    if entry_type == "slow":
        uplinks = set(entry.get("uplinks", []))

        device_id = (
            entry.get("device_id")
            or entry.get("device")
            or CONFIG.get("device_id")
        )

        entry["device_id"] = device_id
        update_topology(device_id, uplinks)
        learned_uplinks = {p for p, score in UPLINK_CONFIDENCE.items() if score >= UPLINK_PROMOTE_SCORE}

        SUPER_CRITICAL_PORTS.clear()
        SUPER_CRITICAL_PORTS.update(uplinks)
        SUPER_CRITICAL_PORTS.update(learned_uplinks)
    else:
        uplinks = set()

    device_id = (
        entry.get("device_id")
        or entry.get("device")
        or CONFIG.get("device_id")
    )

    entry["device_id"] = device_id

    if device_id not in DEVICE_HISTORY:
        DEVICE_HISTORY[device_id] = deque(maxlen=120)

    DEVICE_HISTORY[device_id].append(entry)
    current_ts = entry.get("timestamp_epoch", entry.get("ts", time.time()))

    # System alerts (CPU/Mem/Flash from fast or slow)
    if entry_type in ("fast", "slow") and system:
        cpu = system.get("cpu", 0)

        # --- EWMA baseline for CPU ---
        if ewma_enabled:
            EWMA_BASELINES["cpu"] = ewma(EWMA_BASELINES["cpu"], cpu)

        mem = system.get("mem", 0)
        flash = system.get("flash", 0)

        # --- Single sudden upward CPU spike detection (noise-filtered) ---
        baseline = EWMA_BASELINES["cpu"] if ewma_enabled else cpu

        if baseline is not None:
            spike = cpu - baseline

            if (
                baseline >= 40.0 and      # only care if CPU was already meaningful
                spike >= 30.0 and         # sudden spike of 30%+
                cpu > baseline            # only upward spikes
            ):
                observations["cpu_spike"] = {
                    "from": round(baseline, 1),
                    "to": round(cpu, 1),
                    "delta": round(spike, 1)
                }
                recommendations.append(
                    f"Sudden CPU spike ({baseline:.1f}% → {cpu:.1f}%, +{spike:.1f}%)"
                )
                confidence = max(confidence, 0.6)   # MINOR alert

        def adaptive_threshold(metric, history):
            if len(history) < 20:
                return 80

            mean = statistics.mean(history)
            std = statistics.stdev(history)

            return mean + 2 * std

        SUSTAIN_SECONDS = 4   # require 4 consecutive FAST samples

        cpu_hist = [float(h.get("sys", {}).get("cpu", 0)) for h in HISTORY if h.get("sys")]
        cpu_thresh = adaptive_threshold(cpu, cpu_hist)

        if cpu > cpu_thresh:
            STATE["cpu_spikes"] += 1
        else:
            STATE["cpu_spikes"] = 0

        if STATE["cpu_spikes"] >= SUSTAIN_SECONDS:
            observations["high_cpu_sustained"] = cpu
            recommendations.append(f"Sustained high CPU usage ({cpu}%) for {STATE['cpu_spikes']}s")
            confidence = max(confidence, 0.85)

        if STATE["cpu_spikes"] == 0 and STATE.get("last_cpu_alerted"):
            recommendations.append("CPU usage back to normal")
            confidence = 0.6
            STATE["last_cpu_alerted"] = False
        elif STATE["cpu_spikes"] >= SUSTAIN_SECONDS:
            STATE["last_cpu_alerted"] = True

        if mem > 85:
            observations["high_mem"] = mem
            recommendations.append(f"High memory usage ({mem}%)")
            confidence = max(confidence, 0.95)
        elif mem > 75:
            observations["high_mem"] = mem
            recommendations.append(f"High memory usage ({mem}%)")
            confidence = max(confidence, 0.8)

        if flash > 85:
            observations["high_flash"] = flash
            recommendations.append(f"High flash storage usage ({flash}%)")
            confidence = max(confidence, 0.95)
        elif flash > 75:
            observations["high_flash"] = flash
            recommendations.append(f"High flash storage usage ({flash}%)")
            confidence = max(confidence, 0.8)

    # Ports (only from slow entries)
    if entry_type == "slow" and ports:
        unexpected_down = []
        high_traffic = []
        discard_spike = []
        error_spike = []
        high_pps = []

        for pname, pd in ports.items():
            if not isinstance(pd, dict) or not is_physical_port(pname):
                continue

            state = ensure_port_state(pname)
            state.setdefault("zero_traffic_count", 0)

            oper = pd.get("oper", "unknown")
            in_mbps = pd.get("in_b", 0.0) / 1_000_000
            out_mbps = pd.get("out_b", 0.0) / 1_000_000
            traffic = in_mbps + out_mbps

            # --- EWMA/CUSUM traffic intelligence ---
            port_ewma = EWMA_BASELINES["ports"].get(pname)

            if ewma_enabled:
                if oper == "up":
                    # Freeze EWMA learning if this is a super-critical uplink going silent
                    if not (pname in SUPER_CRITICAL_PORTS and traffic < 1.0):
                        port_ewma = ewma(port_ewma, traffic)
                        EWMA_BASELINES["ports"][pname] = port_ewma
                else:
                    port_ewma = EWMA_BASELINES["ports"].get(pname)

                if port_ewma is not None:
                    # --- Silent uplink failure detection (uplink UP but traffic collapsed) ---
                    if traffic < 1.0:
                        state["zero_traffic_count"] += 1
                    else:
                        state["zero_traffic_count"] = 0

                    if traffic > 0.2 * port_ewma:
                        state["last_silent_alert_ts"] = 0

                    now = time.time()
                    state.setdefault("last_silent_alert_ts", 0)

                    if (
                        pname in SUPER_CRITICAL_PORTS and
                        oper == "up" and
                        port_ewma > 5 and
                        traffic < 0.1 * port_ewma and
                        state["zero_traffic_count"] >= 2 and
                        now - state["last_silent_alert_ts"] > 120
                    ):
                        state["last_silent_alert_ts"] = now

                        recommendations.append(
                            f"Uplink {pname} traffic dropped abnormally "
                            f"(EWMA baseline {port_ewma:.1f} Mbps → current {traffic:.1f} Mbps)"
                        )
                        confidence = max(confidence, 0.95)

                    # --- Automatic uplink learning (LLDP + traffic dominance) ---
                    if oper == "up" and pname in uplinks:
                        ewmas = [v for p, v in EWMA_BASELINES["ports"].items() if p != pname]
                        if len(ewmas) >= 3:
                            avg_traffic = sum(ewmas) / max(1, len(ewmas))

                            if avg_traffic > 0 and port_ewma > UPLINK_DOMINANCE_RATIO * avg_traffic:
                                UPLINK_CONFIDENCE[pname] = UPLINK_CONFIDENCE.get(pname, 0) + 1
                            else:
                                UPLINK_CONFIDENCE[pname] = max(0, UPLINK_CONFIDENCE.get(pname, 0) - 1)

                            if UPLINK_CONFIDENCE.get(pname, 0) == UPLINK_PROMOTE_SCORE:
                                SUPER_CRITICAL_PORTS.add(pname)
                                observations.setdefault("uplink_learned", []).append(
                                    f"{pname} promoted to uplink (LLDP + dominant traffic EWMA={port_ewma:.1f})"
                                )
                                recommendations.append(
                                    f"Port {pname} classified as uplink based on LLDP + sustained high traffic"
                                )
                                confidence = max(confidence, 0.7)

                    if cusum_enabled and port_ewma > 5:
                        ps = CUSUM_STATE["ports"].get(pname, {"pos": 0.0, "neg": 0.0})
                        pos, neg, cp = cusum_update(ps["pos"], ps["neg"], traffic, port_ewma)
                        CUSUM_STATE["ports"][pname] = {"pos": pos, "neg": neg}

                        state = ensure_port_state(pname)

                        now = time.time()
                        if cp and oper == "up" and now - state["last_cp_alert_ts"] > 120:
                            state["last_cp_alert_ts"] = now
                            observations.setdefault("port_changepoint", []).append(
                                f"{pname} traffic shift (now {traffic:.1f} Mbps, baseline {port_ewma:.1f})"
                            )
                            recommendations.append(
                                f"Sudden traffic change on {pname} (now {traffic:.1f} Mbps vs baseline {port_ewma:.1f})"
                            )
                            confidence = max(confidence, 0.8)

            # Use already normalized rates from catch.py
            disc_rate = float(pd.get("discard_rate", 0))
            err_rate = float(pd.get("in_err_rate", 0))
            pps = float(pd.get("in_p", 0)) + float(pd.get("out_p", 0))

            state = ensure_port_state(pname)

            if oper == "up":
                if state["last_state"] != "up":
                    state["up_since"] = current_ts

            elif oper == "down":
                if state["last_state"] == "up":
                    up_duration = (current_ts - state["up_since"]) if state["up_since"] else 0

                    if pname in SUPER_CRITICAL_PORTS:
                        unexpected_down.append(f"{pname} (uplink)")
                    elif up_duration >= UPTIME_THRESHOLD_SEC:
                        unexpected_down.append(f"{pname} (was up {int(up_duration/3600)}h)")
                    else:
                        unexpected_down.append(pname)

            state["last_state"] = oper
            PORT_STATE[pname] = state

            if oper == "up" and traffic > 700:
                high_traffic.append(f"{pname} ({in_mbps + out_mbps:.1f} Mbps)")

            if disc_rate > 5:
                discard_spike.append(f"{pname} ({disc_rate:.1f}/s)")

            if err_rate > 1:
                error_spike.append(f"{pname} ({err_rate:.1f}/s)")

            if pps > 2000:
                high_pps.append(f"{pname} ({pps:.0f} pps)")

        if unexpected_down:
            observations["unexpected_down"] = unexpected_down[:5]
            recommendations.append(f"Ports down: {', '.join(unexpected_down[:5])}")

            if device_id not in DEVICE_ANOMALIES:
                DEVICE_ANOMALIES[device_id] = deque(maxlen=20)

            # detect if it's uplink-related
            if any("uplink" in p for p in unexpected_down):
                event_type = "uplink"
            else:
                event_type = "link"

            DEVICE_ANOMALIES[device_id].append({
                "ts": time.time(),
                "type": event_type
            })

            # Uplink down = critical
            if any("uplink" in p for p in unexpected_down):
                confidence = max(confidence, 0.95)
            else:
                confidence = max(confidence, 0.85)

        if high_traffic:
            observations["high_traffic"] = high_traffic[:3]
            recommendations.append(f"High traffic: {', '.join(high_traffic[:3])}")
            confidence = max(confidence, 0.7)

        if discard_spike:
            observations["discard_spike"] = discard_spike[:3]
            recommendations.append(f"Discard spikes: {', '.join(discard_spike[:3])}")
            confidence = max(confidence, 0.75)

        if error_spike:
            observations["error_spike"] = error_spike[:3]
            recommendations.append(f"Error spikes: {', '.join(error_spike[:3])}")
            confidence = max(confidence, 0.8)

        if high_pps:
            observations["high_pps"] = high_pps[:3]
            recommendations.append(f"High PPS: {', '.join(high_pps[:3])}")

    # Temperature + Fan (slow entries only)
    if entry_type == "slow" and env:
        temp = float(env.get("temp", 0))
        if temp > 75:
            observations["high_temp"] = temp
            recommendations.append(f"High temperature ({temp}°C)")
            confidence = max(confidence, 0.8)

        fan_ok = env.get("fan_ok", True)

        fan_rpms = env.get("fan_rpms", "0/0").split("/")
        fan_rpms = [int(x) for x in fan_rpms if x.isdigit()]
        min_fan = min(fan_rpms) if fan_rpms else 0

        if not fan_ok or min_fan < 7000:
            observations["fan_issue"] = {
                "fan_ok": fan_ok,
                "min_rpm": min_fan
            }
            recommendations.append(f"Fan issue detected (min rpm={min_fan})")
            confidence = max(confidence, 0.85)

    if len(recommendations) >= 2:
        confidence = min(0.95, confidence + 0.15)

    # trap context for ML
    if traps_enabled and recent_triggers:
        observations["trap_context"] = [t.get("type") for t in recent_triggers]

    # --- ML Anomaly Detection (Isolation Forest Lite) ---

    sample_rate = perf_cfg.get("ml_sample_rate", 1)
    try:
        sample_rate = max(1, int(sample_rate))
    except Exception:
        sample_rate = 1

    if entry_type == "slow" and ml_enabled:
        ML_SAMPLE_COUNTER += 1
        if ML_SAMPLE_COUNTER % sample_rate != 0:
            ml_enabled = False

    if entry_type == "slow" and ml_enabled:
        # 1. Generate features for all 3 domains
        s_x = build_system_features(system)
        t_x = build_traffic_features(ports, uplinks)
        e_x = build_env_features(env)

        ml_ready = len(SYS_MODEL.window) >= 20

        if not ml_ready:
            SYS_MODEL.update(s_x)
            TRAF_MODEL.update(t_x)
            ENV_MODEL.update(e_x)

            warmup_count = len(SYS_MODEL.window)
            warmup_payload = {
                "score": None,
                "sys": None,
                "traf": None,
                "env": None,
                "warming_up": True,
                "samples": warmup_count,
                "required": 20
            }
            send_ml_to_central({
                "type": "ml_live",
                "device_id": device_id,
                "timestamp_epoch": int(entry.get("timestamp_epoch", time.time())),
                "observations": {
                    "ml_anomaly": warmup_payload
                }
            })

            print(f"{YELLOW}[ML] warming up... ({warmup_count}/20){RESET}")
        else:
            # Ensure models are trained
            if not SYS_MODEL.trees:
                SYS_MODEL.fit()
                TRAF_MODEL.fit()
                ENV_MODEL.fit()

            s_score = SYS_MODEL.score(s_x)
            t_score = TRAF_MODEL.score(t_x)
            e_score = ENV_MODEL.score(e_x)

            # 4. Weighted Final Score: Priority to Traffic and System
            final_score = (
                0.5 * s_score +
                0.8 * t_score +
                0.3 * e_score
            )

            # Stream live ML scores for the dashboard even when no anomaly alert is raised.
            ml_live_scores = {
                "score": round(final_score, 3),
                "sys": round(s_score, 3),
                "traf": round(t_score, 3),
                "env": round(e_score, 3),
                "warming_up": False,
                "samples": len(SYS_MODEL.window),
                "required": 20
            }
            send_ml_to_central({
                "type": "ml_live",
                "device_id": device_id,
                "timestamp_epoch": int(entry.get("timestamp_epoch", time.time())),
                "observations": {
                    "ml_anomaly": ml_live_scores
                }
            })

            if final_score < 0.8:
                SYS_MODEL.update(s_x)
                TRAF_MODEL.update(t_x)
                ENV_MODEL.update(e_x)

            if final_score > 0.75:
                baseline_norm = [
                    normalize(EWMA_BASELINES.get("cpu", 0), 100),
                    None,
                    None,
                    0
                ]

                if t_score > s_score:
                    traf_baseline = [0.5, 0.5, 0.1, 0.1, 0.1]  # expected norms
                    explain = explain_anomaly(t_x, traf_baseline)
                else:
                    explain = explain_anomaly(s_x, baseline_norm)

                recommendations.append(f"ML anomaly (score={final_score:.2f}) deviations={explain}")
                confidence = max(confidence, 0.85)

                observations["ml_anomaly"] = ml_live_scores

                print(
                    f"{YELLOW}[ML LIVE] "
                    f"SYS:{s_score:.3f} TRAF:{t_score:.3f} ENV:{e_score:.3f} "
                    f"FINAL:{final_score:.3f}{RESET}"
                )

    # Add anomalies for correlation
    if "cpu_spike" in observations and confidence > 0.75:
        if device_id not in DEVICE_ANOMALIES:
            DEVICE_ANOMALIES[device_id] = deque(maxlen=20)

        DEVICE_ANOMALIES[device_id].append({
            "ts": time.time(),
            "type": "cpu"
        })
    if "high_traffic" in observations and confidence > 0.75:
        if device_id not in DEVICE_ANOMALIES:
            DEVICE_ANOMALIES[device_id] = deque(maxlen=20)

        DEVICE_ANOMALIES[device_id].append({
            "ts": time.time(),
            "type": "traffic"
        })

    corr = None
    multi_corr = None
    topo_corr = None
    blast = None

    if correlation_enabled:
        corr = correlate()
        multi_corr = correlate_multi_switch()
        topo_corr = correlate_topology()
        blast = estimate_blast_radius()

    if corr:
        recommendations.append(corr)
        confidence = max(confidence, 0.9)

    if multi_corr:
        recommendations.append(multi_corr)
        confidence = max(confidence, 0.95)

    if topo_corr:
        for msg in topo_corr:
            recommendations.append(msg)

        observations["topology_impact"] = topo_corr
        confidence = max(confidence, 0.95)

    if blast:
        # Avoid duplicate blast-only alerts
        if not observations or list(observations.keys()) == ["blast_radius"]:
            return None

        for b in blast:
            root = b.get("root") or CONFIG.get("device_id", "NANDI")
            b["root"] = root
            msg = f"{root} issue impacting {b['count']} devices: {b['impacted'][:5]}"

            recommendations.append(msg)

        observations["blast_radius"] = blast
        confidence = max(confidence, 0.95)

    #  FAST PATH: trap-only alert (no telemetry needed)
    if recent_triggers and not observations:
        return finalize_and_alert({
            "timestamp_epoch": int(time.time()),
            "uptime_sec": 0,
            "observations": {"trap_only": recent_triggers[-1].get("type")},
            "recommendations": [f"Immediate trap: {recent_triggers[-1].get('type')}"],
            "ai_mode": "TRAP_TRIGGERED",
            "device_id": device_id
        }, 0.9, "trap_event")

    # prediction engine
    predictions = []

    if prediction_enabled:
        for ev in observations.keys():
            next_events = PREDICTION_MODEL.get(ev, {})
            for nxt, count in next_events.items():
                if count >= 3:
                    predictions.append(f"{ev} → {nxt}")

    if predictions:
        observations["predictions"] = predictions
        recommendations.append(f"Predicted next issues: {predictions}")

    if not observations:
        return None

    # --- Alert grouping ---
    key = tuple(sorted(observations.keys()))

    is_violation = "link_violation" in observations

    if not is_violation:
        if key in ACTIVE_ALERTS:
            ACTIVE_ALERTS[key]["count"] += 1
            return None
        else:
            ACTIVE_ALERTS[key] = {"count": 1, "ts": time.time()}

    # --- Build decision ---
    decision = {
        "timestamp_epoch": int(time.time()),
        "uptime_sec": entry.get("uptime_sec", 0),
        "observations": observations,
        "recommendations": recommendations,
        "ai_mode": "ADVISORY_ONLY",
        "device_id": device_id
    }

    root = pick_root(observations)
    root_detail = None

    # --- NEW ROOT CAUSE ENGINE ---
    rc = build_root_cause(observations, ports if entry_type == "slow" else {}, confidence)

    if rc:
        decision["root_causes"] = rc   # list
        top = rc[0]

        decision["root_cause_detail"] = top["cause"]
        confidence = max(confidence, top["confidence"])
        root_detail = top["cause"]
        if "high_traffic" in observations and confidence > 0.75:
            root = "traffic_flood"
        elif "uplink" in top["cause"].lower():
            root = "link_issue"
        elif "error" in top["cause"].lower():
            root = "error_spike"

    elif root == "cpu_spike" and "high_traffic" in observations:
        root = "cpu_spike"
        root_detail = "CPU spike likely due to traffic surge"

    # --- NEW: causal chain ---
    chain = build_causal_chain(observations, ports if entry_type == "slow" else {})

    if chain:
        decision["root_cause_chain"] = chain

        # Only override if stronger explanation
        if "root_cause_detail" not in decision:
            decision["root_cause_detail"] = chain[0]

        # Boost confidence slightly if chain is strong
        if len(chain) >= 2:
            confidence = min(0.95, confidence + 0.05)

    elif root_detail and "root_cause_detail" not in decision:
        decision["root_cause_detail"] = root_detail

    if confidence > 0.75:
        logs = get_recent_swlog()

        trap_logs = entry.get("trap_logs")

        if trap_logs:
            decision["log_context"] = trap_logs[-5:]
        elif logs:
            decision["log_context"] = logs[-5:] if logs else []

    return finalize_and_alert(decision, confidence, root)

def preload_training_data():
    global ML_RESUME_MESSAGE

    if not os.path.exists(TELEMETRY_LOG):
        ML_RESUME_MESSAGE = "[ML RESUME] No telemetry log found."
        return

    slow_entries = []

    with open(TELEMETRY_LOG, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get("type") == "slow":
                    slow_entries.append(entry)
            except:
                continue

    if len(slow_entries) >= 200:
        slow_entries = slow_entries[-200:]

        for entry in slow_entries:
            system = entry.get("sys", {})
            ports = entry.get("ports", {})
            env = entry.get("env", {})
            uplinks = set(entry.get("uplinks", []))

            s_x = build_system_features(system)
            t_x = build_traffic_features(ports, uplinks)
            e_x = build_env_features(env)

            SYS_MODEL.window.append(s_x)
            TRAF_MODEL.window.append(t_x)
            ENV_MODEL.window.append(e_x)

        SYS_MODEL.fit()
        TRAF_MODEL.fit()
        ENV_MODEL.fit()

        ML_RESUME_MESSAGE = f"[ML RESUME] Loaded {len(SYS_MODEL.window)} samples. Trees={len(SYS_MODEL.trees)}"
    else:
        ML_RESUME_MESSAGE = f"[ML RESUME] Only {len(slow_entries)} slow entries found. Warmup required."

def main():
    #print("=== AI Brain Started - Alert Mode ===")
    load_config()
    global CONFIG, CENTRAL_LOG_URL
    CONFIG = get_config()
    CENTRAL_LOG_URL = CONFIG.get("central", {}).get("log_url", "http://127.0.0.1:5000/ingest_logs")

    load_ml_state()
    preload_training_data()
    CONFIG = get_config()
    atexit.register(save_ml_state)

    # --- Start syslog listener ---
    sources_cfg = CONFIG.get("sources", {})
    if sources_cfg.get("syslog", True) and CONFIG.get("enable_syslog", True):
        threading.Thread(
            target=start_syslog_server,
            args=(CONFIG.get("syslog_port", 5514),),
            daemon=True
        ).start()

    if sources_cfg.get("swlog", True):
        threading.Thread(target=tail_swlog, daemon=True).start()

    # --- Main telemetry loop ---
    for line in tail_file(TELEMETRY_LOG):
        try:
            entry = json.loads(line.strip())
        except:
            continue

        try:
            decision = analyze(entry)
        except Exception as e:
            edge_print("[BRAIN ERROR]", repr(e))
            continue

        global LAST_SAVE_TS
        if time.time() - LAST_SAVE_TS > 20:
            save_ml_state()
            LAST_SAVE_TS = time.time()

        if decision:
            intel_cfg = CONFIG.get("intelligence", {})
            if intel_cfg.get("remediation", False):
                remediate(decision, entry.get("ports", {}))

            ts = time.strftime("%H:%M:%S", time.localtime(decision["timestamp_epoch"]))
            sev, color = severity_from_conf(decision["confidence"])

            print(f"{BOLD}{color}[ALERT {ts}] {sev} (confidence={decision['confidence']}){RESET}")
            send_formatted_alert_to_central(decision, sev) #
            for rec in decision["recommendations"]:
                print(f"  - {rec}")
            print("")

            with open(AI_LOG, "a") as f:
                f.write(json.dumps(decision) + "\n")
            #send_ml_to_central(decision)

if __name__ == "__main__":
    main()