import json
import os
import time

LOCAL_DIR = os.path.dirname(__file__)

CONFIG_PATHS = {
    "modes": [
        "/flash/ai_agent/modes.json",
        os.path.join(LOCAL_DIR, "modes.json")
    ],
    "base": [
        "/flash/ai_agent/base_config.json",
        os.path.join(LOCAL_DIR, "base_config.json")
    ],
    "runtime": [
        "/flash/ai_agent/config.json",
        os.path.join(LOCAL_DIR, "config.json")
    ]
}

# Default config (safe fallback)
DEFAULT_CONFIG = {
    "device_id": "UNKNOWN",
    "mode": "balanced",
    "metrics": {
        "system": True,
        "traffic": True,
        "environment": False,
        "heap": False
    },
    "sources": {
        "snmp_traps": True,
        "syslog": True,
        "swlog": True
    },
    "intelligence": {
        "ml": True,
        "ewma": True,
        "cusum": True,
        "correlation": True,
        "prediction": True,
        "remediation": False
    },
    "performance": {
        "fast_interval": 1,
        "slow_interval": 5,
        "ml_sample_rate": 2,
        "max_ports_analyzed": 32
    },
    "thresholds": {
        "cpu": 85,
        "error_rate": 10
    },
    "features": {
        "ml": True,
        "traps": True,
        "prediction": True
    },
    "alerting": {
        "enabled": True,
        "central_url": "http://10.95.131.72:5000/alert",
        "local_syslog": True
    },
    "filters": {
        "ignore_traps": []
    },
    "central": {
        "log_url": "http://127.0.0.1:5000/ingest_logs",
        "alert_url": "http://127.0.0.1:5000/alert",
        "heap_url": "http://127.0.0.1:5000/heap"
    },
    "heap": {
        "processes": ["sshd"],
        "interval_sec": 5
    },
    "sequence": {
        "enabled": True,
        "window_size": 50,
        "time_window_sec": 10,
        "prediction_top_k": 3
    },
    "remediation": {
        "enabled": True,
        "mode": "advisory"
    }
}

_config_cache = DEFAULT_CONFIG.copy()
_last_load_signature = None


def deep_merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            a[k] = deep_merge(a.get(k, {}), v)
        else:
            a[k] = v
    return a


def _first_existing_path(path_list):
    for path in path_list:
        if os.path.exists(path):
            return path
    return path_list[0]


def _read_json(path, fallback):
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    except Exception as e:
        print(f"[CONFIG READ ERROR] {path}: {e}")
    return fallback


def _get_signature(paths):
    sig = []
    for path in paths:
        try:
            sig.append((path, os.path.getmtime(path)))
        except Exception:
            sig.append((path, None))
    return tuple(sig)


def load_config():
    global _config_cache, _last_load_signature

    try:
        modes_path = _first_existing_path(CONFIG_PATHS["modes"])
        base_path = _first_existing_path(CONFIG_PATHS["base"])
        runtime_path = _first_existing_path(CONFIG_PATHS["runtime"])

        signature = _get_signature([modes_path, base_path, runtime_path])

        # reload only if any config source changes
        if signature != _last_load_signature:
            modes = _read_json(modes_path, {})
            base_cfg = _read_json(base_path, {})
            runtime_cfg = _read_json(runtime_path, {})

            selected_mode = base_cfg.get("mode", DEFAULT_CONFIG.get("mode", "balanced"))
            mode_cfg = modes.get(selected_mode)
            if not isinstance(mode_cfg, dict):
                selected_mode = "balanced"
                mode_cfg = modes.get("balanced", {})

            merged = deep_merge(DEFAULT_CONFIG.copy(), mode_cfg or {})
            merged = deep_merge(merged, base_cfg)
            merged["mode"] = selected_mode
            merged = deep_merge(merged, runtime_cfg)

            _config_cache = merged
            _last_load_signature = signature
            print(f"[CONFIG] Reloaded (mode={selected_mode})")
            print(f"[CONFIG DEBUG] device_id={merged.get('device_id')}")

    except Exception as e:
        print("[CONFIG ERROR]", e)

    return _config_cache


def get_config():
    return _config_cache