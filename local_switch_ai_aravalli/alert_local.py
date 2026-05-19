import json
import time
import os
import socket
from config_manager import get_config

# ================================
# EDGE VISIBILITY CONTROL
# ================================
EDGE_VISIBILITY = os.getenv("EDGE_VISIBILITY", "true").lower() == "true"

def edge_print(msg, *args):
    if EDGE_VISIBILITY:
        print(msg, *args)

def send_http_alert(data, url):
    import urllib.request

    for attempt in range(3):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )

            urllib.request.urlopen(req, timeout=3)
            return
        except Exception as e:
            edge_print(f"[RETRY {attempt + 1}] ALERT ERROR:", e)
            time.sleep(0.5 * (attempt + 1))


def send_syslog_alert(message):
    try:
        edge_print("[SYSLOG ALERT]", message)
    except Exception:
        pass


def send_alert(event):
    cfg = get_config()

    if not cfg["alerting"]["enabled"]:
        return

    alert = {
        "timestamp": int(time.time()),
        "device": event.get("device_id") 
                or event.get("device") 
                or cfg.get("device_id", "UNKNOWN"),
        "event": event.get("type", event.get("event")),
        "confidence": event.get("confidence", 0.5),
        "observations": event.get("observations", {}),
        "recommendations": event.get("recommendations", []),
        "source": event.get("source", "telemetry"),
        "logs": event.get("logs", [])
    }

    # send to central
    url = cfg.get("central", {}).get("alert_url")
    if url:
        edge_print("[DEBUG] Sending alert to central:", url)
        send_http_alert(alert, url)
    else:
        edge_print("[WARNING] No central URL configured")

    # local syslog
    if cfg["alerting"].get("local_syslog"):
        send_syslog_alert(alert)