import time

def build_event(
    source,
    event_type,
    severity="info",
    device_id=None,
    interface=None,
    metrics=None,
    raw=None,
    tags=None
):
    return {
        # -------------------------------
        # CORE FIELDS
        # -------------------------------
        "ts": int(time.time()),
        "source": source,
        "type": event_type,
        "event": event_type,
        "severity": severity,

        # -------------------------------
        # DEVICE (STANDARDIZED)
        # -------------------------------
        "device": device_id or "UNKNOWN",

        # -------------------------------
        # OPTIONAL CONTEXT
        # -------------------------------
        "interface": interface,
        "metrics": metrics or {},
        "tags": tags or [],

        # -------------------------------
        # RAW DATA (for debugging / RCA)
        # -------------------------------
        "raw": raw or {}
    }