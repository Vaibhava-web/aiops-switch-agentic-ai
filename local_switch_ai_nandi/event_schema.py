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
        "ts": int(time.time()),
        "source": source,
        "type": event_type,
        "severity": severity,
        "device_id": device_id,
        "interface": interface,
        "metrics": metrics or {},
        "tags": tags or [],
        "raw": raw or {}
    }