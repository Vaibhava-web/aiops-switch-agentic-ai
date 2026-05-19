import json
import numpy as np
from collections import defaultdict

from torch import device

INPUT_FILE = "events.jsonl"   # merge all sources into this

SEQ_LEN = 10

EVENT_MAP = {
    "normal": 0,
    "cpu_high": 1,
    "link_down": 2,
    "log_anomaly": 3
}

def encode(event):
    vec = []

    vec.append(event.get("cpu", 0) / 100.0)
    vec.append(event.get("mem", 0) / 100.0)
    vec.append(event.get("traffic", 0) / 1000.0)
    vec.append(event.get("errors", 0))

    # Log signal
    vec.append(1 if event.get("correlated_logs") else 0)

    # Event type
    ev = (event.get("event") or event.get("type") or "").lower()
    vec.append(1 if "link" in ev and "down" in ev else 0)

    return np.array(vec)


def load_events():
    events = []
    with open(INPUT_FILE) as f:
        for line in f:
            events.append(json.loads(line))
    return events

def build_sequences(events):
    X, y = [], []

    # Group events per device
    device_events = defaultdict(list)

    for e in events:
        device = e.get("device") or "UNKNOWN"
        device_events[device].append(e)

    # Build sequences per device
    for device, evs in device_events.items():
        encoded = [encode(e) for e in evs]

        for i in range(len(encoded) - SEQ_LEN):
            X.append(encoded[i:i+SEQ_LEN])
            y.append(encoded[i+SEQ_LEN])

    return np.array(X), np.array(y)


if __name__ == "__main__":
    events = load_events()
    X, y = build_sequences(events)

    np.save("X.npy", X)
    np.save("y.npy", y)

    print("Dataset created:", X.shape, y.shape)