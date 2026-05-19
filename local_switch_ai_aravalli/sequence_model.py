from collections import defaultdict, deque
import time

# -------------------------------
# GLOBAL STRUCTURES (PER DEVICE)
# -------------------------------
SEQUENCE_DB = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
SEQUENCE_WINDOW = defaultdict(lambda: deque(maxlen=50))


# -------------------------------
# UPDATE SEQUENCE
# -------------------------------
def update_sequence(event_type, device=None, time_window=10):
    device = device or "UNKNOWN"
    now = time.time()

    window = SEQUENCE_WINDOW[device]
    window.append((event_type, now))

    for i in range(len(window) - 1):
        e1, t1 = window[i]
        e2, t2 = window[i + 1]

        if t2 - t1 <= time_window:
            SEQUENCE_DB[device][e1][e2] += 1


# -------------------------------
# PREDICT NEXT EVENTS
# -------------------------------
def predict_next(event_type, device=None, top_k=3):
    device = device or "UNKNOWN"

    if event_type not in SEQUENCE_DB[device]:
        return []

    return sorted(
        SEQUENCE_DB[device][event_type].items(),
        key=lambda x: x[1],
        reverse=True
    )[:top_k]


# -------------------------------
# OPTIONAL: GLOBAL PREDICTION
# -------------------------------
def predict_global(event_type, top_k=3):
    combined = defaultdict(int)

    for device in SEQUENCE_DB:
        for k, v in SEQUENCE_DB[device].get(event_type, {}).items():
            combined[k] += v

    return sorted(
        combined.items(),
        key=lambda x: x[1],
        reverse=True
    )[:top_k]