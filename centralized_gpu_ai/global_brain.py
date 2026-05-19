import time
from collections import defaultdict, deque

import torch

from deep_sequence_model import model as MODEL, add_event, predict as predict_seq, online_learn
from deep_model import correlate_with_logs, update_device_score, update_features, detect_multivariate_anomaly
from graph_model import propagate_impact, update_node, graph_score

# -------------------------------
# GLOBAL STATE
# -------------------------------

GLOBAL_EVENTS = deque(maxlen=500)

GLOBAL_CAUSAL_GRAPH = defaultdict(lambda: defaultdict(int))
DEVICE_EVENTS = defaultdict(lambda: deque(maxlen=50))

CORR_WINDOW = 10  # seconds
INCIDENTS = []


def group_incident(event):
    now = event.get("ts", 0)

    for inc in INCIDENTS:
        if abs(inc["ts"] - now) < 30:
            inc["events"].append(event)
            return inc

    new_inc = {"ts": now, "events": [event]}
    INCIDENTS.append(new_inc)

    # Keep incident list bounded
    if len(INCIDENTS) > 200:
        INCIDENTS.pop(0)

    return new_inc
optimizer = torch.optim.Adam(MODEL.parameters(), lr=0.001)
loss_fn = torch.nn.CrossEntropyLoss()


def train_step(x, y):
    MODEL.train()
    optimizer.zero_grad()
    out = MODEL(x)
    loss = loss_fn(out, y)
    loss.backward()
    optimizer.step()
    return loss.item()


def predict_sequence(event_vector):
    x = torch.tensor(event_vector, dtype=torch.float32).unsqueeze(0)
    out = MODEL(x)
    return out.detach().numpy()


# -------------------------------
# INGEST EVENT
# -------------------------------
def process_event(event):
    """
    Entry point from central_server
    """
    event["ts"] = event.get("ts", time.time())

    device = event.get("device") or "UNKNOWN"
    ev_type = event.get("type") or event.get("event") or "unknown"

    GLOBAL_EVENTS.append(event)
    DEVICE_EVENTS[device].append(event)

    # Learn causal relationships
    learn_global_causality()

    # Run correlation
    insight = correlate_global()

    # Run prediction
    prediction = predict_next(ev_type)

    seq_prediction = None
    event_vector = event.get("event_vector")
    if event_vector is not None:
        seq_prediction = predict_sequence(event_vector).tolist()

    result = {
        "insight": insight,
        "prediction": prediction,
        "sequence_prediction": seq_prediction
    }

    # --- Sequence model prediction ---
    add_event(event)
    seq_pred = predict_seq()
    if seq_pred:
        result["prediction"] = seq_pred

    # --- Online learning from live events ---
    online_learn(event)

    # --- Incident grouping ---
    incident = group_incident(event)
    result["incident_size"] = len(incident["events"])

    # --- Topology impact ---
    observations = event.get("observations", {})
    if "unexpected_down" in observations:
        ports = observations["unexpected_down"]
        port = ports[0] if isinstance(ports, list) and ports else str(ports)
        result["impact"] = propagate_impact(port)

    # --- Graph risk score ---
    update_node(device, event)
    result["graph_risk"] = round(graph_score(device), 3)

    # --- Device anomaly score ---
    result["device_anomaly_score"] = round(update_device_score(device, event), 3)

    # --- Multivariate anomaly detection ---
    update_features(event)
    mv = detect_multivariate_anomaly()
    if mv:
        result["multivariate"] = mv

    # --- Log correlation for RCA ---
    correlation = correlate_with_logs(event)
    result["correlated_insights"] = correlation["insights"]
    result["correlated_logs"] = event.get("logs", [])[:10]
    result["confidence"] = min(
        event.get("confidence", 0.7) + correlation["confidence_boost"],
        1.0
    )

    return result


def process_log(log):
    msg = log.get("msg", "").lower()

    if "link down" in msg:
        return {
            "type": "log_detected_issue",
            "confidence": 0.9
        }

    return None


# -------------------------------
# GLOBAL CAUSAL LEARNING
# -------------------------------
def learn_global_causality():
    events = list(GLOBAL_EVENTS)

    for i in range(len(events) - 1):
        e1 = events[i]
        e2 = events[i + 1]

        if e2["ts"] - e1["ts"] < 5:
            dev1 = e1.get("device") or "UNKNOWN"
            dev2 = e2.get("device") or "UNKNOWN"

            ev1 = (e1.get("event") or e1.get("type") or "unknown").lower()
            ev2 = (e2.get("event") or e2.get("type") or "unknown").lower()

            k1 = f"{dev1}:{ev1}"
            k2 = f"{dev2}:{ev2}"

            GLOBAL_CAUSAL_GRAPH[k1][k2] += 1


# -------------------------------
# GLOBAL CORRELATION
# -------------------------------
def correlate_global():
    now = time.time()
    recent = [e for e in GLOBAL_EVENTS if now - e["ts"] < CORR_WINDOW]

    if len(recent) < 2:
        return None

    # Example: detect multi-switch issue
    devices = set(e["device"] for e in recent)

    if len(devices) >= 2:
        return f"Multi-device anomaly across: {', '.join(devices)}"

    return None


# -------------------------------
# PREDICTION ENGINE
# -------------------------------
def predict_next(current_event):
    predictions = []

    for src, targets in GLOBAL_CAUSAL_GRAPH.items():
        if src.endswith(current_event):
            for dst, count in targets.items():
                if count >= 3:
                    predictions.append(dst)

    return predictions[:3]


# -------------------------------
# DEBUG VIEW
# -------------------------------
def dump_graph():
    lines = []

    for src, targets in GLOBAL_CAUSAL_GRAPH.items():
        for dst, count in targets.items():
            if count >= 2:
                lines.append(f"{src} → {dst} ({count})")

    return lines[:10]