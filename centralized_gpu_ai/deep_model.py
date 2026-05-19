import numpy as np
import time
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
import os

# --- CRITICAL MISSING IMPORT ---
from sentence_transformers import SentenceTransformer, models
# -------------------------------
# 2. LOAD FROM LOCAL FOLDER
# -------------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'all-MiniLM-L6-v2')

try:
    print(f"[MODEL] Manually constructing model from: {MODEL_PATH}")
    
    # 1. Load the raw transformer (the BERT part)
    word_embedding_model = models.Transformer(MODEL_PATH, max_seq_length=256)
    
    # 2. Manually define the Pooling layer (this fixes the missing argument error)
    pooling_model = models.Pooling(word_embedding_model.get_word_embedding_dimension())
    
    # 3. Combine them into a SentenceTransformer
    model = SentenceTransformer(modules=[word_embedding_model, pooling_model], device='cpu')
    
    print("[MODEL] Success! Manual assembly complete.")
except Exception as e:
    print(f"[MODEL LOAD ERROR] {e}")
    model = None

LOG_MEMORY = []
EMBEDDINGS = []
MAX_LOGS = 1000
LOG_COUNTER = 0

def embed_log(log):
    if model is None:
        return np.zeros(384) # Return empty vector (all-MiniLM is 384 dims)
    
    text = log.get("msg", "")
    vec = model.encode(text)
    return vec

def add_log(log):
    vec = embed_log(log)

    LOG_MEMORY.append(log)
    EMBEDDINGS.append(vec)

    # Keep memory bounded
    if len(LOG_MEMORY) > MAX_LOGS:
        LOG_MEMORY.pop(0)
        EMBEDDINGS.pop(0)


def cluster_logs():
    if len(EMBEDDINGS) < 10:
        return None

    X = np.array(EMBEDDINGS)

    clustering = DBSCAN(eps=0.2, min_samples=3).fit(X)

    return clustering.labels_


def detect_anomalies():
    labels = cluster_logs()

    if labels is None:
        return []

    anomalies = []

    for i, label in enumerate(labels):
        if label == -1:  # DBSCAN outlier
            anomalies.append(LOG_MEMORY[i])

    return anomalies


def analyze_logs(log):
    global LOG_COUNTER

    add_log(log)
    LOG_COUNTER += 1

    if LOG_COUNTER % 5 != 0:
        return None

    anomalies = detect_anomalies()

    if anomalies:
        return {
            "type": "log_anomaly",
            "count": len(anomalies),
            "sample": anomalies[-3:],
            "confidence": 0.9
        }

    return None


def safe_analyze(log):
    try:
        return analyze_logs(log)
    except Exception as e:
        print("[MODEL ERROR]", e)
        return None


# -------------------
# LOG WINDOW FETCH (for correlation)
# -------------------
def get_logs_near(ts, window=10):
    result = []
    for log in LOG_MEMORY:
        if abs(log.get("ts", 0) - ts) <= window:
            result.append(log)
    return result


def correlate_with_logs(alert):
    ts = alert.get("ts", time.time())
    nearby_logs = get_logs_near(ts)

    insights = []
    confidence_boost = 0

    for log in nearby_logs:
        msg = log.get("msg", "").lower()

        # Link events
        if "linksts" in msg and "down" in msg:
            insights.append("Link down detected in logs")
            confidence_boost += 0.2

        # Admin action
        if "admin-state disable" in msg:
            insights.append("Port manually disabled")
            confidence_boost += 0.3

        # Security
        if "login as root failed" in msg:
            insights.append("Failed login attempt detected")
            confidence_boost += 0.2

        # Process kill
        if "pkill" in msg:
            insights.append("Process killed recently")
            confidence_boost += 0.3

        # Generic anomaly signals
        if "error" in msg or "fail" in msg:
            insights.append("Error pattern detected in logs")
            confidence_boost += 0.1

        if "timeout" in msg:
            insights.append("Timeout observed in logs")
            confidence_boost += 0.1

    return {
        "insights": list(set(insights)),
        "confidence_boost": min(confidence_boost, 0.5)
    }


# -------------------
# DEVICE ANOMALY SCORING
# -------------------
DEVICE_STATS = {}


def update_device_score(device, event):
    device = device or "UNKNOWN"
    stats = DEVICE_STATS.setdefault(device, {
        "events": 0,
        "anomalies": 0
    })

    stats["events"] += 1

    if event.get("confidence", 0) > 0.8:
        stats["anomalies"] += 1

    score = stats["anomalies"] / stats["events"]
    return score


# -------------------
# MULTIVARIATE ANOMALY DETECTION
# -------------------
ANOMALY_MODEL = IsolationForest(contamination=0.05)

FEATURE_HISTORY = []


def update_features(event):
    vec = [
        event.get("cpu", 0),
        event.get("mem", 0),
        event.get("traffic", 0),
        event.get("errors", 0),
    ]

    FEATURE_HISTORY.append(vec)

    if len(FEATURE_HISTORY) > 100:
        FEATURE_HISTORY.pop(0)


def detect_multivariate_anomaly():
    if len(FEATURE_HISTORY) < 20:
        return None

    X = np.array(FEATURE_HISTORY)

    ANOMALY_MODEL.fit(X)
    scores = ANOMALY_MODEL.predict(X)

    if scores[-1] == -1:
        return {
            "type": "multivariate_anomaly",
            "confidence": 0.9
        }

    return None