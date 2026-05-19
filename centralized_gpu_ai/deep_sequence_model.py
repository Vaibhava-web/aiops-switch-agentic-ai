import torch
import torch.nn as nn
import numpy as np
from collections import defaultdict

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# -------------------
# MODEL
# -------------------
class SequenceModel(nn.Module):
    def __init__(self, input_size=4, hidden_size=32, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, input_size)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

model = SequenceModel().to(DEVICE)

try:
    model.load_state_dict(torch.load("sequence_model.pt", map_location=DEVICE))
    model.eval()
    print("[MODEL] Loaded trained weights")
except Exception:
    print("[MODEL] Using untrained model")

# -------------------
# ENCODING
# -------------------
EVENT_MAP = {
    "normal": 0,
    "cpu_high": 1,
    "link_down": 2,
    "log_anomaly": 3,
}

def encode_event(event):
    vec = np.zeros(len(EVENT_MAP))

    ev = (event.get("event") or event.get("type") or "").lower()

    if "link" in ev and "down" in ev:
        key = "link_down"
    elif "cpu" in ev:
        key = "cpu_high"
    elif "log_anomaly" in ev:
        key = "log_anomaly"
    else:
        key = "normal"

    vec[EVENT_MAP[key]] = 1
    return vec


# -------------------
# SEQUENCE BUFFER
# -------------------
SEQUENCE = defaultdict(list)

def add_event(event):
    device = event.get("device") or "UNKNOWN"

    seq = SEQUENCE[device]
    seq.append(encode_event(event))

    if len(seq) > 20:
        seq.pop(0)


def predict(device=None):
    device = device or "UNKNOWN"
    seq = SEQUENCE.get(device, [])

    if len(seq) < 5:
        return None

    x = torch.tensor([seq], dtype=torch.float32).to(DEVICE)

    with torch.no_grad():
        out = model(x).cpu().numpy()[0]

    idx = np.argmax(out)

    inv_map = {v: k for k, v in EVENT_MAP.items()}

    probs = torch.softmax(torch.tensor(out), dim=0).numpy()

    return {
        "prediction": inv_map.get(idx, "unknown"),
        "confidence": float(probs[idx])
    }


# -------------------
# ONLINE LEARNING
# -------------------
def online_update(mdl, new_X, new_y):
    mdl.train()
    opt = torch.optim.Adam(mdl.parameters(), lr=0.0005)
    loss_fn = nn.MSELoss()
    X = torch.tensor(new_X, dtype=torch.float32).to(DEVICE)
    y = torch.tensor(new_y, dtype=torch.float32).to(DEVICE)
    opt.zero_grad()
    out = mdl(X)
    loss = loss_fn(out, y)
    loss.backward()
    opt.step()
    mdl.eval()
    return loss.item()


def online_learn(event):
    device = event.get("device") or "UNKNOWN"
    seq = SEQUENCE.get(device, [])

    vec = encode_event(event)

    if len(seq) >= 5:
        online_update(model, [seq[-5:]], [vec])