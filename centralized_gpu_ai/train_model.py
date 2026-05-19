import torch
import torch.nn as nn
import numpy as np

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# -------------------
# LOAD DATA
# -------------------
X = np.load("X.npy")
y = np.load("y.npy")

X = torch.tensor(X, dtype=torch.float32).to(DEVICE)
y = torch.tensor(y, dtype=torch.float32).to(DEVICE)
y = torch.clamp(y, 0, 1)

# Split train / validation
split = int(0.8 * X.size(0))
X_train, X_val = X[:split], X[split:]
y_train, y_val = y[:split], y[split:]

# -------------------
# MODEL
# -------------------
class LSTMModel(nn.Module):
    def __init__(self, input_size, hidden_size=32):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, input_size)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

model = LSTMModel(X.shape[2]).to(DEVICE)

# -------------------
# TRAIN
# -------------------
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
loss_fn = nn.MSELoss()

BATCH_SIZE = 32
EPOCHS = 20

for epoch in range(EPOCHS):
    model.train()
    perm = torch.randperm(X_train.size(0))

    total_loss = 0

    for i in range(0, X_train.size(0), BATCH_SIZE):
        idx = perm[i:i+BATCH_SIZE]
        batch_X = X_train[idx]
        batch_y = y_train[idx]

        optimizer.zero_grad()
        out = model(batch_X)
        loss = loss_fn(out, batch_y)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    model.eval()
    with torch.no_grad():
        val_out = model(X_val)
        val_loss = loss_fn(val_out, y_val)

    print(f"Epoch {epoch} Train Loss: {total_loss:.4f} | Val Loss: {val_loss.item():.4f}")

# -------------------
# SAVE MODEL
# -------------------
torch.save(model.state_dict(), "sequence_model.pt")

print("Model saved!")


# -------------------
# ONLINE UPDATE (for continuous learning)
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
    return loss.item()