import json
import time

FILES = [
    "telemetry.jsonl",
    "ml_alerts.jsonl",
    "traps.jsonl"
]

OUT = "events.jsonl"

with open(OUT, "w") as out:
    for f in FILES:
        try:
            with open(f) as infile:
                for line in infile:
                    try:
                        data = json.loads(line)

                        # -------------------------------
                        # NORMALIZE DEVICE
                        # -------------------------------
                        device = data.get("device") or data.get("device_id") or "UNKNOWN"
                        data["device"] = device

                        # Remove legacy field to avoid confusion
                        if "device_id" in data:
                            del data["device_id"]

                        # -------------------------------
                        # NORMALIZE TIMESTAMP
                        # -------------------------------
                        data["ts"] = (
                            data.get("ts")
                            or data.get("timestamp_epoch")
                            or int(time.time())
                        )

                        # -------------------------------
                        # NORMALIZE EVENT FIELD
                        # -------------------------------
                        if "event" not in data:
                            data["event"] = data.get("type") or "unknown"

                        # -------------------------------
                        # WRITE CLEAN DATA
                        # -------------------------------
                        out.write(json.dumps(data) + "\n")

                    except Exception:
                        continue
        except Exception:
            continue

print("Merged dataset created")