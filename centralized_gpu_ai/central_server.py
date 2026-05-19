from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import json
import time
import threading
import logging
import requests
from queue import Queue, Empty, Full
from global_brain import process_event
from deep_model import analyze_logs, safe_analyze, correlate_with_logs
from alert_manager import dispatch_alert
import os
from datetime import datetime, timedelta, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

HOST = "0.0.0.0"
PORT = 5000

BASE_DIR = "/home/tec/working/vaibhav/ai_agent"

os.makedirs(BASE_DIR, exist_ok=True)
TELEMETRY_FILE = os.path.join(BASE_DIR, "telemetry_central.jsonl")
ML_FILE = os.path.join(BASE_DIR, "ml_alerts_central.jsonl")
HEAP_FILE = os.path.join(BASE_DIR, "heap_metrics.jsonl")

EVENTS = []
LOG_STORE = []
MAX_LOG_STORE = 10000
SHUTDOWN_EVENT = threading.Event()

# ---
# QUEUE & PERSISTENCE
# ---
LOG_QUEUE = Queue(maxsize=10000)
EVENT_QUEUE = Queue(maxsize=1000)
IST = timezone(timedelta(hours=5, minutes=30))


def now_ist_str():
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")


def is_valid_heap_timestamp(ts):
    if not isinstance(ts, str):
        return False
    try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        return dt.year >= 2020
    except Exception:
        return False


def normalize_heap_record(data):
    ts = data.get("timestamp")
    if not is_valid_heap_timestamp(ts):
        ts = now_ist_str()

    try:
        heap_kb = int(data.get("heap_kb", 0))
    except Exception:
        heap_kb = 0

    return {
        "timestamp": ts,
        "device": (
            data.get("device")
            or data.get("device_id")
            or data.get("source_device")
            or "UNKNOWN"
        ),  # CRITICAL FIX
        "process": str(data.get("process", "unknown")),
        "pid": str(data.get("pid", "")),
        "heap_kb": heap_kb
    }


def persist_log(log):
    try:
        with open(os.path.join(BASE_DIR, "logs_store.jsonl"), "a") as f:
            f.write(json.dumps(log) + "\n")
    except Exception as e:
        logging.warning(f"[PERSIST ERROR] {e}")


def send_to_ui(event):
    try:
        print("[DEBUG] Sending to UI:", event["message"][:80])
        requests.post(
            "http://127.0.0.1:8000/ingest",
            json=event,
            timeout=1
        )
        print("[DEBUG] UI SENT SUCCESS")
    except Exception as e:
        print("[UI ERROR]", e)


def safe_write(handler, payload: bytes):
    try:
        handler.wfile.write(payload)
    except BrokenPipeError:
        logging.warning("[WARN] Client disconnected before response")


def log_worker():
    while not SHUTDOWN_EVENT.is_set():
        try:
            log = LOG_QUEUE.get(timeout=1)
        except Empty:
            continue

        try:
            LOG_STORE.append(log)
            if len(LOG_STORE) > MAX_LOG_STORE:
                LOG_STORE.pop(0)
            persist_log(log)
            result = safe_analyze(log)
            if result:
                logging.info(f"[LOG AI] {result}")
        except Exception as e:
            logging.warning(f"[LOG WORKER ERROR] {e}")
        finally:
            LOG_QUEUE.task_done()

def should_send_to_dashboard(data):
    event = data.get("event")
    source = data.get("source")

    #  block noise
    if event in {"oid_1", "oid_2", "oid_3", "anomaly", "ml_anomaly"}:
        return False

    # allow real alerts
    if data.get("is_alert"):
        return True

    # allow only link traps
    if source == "trap" and event in {"linkUp", "linkDown"}:
        return False

    return False

def process_alert_event(data):
    try:
        EVENTS.append(data)
        if len(EVENTS) > 1000:
            EVENTS.pop(0)

        print("\n[ALERT RECEIVED]")
        print(json.dumps(data, indent=2))

        # Send to global brain (enriches result with correlation/prediction)
        result = process_event(data)
        insight = result.get("insight")
        prediction = result.get("prediction")

        # Merge RCA fields back onto data for alert dispatch
        data["correlated_insights"] = result.get("correlated_insights", [])
        data["correlated_logs"] = result.get("correlated_logs", data.get("logs", [])[:10])
        data["confidence"] = result.get("confidence", data.get("confidence", 0.7))

        # Explicit log+alert correlation at ingress
        log_corr = correlate_with_logs(data)
        if not data.get("correlated_logs"):
            data["correlated_logs"] = log_corr.get("insights", [])
        data["confidence"] = min(
            data.get("confidence", 0.7) + log_corr.get("confidence_boost", 0),
            1.0
        )

        print("\n[CENTRAL AI ANALYSIS]")
        print(f"Event: {data.get('event')} from {data.get('device')}")
        print(f"Confidence: {data.get('confidence')}")

        if data.get("correlated_insights"):
            print("Correlated Insights:")
            for i in data["correlated_insights"]:
                print("  -", i)

        if data.get("correlated_logs"):
            print("Logs:")
            for l in data["correlated_logs"][:5]:
                print("  -", l)

        print("--------------------------------------------------")

        if insight:
            logging.info(f"[GLOBAL INSIGHT] {insight}")

        if prediction:
            logging.info(f"[PREDICTION] {prediction}")

        if result.get("correlated_insights"):
            logging.info(f"[RCA INSIGHTS] {result['correlated_insights']}")

        if result.get("multivariate"):
            logging.info(f"[MULTIVARIATE] {result['multivariate']}")

        # ---- FIX: Ensure message exists ----
        if "message" not in data:
            event = data.get("event", "unknown")
            device = data.get("device", "UNKNOWN")

            data["message"] = f"[TRAP] {device}: {event}"

        # WRITE TO DASHBOARD + UI 
        if should_send_to_dashboard(data):
            with open(os.path.join(BASE_DIR, "dashboard_alerts.jsonl"), "a") as f:
                f.write(json.dumps(data) + "\n")

            send_to_ui(data)
        else:
            print("[FILTERED]", data.get("event"))

        # Send alert to user
        dispatch_alert(data, insight, prediction)

        # Push to UI ingest endpoint.
        send_to_ui(data)

        if result:
            if result.get("insight"):
                print("[GLOBAL INSIGHT]", result["insight"])

            if result.get("prediction"):
                print("[PREDICTION]", result["prediction"])

        print(json.dumps(data, indent=2))
    except Exception as e:
        print("[PROCESS ERROR]", e)


def event_worker():
    while not SHUTDOWN_EVENT.is_set():
        try:
            event = EVENT_QUEUE.get(timeout=1)
        except Empty:
            continue

        try:
            process_alert_event(event)
        except Exception as e:
            print("[WORKER ERROR]", e)
        finally:
            EVENT_QUEUE.task_done()


threading.Thread(target=log_worker, daemon=True).start()
threading.Thread(target=event_worker, daemon=True).start()


class Handler(BaseHTTPRequestHandler):

    def handle_logs(self, body):
        try:
            data = json.loads(body.decode("utf-8"))
            logging.info(f"[LOG RECEIVED] {data.get('msg', '')[:80]}")
            if LOG_QUEUE.full():
                self.send_response(200)
                self.end_headers()
                safe_write(self, b"OK")
                return

            LOG_QUEUE.put_nowait(data)
            self.send_response(200)
            self.end_headers()
            safe_write(self, b"OK")
        except Exception as e:
            logging.warning(f"[LOG ERROR] {e}")
            self.send_response(500)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        if self.path == "/alert":
            try:
                data = json.loads(body.decode("utf-8"))

                # normalize edge schema to central fields
                data["device"] = data.get("device_id") or data.get("device") or "UNKNOWN"
                data["event"] = data.get("type", data.get("event"))
                data["received_at"] = int(time.time())

                # Optional load-shedding: drop low-confidence events.
                if data.get("confidence", 1) < 0.5:
                    self.send_response(200)
                    self.end_headers()
                    safe_write(self, b"OK")
                    return

                # Enqueue for background processing.
                try:
                    EVENT_QUEUE.put_nowait(data)
                except Full:
                    print("[QUEUE FULL] Dropping event")

                self.send_response(200)
                self.end_headers()
                safe_write(self, b"OK")

            except Exception as e:
                print("[ERROR]", e)
                self.send_response(500)
                self.end_headers()
        elif self.path == "/ingest_logs":
            self.handle_logs(body)
        elif self.path == "/telemetry":
            try:
                data = json.loads(body.decode("utf-8"))
                data["device"] = (
                    data.get("device")
                    or data.get("device_id")
                    or data.get("source_device")
                    or "UNKNOWN"
                )
                try:
                    with open(TELEMETRY_FILE, "a") as f:
                        f.write(json.dumps(data) + "\n")
                except Exception as e:
                    logging.warning(f"[TELEMETRY WRITE] {e}")
                self.send_response(200)
                self.end_headers()
                safe_write(self, b"OK")
            except Exception as e:
                logging.warning(f"[TELEMETRY ERROR] {e}")
                self.send_response(500)
                self.end_headers()
        elif self.path == "/ml":
            try:
                data = json.loads(body.decode("utf-8"))

                data["device"] = (
                    data.get("device")
                    or data.get("device_id")
                    or data.get("source_device")
                    or "UNKNOWN"
                )

                # -----------------------------
                # DECIDE IF THIS IS A REAL ALERT
                # -----------------------------
                severity = str(data.get("severity", "")).upper()
                has_message = "message" in data

                is_violation = "link_violation" in str(data.get("observations", {})).lower()

                is_alert = (
                    has_message or
                    severity in ("CRITICAL", "MAJOR") or
                    is_violation
                )

                # -----------------------------
                # DASHBOARD ALERT PATH
                # -----------------------------
                if is_alert:
                    message = str(data.get("message", "")).lower()

                    if not is_violation and (
                        "link_violation" not in message and
                        any(token in message for token in (
                            "unknown_trap",
                            "trap_link_down",
                            "trap_link_up",
                        ))
                    ):
                        self.send_response(200)
                        self.end_headers()
                        safe_write(self, b"OK")
                        return

                    # If message is missing, BUILD ONE (critical fix for Aravalli)
                    if not has_message:
                        obs = data.get("observations", {})
                        recs = data.get("recommendations", [])

                        msg = f"[{severity or 'ALERT'}] "

                        if obs:
                            msg += ", ".join(obs.keys()) + "\n"

                        for r in recs:
                            msg += f"  - {r}\n"

                        data["message"] = msg

                    if data.get("source") == "trap":
                        return

                    # Write to dashboard alerts
                    with open(os.path.join(BASE_DIR, "dashboard_alerts.jsonl"), "a") as f:
                        f.write(json.dumps(data) + "\n")

                    # Normalize for UI + alert system
                    data["device"] = (
                        data.get("device")
                        or data.get("device_id")
                        or data.get("source_device")
                        or "UNKNOWN"
                    )
                    data["event"] = data.get("message", "dashboard_alert")
                    data["confidence"] = data.get("confidence", 0.9)
                    data["source"] = "dashboard"
                    data["is_ui_alert"] = True

                    # Send to UI
                    send_to_ui(data)

                    # Send to email / alert manager
                    dispatch_alert(data)

                # -----------------------------
                # PURE ML DATA PATH
                # -----------------------------
                else:
                    with open(ML_FILE, "a") as f:
                        f.write(json.dumps(data) + "\n")

                self.send_response(200)
                self.end_headers()
                safe_write(self, b"OK")

            except Exception as e:
                logging.warning(f"[ML/UI ERROR] {e}")
                self.send_response(500)
                self.end_headers()
        elif self.path == "/heap":
            try:
                data = json.loads(body.decode("utf-8"))
                rec = normalize_heap_record(data)
                try:
                    with open(HEAP_FILE, "a") as f:
                        f.write(json.dumps(rec) + "\n")
                except Exception as e:
                    logging.warning(f"[HEAP WRITE] {e}")
                self.send_response(200)
                self.end_headers()
                safe_write(self, b"OK")
            except Exception as e:
                logging.warning(f"[HEAP ERROR] {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            safe_write(self, b"OK")
        elif self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            safe_write(self, json.dumps(EVENTS).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def run():
    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = ThreadedHTTPServer((HOST, PORT), Handler)
    print(f"[CENTRAL] Server running on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("[CENTRAL] Shutdown requested")
    finally:
        SHUTDOWN_EVENT.set()
        server.shutdown()
        server.server_close()
        logging.info("[CENTRAL] Server stopped cleanly")

if __name__ == "__main__":
    run()