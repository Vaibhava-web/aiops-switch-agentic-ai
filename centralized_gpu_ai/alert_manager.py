import time
import smtplib
import json
import os
from email.mime.text import MIMEText
from collections import deque

# -------------------------------
# CONFIG
# -------------------------------
SMTP_SERVER = os.getenv("ALERT_SMTP_SERVER", "smtp.office365.com")
SMTP_PORT = int(os.getenv("ALERT_SMTP_PORT", "587"))
SMTP_USER = os.getenv("ALERT_SMTP_USER", "vaibhav.n@al-enterprise.com")
SMTP_PASS = os.getenv("ALERT_SMTP_PASS", "pypccdcdvskpynny")
ALERT_TO = os.getenv("ALERT_TO", "vaibhav.n@al-enterprise.com, vismaya.c@al-enterprise.com")

WEBHOOK_URL = None  # optional

# -------------------------------
# DEDUP CACHE
# -------------------------------
RECENT_ALERTS = deque(maxlen=100)

# -------------------------------
# RATE LIMITING
# -------------------------------
LAST_ALERT_TS = 0


def rate_limit():
    global LAST_ALERT_TS
    now = time.time()
    if now - LAST_ALERT_TS < 5:
        return False
    LAST_ALERT_TS = now
    return True


def is_duplicate(event):
    key = f"{event.get('device')}:{event.get('event') or event.get('message')}"
    now = time.time()

    for k, ts in RECENT_ALERTS:
        if k == key and now - ts < 10:
            return True

    RECENT_ALERTS.append((key, now))
    return False


# -------------------------------
# EMAIL ALERT
# -------------------------------
def send_email(event, insight=None, prediction=None):
    try:
        # 2. SAFE-GUARD DATA: Ensure everything is at least an empty string or default text
        device = event.get('device') or "UNKNOWN"
        event_name = event.get('message') or event.get('event') or "UNKNOWN"
        confidence = event.get('confidence', 'N/A')
        
        # Convert lists/None to readable strings immediately
        raw_insights = event.get("correlated_insights")
        formatted_insights = "\n- ".join(raw_insights) if raw_insights else "No correlated insights."
        
        # 3. CONSTRUCT BODY SAFELY
        body = f"Device: {device}\n"
        body += f"Event: {event_name}\n"
        body += f"Confidence: {confidence}\n\n"
        body += f"Correlated Insights:\n- {formatted_insights}\n\n"

        # Handle optional arguments from the Dispatcher
        body += f"Global Insight: {insight if insight else 'None detected'}\n"
        body += f"Prediction: {prediction if prediction else 'No future prediction'}\n\n"

        body += "Observations:\n"
        body += json.dumps(event.get('observations', {}), indent=2)

        # 4. SEND (MIMEText now always receives a valid string)
        if not SMTP_USER or not SMTP_PASS:
            print("[EMAIL ERROR] Missing SMTP credentials: ALERT_SMTP_USER / ALERT_SMTP_PASS")
            return

        msg = MIMEText(body)
        msg["Subject"] = f"[ALERT] {event_name} on {device}"
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_TO

        recipients = [x.strip() for x in ALERT_TO.split(",") if x.strip()]
        if not recipients:
            recipients = [SMTP_USER]

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, recipients, msg.as_string())
        server.quit()

        print(f"[EMAIL SENT] Alert for {event_name}")

    except Exception as e:
        print("[EMAIL ERROR]", e)


# -------------------------------
# WEBHOOK ALERT
# -------------------------------
def send_webhook(event, insight=None, prediction=None):
    if not WEBHOOK_URL:
        return

    try:
        import urllib.request

        payload = {
            "text": f"ALERT: {event.get('event')} on {event.get('device')}",
            "event": event,
            "insight": insight,
            "prediction": prediction
        }

        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        urllib.request.urlopen(req, timeout=2)

        print("[WEBHOOK SENT]")

    except Exception as e:
        print("[WEBHOOK ERROR]", e)


# -------------------------------
# MAIN DISPATCH
# -------------------------------
def dispatch_alert(event, insight=None, prediction=None):
    try:
        # Skip raw ML alerts
        if event.get("source") == "ml":
            return

        # Only send meaningful alerts
        severity = str(event.get("severity", "info")).lower()
        if severity not in ("critical", "major"):
            return

        if not rate_limit():
            return

        if is_duplicate(event):
            return

        send_email(event, insight, prediction)
        send_webhook(event, insight, prediction)
    except Exception as e:
        print("[ALERT DISPATCH ERROR]", e)