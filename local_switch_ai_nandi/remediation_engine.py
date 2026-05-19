SAFE_ACTIONS = {
    "rate_limit": True,
    "restart_port": True,
    "shutdown_port": False
}


# -------------------------------
# HELPERS
# -------------------------------
def extract_port(decision):
    rc = decision.get("root_cause", "")
    import re

    match = re.search(r"\d+/\d+/\d+", str(rc))
    return match.group(0) if match else "unknown"


def get_device(decision):
    return decision.get("device") or "UNKNOWN"


# -------------------------------
# DECISION ENGINE
# -------------------------------
def decide_action(decision):
    obs = decision.get("observations", {})
    port = extract_port(decision)
    device = get_device(decision)

    if "high_traffic" in obs:
        return {
            "action": "rate_limit",
            "target": port,
            "device": device,
            "safe": SAFE_ACTIONS.get("rate_limit", False)
        }

    if "flapping" in obs:
        return {
            "action": "restart_port",
            "target": port,
            "device": device,
            "safe": SAFE_ACTIONS.get("restart_port", False)
        }

    return None


# -------------------------------
# ADVISORY
# -------------------------------
def generate_advisory(action):
    if not action:
        return None

    device = action.get("device", "UNKNOWN")

    if action["action"] == "rate_limit":
        return f"[{device}] Consider rate-limiting port {action['target']} to control traffic surge"

    elif action["action"] == "restart_port":
        return f"[{device}] Consider restarting port {action['target']} due to instability"

    return None


# -------------------------------
# EXECUTION SAFETY (future-ready)
# -------------------------------
def is_safe(action):
    if not action:
        return False
    return action.get("safe", False)