import json
import time
import os
from collections import defaultdict, deque
import requests

# ================================
# EDGE VISIBILITY CONTROL
# ================================
EDGE_VISIBILITY = os.getenv("EDGE_VISIBILITY", "true").lower() == "true"

DEVICE_MAP = {
    "10.135.81.141": "NANDI",
    "10.135.81.69": "ARAVALLI"
}

def edge_print(msg):
    if EDGE_VISIBILITY:
        print(msg)

from pysnmp.entity import engine as snmp_engine_mod, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv

from event_schema import build_event

TRAP_LOG = "/home/tec/working/vaibhav/ai_agent/traps.jsonl"

# -------------------------------
# BASIC KNOWN TRAPS
# -------------------------------
TRAP_OID_MAP = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
}

# -------------------------------
# NOISE FILTER
# -------------------------------
NOISE_TRAPS = {
    "lldpRemTablesChange",
    "monitorFileWritten",
    "mirrorConfigError",
}

# -------------------------------
# STATE
# -------------------------------
last_seen = {}
trap_history = defaultdict(lambda: deque(maxlen=10))

# -------------------------------
# DEDUP
# -------------------------------
def is_duplicate(trap):
    key = f"{trap['type']}_{trap.get('ifIndex')}"
    now = time.time()

    if key in last_seen and now - last_seen[key] < 2:
        return True

    last_seen[key] = now
    return False

# -------------------------------
# BURST DETECTION
# -------------------------------
def detect_burst(trap):
    key = trap["type"]
    history = trap_history[key]

    history.append(time.time())

    return len(history) >= 5 and history[-1] - history[0] < 5

# -------------------------------
# PARSER (SMART AUTO-MAP)
# -------------------------------
def parse_trap(varBinds):
    trap = {
        "ts": int(time.time()),
        "type": None,
        "event": None,
        "device": "unknown",
        "ifIndex": None,
        "oid": None,
        "raw": {}
    }

    for name, val in varBinds:
        oid = name.prettyPrint()
        value = val.prettyPrint()

        trap["raw"][oid] = value

        # Identify trap type
        if oid == "1.3.6.1.6.3.1.1.4.1.0":
            trap["oid"] = value

            # Known mapping
            if value in TRAP_OID_MAP:
                trap["type"] = TRAP_OID_MAP[value]
                trap["event"] = TRAP_OID_MAP[value]
            else:
                # AUTO-MAP unknown
                short = value.split(".")[-1]
                trap["type"] = f"oid_{short}"
                trap["event"] = f"oid_{short}"
                trap["unknown_oid"] = value

        # Interface index
        elif oid.endswith("1.1.0"):
            try:
                trap["ifIndex"] = int(value)
            except:
                pass

    return trap

# -------------------------------
# MAIN
# -------------------------------
def main():
    edge_print("[INFO] Smart Trap Agent started...")

    snmpEngine = snmp_engine_mod.SnmpEngine()

    # The OID for snmpUDPDomain
    snmpUDPDomain = (1, 3, 6, 1, 6, 1, 1)

    config.addTransport(
        snmpEngine,
        snmpUDPDomain,
        udp.UdpAsyncioTransport().openServerMode(("0.0.0.0", 162))
    )

    config.addV1System(snmpEngine, "public-read", "public")

    def cbFun(snmpEngine, stateReference, contextEngineId,
              contextName, varBinds, cbCtx):

        transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
        src_ip = transportAddress[0]

        trap = parse_trap(varBinds)
        trap["src"] = src_ip
        trap["device"] = DEVICE_MAP.get(src_ip, src_ip)
        trap["src_ip"] = src_ip

        if trap["type"] in NOISE_TRAPS or is_duplicate(trap):
            return

        if detect_burst(trap):
            trap["burst"] = True

        edge_print(f"[SMART TRAP] Received {trap['type']} from {src_ip}")

        try:
            requests.post(
                "http://127.0.0.1:5000/alert",
                json={
                    "device_id": DEVICE_MAP.get(src_ip, src_ip),
                    "type": trap["type"],
                    "event": trap["event"],
                    "confidence": 0.9,
                    "source": "trap"
                },
                timeout=5
            )
        except Exception as e:
            edge_print("[FORWARD ERROR]", e)

        event = build_event(
            source="trap",
            event_type=trap.get("type"),
            device_id=DEVICE_MAP.get(src_ip, src_ip),
            interface=trap.get("ifIndex"),
            raw=trap
        )

        event["device"] = DEVICE_MAP.get(src_ip, src_ip)
        event["event"] = trap.get("type")

        try:
            with open(TRAP_LOG, "a") as f:
                f.write(json.dumps(trap) + "\n")
        except Exception as e:
            edge_print("[TRAP LOG ERROR]", e)

    ntfrcv.NotificationReceiver(snmpEngine, cbFun)
    
    snmpEngine.transportDispatcher.jobStarted(1)

    edge_print("[INFO] Listening for SNMP traps on port 162...")

    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        edge_print("\n[INFO] Trap agent stopped.")
        snmpEngine.transportDispatcher.closeDispatcher()
if __name__ == "__main__":
    main()