from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.responses import StreamingResponse

import json
import asyncio
import time
import os

BASE_DIR = "/home/tec/working/vaibhav/ai_agent"
TELEMETRY_FILE = BASE_DIR + "/telemetry_central.jsonl"
ML_FILE = BASE_DIR + "/ml_alerts_central.jsonl"
ALERTS_FILE = BASE_DIR + "/dashboard_alerts.jsonl"
HEAP_FILE = BASE_DIR + "/heap_metrics.jsonl"
UI_DIR = os.path.dirname(__file__)
INDEX_FILE = os.path.join(UI_DIR, "index.html")

def tail_file(path):
  with open(path, "r") as f:
    f.seek(0, 2)
    while True:
      line = f.readline()
      if not line:
        time.sleep(0.2)
        continue
      yield line

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

EVENTS = []
CLIENTS: list = []

# ---------------------------------------------------------------------------
# DASHBOARD HTML (no build step required — React + Babel loaded from CDN)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Network AI Dashboard</title>
  <script crossorigin src="https://unpkg.com/react@18/umd/react.development.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <style>
    body { margin: 0; background: linear-gradient(140deg, #0b1220 0%, #101a2f 55%, #0f1f1f 100%); }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    const { useState, useEffect } = React;

    function App() {
      const [events, setEvents]         = useState([]);
      const [liveML, setLiveML]         = useState({});
      const [activeTab, setActiveTab]   = useState("ai");
      const [showSignals, setShowSignals]     = useState(true);
      const [showAllEvents, setShowAllEvents] = useState(false);
      const [telemetry, setTelemetry] = useState({});
      const [telemetryLog, setTelemetryLog] = useState([]);

      console.log("UI Loaded");

      // Load history once
      useEffect(() => {
        fetch("/events")
          .then(r => r.json())
          .then(d => { if (Array.isArray(d)) setEvents(d.slice(-100).reverse()); })
          .catch(() => {});
      }, []);

      // Live stream via WebSocket
      useEffect(() => {
        const ws = new WebSocket("ws://10.95.131.72:8001/stream");
        ws.onmessage = (msg) => {
          try {
            const parsed = JSON.parse(msg.data);
            const ev = (parsed && parsed.type === "alert") ? parsed.data : parsed;
            if (ev && typeof ev === "object") {
              setEvents(prev => [ev, ...prev].slice(0, 200));
              const ml = (parsed && parsed.type === "ml")
                ? parsed.data
                : (ev.observations && typeof ev.observations.ml_anomaly === "object"
                    ? ev.observations.ml_anomaly : null);
              if (ml) setLiveML(ml);
            }
          } catch {}
        };
        return () => ws.close();
      }, []);

      useEffect(() => {
        fetch("/stream/telemetry")
          .then(res => {
            if (!res.body) return;

            const reader = res.body.getReader();
            const decoder = new TextDecoder();

            function read() {
              reader.read().then(({done, value}) => {
                if (done || !value) return;

                const text = decoder.decode(value);
                text.split("\n").forEach(line => {
                  if (!line) return;

                  try {
                    const data = JSON.parse(line);
                    setTelemetry(data);
                    setTelemetryLog(prev => [data, ...prev].slice(0, 200));
                  } catch {}
                });

                read();
              }).catch(() => {});
            }

            read();
          })
          .catch(() => {});
      }, []);

      useEffect(() => {
        fetch("/stream/ml")
          .then(res => {
            if (!res.body) return;

            const reader = res.body.getReader();
            const decoder = new TextDecoder();

            function read() {
              reader.read().then(({done, value}) => {
                if (done || !value) return;

                const text = decoder.decode(value);
                text.split("\n").forEach(line => {
                  if (!line) return;

                  try {
                    const data = JSON.parse(line);
                    // 1. UPDATE ML SCORE (existing)
                    if (data.observations && data.observations.ml_anomaly) {
                    setLiveML(data.observations.ml_anomaly);
                    }

                    // ✅ 2. PUSH ALERT TO EVENTS (NEW - VERY IMPORTANT)
                    //setEvents(prev => [data, ...prev].slice(0, 200));

                  } catch {}
                });

                read();
              }).catch(() => {});
            }

            read();
          })
          .catch(() => {});
      }, []);

      const tabs = ["ai", "ml", "telemetry", "events", "logs"];
      const tabLabel = { ai: "AI Summary", ml: "Live ML", telemetry: "Telemetry", events: "Events", logs: "Logs" };

      const styles = {
        root: { color:"#e5edf8", minHeight:"100vh", padding:"20px",
                fontFamily:"'IBM Plex Sans','Segoe UI',Tahoma,sans-serif" },
        card: { border:"1px solid #2a3e63", borderRadius:"12px", padding:"14px",
                marginBottom:"12px", background:"rgba(14,25,45,0.92)",
                boxShadow:"0 3px 12px rgba(0,0,0,0.22)" },
        tabBar: { display:"flex", flexWrap:"wrap", gap:"10px", marginBottom:"16px",
                  borderBottom:"1px solid #253552", paddingBottom:"10px" },
        tab: (active) => ({ border:"none", cursor:"pointer", borderRadius:"8px",
                            padding:"8px 12px", color:"#f4f8ff",
                            background: active ? "#2f72ff" : "#182845",
                            fontWeight: active ? 700 : 500 }),
        rowItem: { borderBottom:"1px solid #304766", padding:"10px 0" },
        logEntry: { fontSize:"12px", fontFamily:"'IBM Plex Mono',Consolas,monospace",
                    background:"#152236", padding:"6px", borderRadius:"6px", marginBottom:"4px" },
        mlBox: { border:"1px solid #2d6044", background:"#102c21",
                 borderRadius:"12px", padding:"16px" },
      };

      return (
        <div style={styles.root}>
          <h1 style={{ marginTop:0, marginBottom:"16px" }}>Network AI Dashboard</h1>

          <div style={styles.tabBar}>
            {tabs.map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={styles.tab(activeTab===tab)}>
                {tabLabel[tab]}
              </button>
            ))}
          </div>

          {(activeTab==="ai"||activeTab==="events"||activeTab==="logs") && (
            <div style={{ marginBottom:"14px", display:"flex", gap:"18px", flexWrap:"wrap" }}>
              <label>
                <input type="checkbox" checked={showSignals}
                  onChange={() => setShowSignals(v => !v)} /> Show Signals
              </label>
              <label style={{ marginLeft:"6px" }}>
                <input type="checkbox" checked={showAllEvents}
                  onChange={() => setShowAllEvents(v => !v)} /> Show Full Events
              </label>
            </div>
          )}

          {/* ── AI SUMMARY ── */}
          {activeTab==="ai" && (
            <div>
              {events.length === 0 && <p style={{opacity:0.7}}>No events received yet.</p>}
              {events.map((e,i) => (
                <div key={i} style={styles.card}>
                  <h3 style={{marginTop:0,marginBottom:"8px"}}>🚨 {e.event||"unknown"}</h3>
                  <p style={{margin:"4px 0"}}><b>Device:</b> {e.device||e.device_id||"unknown"}</p>
                  <p style={{margin:"4px 0"}}><b>Confidence:</b> {e.confidence??'n/a'}</p>
                  {e.recommendations && e.recommendations.length > 0 && (
                    <div style={{marginTop:"8px"}}>
                      <b>Recommendations:</b>
                      <ul style={{marginTop:"4px"}}>
                        {e.recommendations.map((r,ri) => <li key={ri}>{r}</li>)}
                      </ul>
                    </div>
                  )}
                  {showSignals && e.observations && (
                    <div style={{marginTop:"10px"}}>
                      <b>Signals:</b>
                      <ul style={{marginTop:"6px"}}>
                        {Object.entries(e.observations)
                          .filter(([k]) => !k.startsWith("all_"))
                          .map(([k,v],idx) => <li key={idx}>{k}: {JSON.stringify(v)}</li>)}
                      </ul>
                    </div>
                  )}
                  {showAllEvents && e.observations && (
                    <div style={{marginTop:"10px"}}>
                      <b>All Events:</b>
                      <ul style={{marginTop:"6px"}}>
                        {Object.entries(e.observations)
                          .filter(([k]) => k.startsWith("all_"))
                          .map(([k,v],idx) => <li key={idx}>{k}: {JSON.stringify(v)}</li>)}
                      </ul>
                    </div>
                  )}
                  {showAllEvents && Array.isArray(e.logs) && e.logs.length > 0 && (
                    <div style={{marginTop:"10px"}}>
                      <b>Logs:</b>
                      <ul style={{marginTop:"6px"}}>
                        {e.logs.map((log,idx) => <li key={idx}>{log}</li>)}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── LIVE ML ── */}
          {activeTab==="ml" && (
            <div style={styles.mlBox}>
              <h2 style={{marginTop:0}}>📊 Live ML Monitor</h2>
              <p><b>Final Score:</b> {liveML.final ?? liveML.score ?? 'n/a'}</p>
              <p><b>System:</b>  {liveML.sys??'n/a'}</p>
              <p><b>Traffic:</b> {liveML.traf??'n/a'}</p>
              <p><b>Env:</b>     {liveML.env??'n/a'}</p>
            </div>
          )}

          {/* ── TELEMETRY ── */}
          {activeTab==="telemetry" && (
            <div>

              {/* SYSTEM METRICS */}
              <div style={styles.card}>
                <h3>🖥 System Metrics</h3>
                <p>CPU: {telemetry.sys?.cpu ?? "-"}</p>
                <p>MEM: {telemetry.sys?.mem ?? "-"}</p>
                <p>FLASH: {telemetry.sys?.flash ?? "-"}</p>
              </div>


              {/* ── LIVE ALERTS ── */}
              <div style={styles.card}>
                <h3>🚨 Live Alerts</h3>

                {events.length === 0 && <p style={{opacity:0.7}}>No alerts yet.</p>}

                {events.slice(0, 10).map((e, i) => (
                  <div key={i} style={{
                    borderLeft: "4px solid #f87171",
                    padding: "8px",
                    marginBottom: "6px",
                    background: "#16213a",
                    borderRadius: "6px"
                  }}>
                    <b>{e.root_cause_detail || e.root_cause || e.event || "Alert"}</b><br/>

                    <span style={{fontSize:"12px"}}>
                      Severity: {e.severity || "info"} | 
                      Confidence: {e.confidence ?? "-"}
                    </span>

                    {Array.isArray(e.recommendations) && (
                      <div style={{marginTop:"4px", fontSize:"12px"}}>
                        {e.recommendations.slice(0,2).map((r,ri) => (
                          <div key={ri}>• {r}</div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* PORT HEATMAP */}
              <div style={styles.card}>
                <h3>🔌 Ports</h3>
                <div style={{display:"flex", flexWrap:"wrap"}}>
                  {Object.entries(telemetry.ports || {}).map(([p,v],i) => {
                    const util = v.utilization || 0;
                    const color =
                      util > 70 ? "#ef4444" :
                      util > 30 ? "#f59e0b" :
                      "#22c55e";

                    return (
                      <div key={i}
                        style={{
                          width:"50px",
                          height:"20px",
                          margin:"4px",
                          background: color,
                          fontSize:"10px",
                          textAlign:"center",
                          borderRadius:"4px"
                        }}>
                        {p}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* RAW STREAM */}
              <div style={styles.card}>
                <h3>📡 Live Telemetry Stream</h3>
                <div style={{maxHeight:"300px", overflowY:"scroll", fontSize:"12px"}}>
                  {telemetryLog.map((t,i) => (
                    <div key={i}>
                      {JSON.stringify(t)}
                    </div>
                  ))}
                </div>
              </div>

            </div>
          )}

          {/* ── EVENTS ── */}
          {activeTab==="events" && (
            <div>
              <h2 style={{marginTop:0}}>📡 Event Stream</h2>
              {events.length === 0 && <p style={{opacity:0.7}}>No events yet.</p>}
              {events.map((e,i) => (
                <div key={i} style={styles.rowItem}>
                  <p style={{margin:"4px 0"}}><b>{e.event||"unknown"}</b> ({e.device||e.device_id||"unknown"})</p>
                  {showAllEvents && e.observations?.all_port_events && (
                    <p style={{margin:"2px 0"}}>Ports: {JSON.stringify(e.observations.all_port_events)}</p>
                  )}
                  {showAllEvents && e.observations?.all_traps && (
                    <p style={{margin:"2px 0"}}>Traps: {JSON.stringify(e.observations.all_traps)}</p>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── LOGS ── */}
          {activeTab==="logs" && (
            <div>
              <h2 style={{marginTop:0}}>📜 Logs</h2>
              {events.every(e => !e.logs || e.logs.length === 0) &&
                <p style={{opacity:0.7}}>No logs attached to any event yet.</p>}
              {events.map((e,i) => (
                <div key={i} style={{marginBottom:"12px"}}>
                  {Array.isArray(e.logs) && e.logs.map((log,idx) => (
                    <div key={idx} style={styles.logEntry}>{log}</div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    const root = ReactDOM.createRoot(document.getElementById("root"));
    root.render(<App />);
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
  try:
    with open(INDEX_FILE, "r", encoding="utf-8") as f:
      return HTMLResponse(f.read())
  except Exception:
    return HTMLResponse(DASHBOARD_HTML)

@app.get("/events")
def get_events():
  return EVENTS[-200:]


@app.post("/ingest")
async def ingest(event: dict):
    # If the event has our new "message" field, we treat it as a display alert
    if "message" in event:
        event["is_ui_alert"] = True 
        
    EVENTS.append(event)
    if len(EVENTS) > 500:
        EVENTS.pop(0)
    await broadcast(event)
    return {"status": "ok"}

@app.websocket("/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    CLIENTS.append(ws)
    try:
        while True:
            await asyncio.sleep(1)
    except Exception:
        pass
    finally:
        if ws in CLIENTS:
            CLIENTS.remove(ws)

async def broadcast(event):
    dead = []
    for ws in CLIENTS:
        try:
            await ws.send_text(json.dumps(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in CLIENTS:
            CLIENTS.remove(ws)

@app.get("/stream/telemetry")
def stream_telemetry():
    return StreamingResponse(tail_file(TELEMETRY_FILE), media_type="text/plain")

# --- SEPARATE TAIL FUNCTIONS ---

async def tail_ml_only():
    """Streams ONLY ML scores from ml_alerts_central.jsonl"""
    with open(ML_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.2)
                continue
            try:
                data = json.loads(line)
                # Accept any ML-like payload and always include device for UI routing.
                if isinstance(data, dict):
                    data["device"] = data.get("device_id") or data.get("device") or "UNKNOWN"
                    yield json.dumps(data) + "\n"
            except:
                continue

async def tail_alerts_only():
    with open(ALERTS_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue

            try:
                data = json.loads(line)

                # ✅ TAG AS UI ALERT (important for filtering)
                data["is_ui_alert"] = True

                yield json.dumps(data) + "\n"

            except:
                continue

# --- SEPARATE ENDPOINTS ---

async def tail_heap_metrics():
    with open(HEAP_FILE, "r") as f:

        #  Send last 20 lines (history)
        try:
            lines = f.readlines()
            for line in lines[-300:]:
                print("INIT HEAP:", line.strip())
                yield line
        except Exception as e:
            print("INIT ERROR:", e)

        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(1)
                continue

            print("HEAP STREAM:", line.strip())
            yield line

@app.get("/stream/ml")
async def stream_ml():
    # This now ONLY carries ML Data
    return StreamingResponse(tail_ml_only(), media_type="text/plain")

@app.get("/stream/alerts")
async def stream_dashboard_alerts():
    # This is a NEW endpoint for your Dashboard Alert box
    return StreamingResponse(tail_alerts_only(), media_type="text/plain")

@app.get("/stream/heap")
async def stream_heap():
    return StreamingResponse(tail_heap_metrics(), media_type="text/plain")
