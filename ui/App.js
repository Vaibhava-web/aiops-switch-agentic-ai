import React, { useEffect, useState } from "react";
import Graph from "./Graph";

function App() {
  const [events, setEvents] = useState([]);
  const [liveMLMap, setLiveMLMap] = useState({});
  const [activeTab, setActiveTab] = useState("ai");
  const [showSignals, setShowSignals] = useState(true);
  const [showAllEvents, setShowAllEvents] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState("ALL");
  const [devices, setDevices] = useState(["ALL"]);

  useEffect(() => {
    fetch("/events")
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) {
          setEvents(data.slice(-100).reverse());
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetch("/stream/ml") // Points to the ML-only stream
      .then(res => {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        function read() {
          reader.read().then(({done, value}) => {
            if (done) return;
            const text = decoder.decode(value);
            text.split("\n").forEach(line => {
              if (!line) return;
              try {
                const data = JSON.parse(line);
                if (data.observations && data.observations.ml_anomaly) {
                  const device = data.device || data.device_id || "UNKNOWN";
                  setLiveMLMap((prev) => ({
                    ...prev,
                    [device]: data.observations.ml_anomaly
                  }));
                }
              } catch {}
            });
            read();
          });
        }
        read();
      });
  }, []);

  useEffect(() => {
    fetch("/stream/alerts") // Points to the Alerts-only stream
      .then(res => {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        function read() {
          reader.read().then(({done, value}) => {
            if (done) return;
            const text = decoder.decode(value);
            text.split("\n").forEach(line => {
              if (!line) return;
              try {
                const data = JSON.parse(line);
                data.is_ui_alert = true;
                setEvents(prev => [data, ...prev].slice(0, 200)); // ONLY updates Alert list
              } catch {}
            });
            read();
          });
        }
        read();
      });
  }, []);

  useEffect(() => {
    const ws = new WebSocket("ws://10.95.131.72:8001/stream");

    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data);
        const streamEvent = parsed && parsed.type === "alert" ? parsed.data : parsed;

        if (streamEvent && typeof streamEvent === "object") {
          if (streamEvent.is_ui_alert) {
            setEvents((prev) => [streamEvent, ...prev].slice(0, 200));
          }

          const mlFromEnvelope = parsed && parsed.type === "ml" ? parsed.data : null;
          const mlFromEvent =
            streamEvent.observations &&
            typeof streamEvent.observations.ml_anomaly === "object"
              ? streamEvent.observations.ml_anomaly
              : null;

          if (mlFromEnvelope && typeof mlFromEnvelope === "object") {
            const device = streamEvent.device || streamEvent.device_id || "UNKNOWN";
            setLiveMLMap((prev) => ({
              ...prev,
              [device]: mlFromEnvelope
            }));
          } else if (mlFromEvent) {
            const device = streamEvent.device || streamEvent.device_id || "UNKNOWN";
            setLiveMLMap((prev) => ({
              ...prev,
              [device]: mlFromEvent
            }));
          }
        }
      } catch {
        // Ignore malformed stream payloads to keep UI responsive.
      }
    };

    return () => ws.close();
  }, []);

  useEffect(() => {
    const unique = new Set();

    events.forEach((event) => {
      const device = event.device || event.device_id;
      if (device) {
        unique.add(device);
      }
    });

    setDevices(["ALL", ...Array.from(unique)]);
  }, [events]);

  const tabs = ["ai", "ml", "telemetry", "events", "logs"]
  const tabLabel = {
    ai: "AI Summary",
    ml: "Live ML",
    telemetry: "Telemetry",
    events: "Events",
    logs: "Logs"
  };

  const filteredEvents =
    selectedDevice === "ALL"
      ? events
      : events.filter(
          (event) => (event.device || event.device_id) === selectedDevice
        );

  const selectedML =
    selectedDevice === "ALL"
      ? Object.values(liveMLMap)[0] || {}
      : liveMLMap[selectedDevice] || {};

  return (
    <div
      style={{
        background: "linear-gradient(140deg, #0b1220 0%, #101a2f 55%, #0f1f1f 100%)",
        color: "#e5edf8",
        minHeight: "100vh",
        padding: "20px",
        fontFamily: "'IBM Plex Sans', 'Segoe UI', Tahoma, sans-serif"
      }}
    >
      <h1 style={{ marginTop: 0, marginBottom: "16px" }}>Network AI Dashboard</h1>

      <div style={{ marginBottom: "12px" }}>
        <label style={{ marginRight: "10px" }}>Device:</label>
        <select
          value={selectedDevice}
          onChange={(e) => setSelectedDevice(e.target.value)}
          style={{
            padding: "6px",
            borderRadius: "6px",
            background: "#182845",
            color: "white",
            border: "1px solid #2a3e63"
          }}
        >
          {devices.map((device) => (
            <option key={device} value={device}>{device}</option>
          ))}
        </select>
      </div>

      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "10px",
          marginBottom: "16px",
          borderBottom: "1px solid #253552",
          paddingBottom: "10px"
        }}
      >
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              border: "none",
              cursor: "pointer",
              borderRadius: "8px",
              padding: "8px 12px",
              background: activeTab === tab ? "#2f72ff" : "#182845",
              color: "#f4f8ff",
              fontWeight: activeTab === tab ? 700 : 500
            }}
          >
            {tabLabel[tab]}
          </button>
        ))}
      </div>

      {(activeTab === "ai" || activeTab === "events" || activeTab === "logs") && (
        <div style={{ marginBottom: "14px", display: "flex", gap: "18px", flexWrap: "wrap" }}>
          <label>
            <input
              type="checkbox"
              checked={showSignals}
              onChange={() => setShowSignals(!showSignals)}
            />{" "}
            Show Signals
          </label>
          <label>
            <input
              type="checkbox"
              checked={showAllEvents}
              onChange={() => setShowAllEvents(!showAllEvents)}
            />{" "}
            Show Full Events
          </label>
        </div>
      )}

      {activeTab === "ai" && (
        <div>
          <div
            style={{
              marginBottom: "20px",
              background: "#0f2038",
              border: "1px solid #264466",
              borderRadius: "12px",
              padding: "12px"
            }}
          >
            <Graph data={filteredEvents} />
          </div>

          {filteredEvents
            .filter(e => e.is_ui_alert)
            .map((e, i) => {
            return (
              <div
                key={i}
                style={{
                  border: "1px solid #2a3e63",
                  borderRadius: "12px",
                  padding: "14px",
                  marginBottom: "12px",
                  background: "rgba(14, 25, 45, 0.92)",
                  boxShadow: "0 3px 12px rgba(0, 0, 0, 0.22)"
                }}
              >
                {/* Header Row */}
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <h3 style={{ marginTop: 0, marginBottom: 0 }}>
                    {e.severity ? `${e.severity} Alert` : `Alert: ${e.event || "System"}`}
                  </h3>
                  <span style={{ fontSize: "12px", opacity: 0.7 }}>{e.timestamp || "Live"}</span>
                </div>

                <p style={{ margin: "4px 0" }}>
                  <b>Device:</b> {e.device || e.device_id || "NANDI"}
                </p>

                {/* OPTION A: Show Formatted Terminal Message (New) */}
                {e.message ? (
                  <div style={{ marginTop: "10px" }}>
                    <pre style={{ 
                      whiteSpace: "pre-wrap", 
                      fontFamily: "'IBM Plex Mono', monospace", 
                      background: "#0a1529",
                      padding: "10px",
                      borderRadius: "6px",
                      color: "#e2e8f0",
                      fontSize: "13px",
                      border: "1px solid #1e2f4f"
                    }}>
                      {e.message}
                    </pre>
                  </div>
                ) : (
                  /* OPTION B: Original Detailed Signals View (Fallback) */
                  <>
                    <p style={{ margin: "4px 0" }}>
                      <b>Confidence:</b> {e.confidence ?? "n/a"}
                    </p>

                    {showSignals && e.observations && (
                      <div style={{ marginTop: "10px" }}>
                        <b>Signals:</b>
                        <ul style={{ marginTop: "6px" }}>
                          {Object.entries(e.observations)
                            .filter(([k]) => !k.startsWith("all_"))
                            .map(([k, v], idx) => (
                              <li key={idx}>
                                {k}: {JSON.stringify(v)}
                              </li>
                            ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}

                {/* Show Logs if toggled and available */}
                {showAllEvents && Array.isArray(e.logs) && e.logs.length > 0 && (
                  <div style={{ marginTop: "10px", borderTop: "1px solid #1e2f4f", paddingTop: "10px" }}>
                    <b>Related Logs:</b>
                    <ul style={{ marginTop: "6px", fontSize: "12px", fontFamily: "monospace", opacity: 0.8 }}>
                      {e.logs.map((log, idx) => (
                        <li key={idx} style={{ marginBottom: "2px" }}>{log}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {activeTab === "ml" && (
        <div
          style={{
            border: "1px solid #2d6044",
            background: "#102c21",
            borderRadius: "12px",
            padding: "16px"
          }}
        >
          <h2 style={{ marginTop: 0 }}>Live ML Monitor</h2>
          <p><b>Final Score:</b> {selectedML.final ?? selectedML.score ?? "n/a"}</p>
          <p><b>System:</b> {selectedML.sys ?? "n/a"}</p>
          <p><b>Traffic:</b> {selectedML.traf ?? "n/a"}</p>
          <p><b>Env:</b> {selectedML.env ?? "n/a"}</p>
        </div>
      )}

      {activeTab === "events" && (
        <div>
          <h2 style={{ marginTop: 0 }}>Event Stream</h2>
          {filteredEvents
            .filter(e => e.is_ui_alert)
            .map((e, i) => (
            <div
              key={i}
              style={{
                borderBottom: "1px solid #304766",
                padding: "10px 0"
              }}
            >
              <p style={{ margin: "4px 0" }}>
                <b>{e.event || "unknown"}</b> ({e.device || e.device_id || "unknown"})
              </p>
              {showAllEvents && e.observations?.all_port_events && (
                <p style={{ margin: "4px 0" }}>
                  Ports: {JSON.stringify(e.observations.all_port_events)}
                </p>
              )}
              {showAllEvents && e.observations?.all_traps && (
                <p style={{ margin: "4px 0" }}>
                  Traps: {JSON.stringify(e.observations.all_traps)}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {activeTab === "logs" && (
        <div>
          <h2 style={{ marginTop: 0 }}>Logs</h2>
          {filteredEvents
            .filter(e => e.is_ui_alert)
            .map((e, i) => (
            <div key={i} style={{ marginBottom: "12px" }}>
              {Array.isArray(e.logs) && e.logs.length > 0 ? (
                e.logs.map((log, idx) => (
                  <div
                    key={idx}
                    style={{
                      fontSize: "12px",
                      fontFamily: "'IBM Plex Mono', Consolas, monospace",
                      background: "#152236",
                      padding: "6px",
                      borderRadius: "6px",
                      marginBottom: "4px"
                    }}
                  >
                    {log}
                  </div>
                ))
              ) : (
                <div style={{ opacity: 0.7 }}>No logs attached.</div>
              )}
            </div>
          ))}
        </div>
      )}

      {events.length === 0 && (
        <div style={{ opacity: 0.8, marginTop: "16px" }}>No events received yet.</div>
      )}
    </div>
  );
}

export default App;