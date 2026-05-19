# AIOps Networking Switch Agentic AI (Network AI Copilot)

An enterprise-grade, distributed AIOps framework designed for autonomous network reliability, telemetry ingestion, and closed-loop remediation at the switch layer. This project implements a split-architecture consisting of a high-performance **Edge Agent** embedded near the switch operating system and a parallelized **Central Inference Server** for heavy telemetry analysis and cross-switch correlation.

---

## 🏗️ System Architecture

![Network Copilot Architecture](assets/architecture.png)

The framework is divided into two decoupled layers to balance low-latency edge edge computation with heavy AI model inference.

### 1. Edge Agent (Switch-Level)
Designed to run with minimal footprint near the switch hardware/OS layer, focusing on rapid metrics harvesting and stream ingestion:
* **Metrics Ingestion (Fast/Slow Loops):** Low-overhead polling loops capturing CPU, Memory, and Flash utilization. Executes `SNMP BULKWALK` (IF-MIB, BRIDGE-MIB, LLDP-MIB) to normalize telemetry into structured `.jsonl` streams.
* **Syslog & SNMP Trap Ingestion:** Active log daemons capturing internal system events into local buffers.
* **Local AI Brain:** Runs lightweight statistical ML anomalies (EWMA, CUSUM, Isolation Forest Lite) for immediate, on-box edge analysis.
* **Remediation Engine:** An intelligent state machine evaluating local anomalies to execute immediate active CLI commands or dry-run logs for self-healing edge operations.

### 2. Central Server & UI Orchestration
A highly scalable parallel computing backend designed to digest telemetry streams forwarded from thousands of edge agents:
* **Parallel Analysis Engine:** Multi-threaded handler routing log arrays into dedicated queues (`LOG_QUEUE`, `EVENT_QUEUE`).
* **Deep NLP Sequence Tracking:** Utilizes pre-trained `SentenceTransformers` and `DBSCAN` clustering for unsupervised log semantic analysis. Predicts cascading network failures by passing logs through deep `LSTM` sequence models and an Impact Propagation Graph Model.
* **Alert & Notification Manager:** Closed-loop alert verification system triggering automatic webhooks, SMTP emails, and upstream UI events once anomaly confidence crosses boosting thresholds.
* **Streaming UI Dashboard:** A real-time monitoring interface leveraging WebSockets and a frontend layout to stream telemetry data, gauge live ML confidence scores, and display interactive D3 network topologies.

---

## 🛠️ Tech Stack & Infrastructure

* **Languages:** Python 3.12, C++ (Switch Firmware Interaction wrappers)
* **Deep Learning & NLP:** TensorFlow/PyTorch, SentenceTransformers (all-MiniLM-L6-v2), LSTM
* **Statistical ML:** Scikit-Learn (Isolation Forest), NumPy, Pandas
* **Data Pipelines & Storage:** Redis Vector Search, Structured JSONL Streaming, SocketServer (Threaded HTTP & WebSockets)
* **Containerization:** Docker / Docker-Compose

---

## 🚀 Quick Start & Deployment

### Prerequisites
* Docker & Docker-Compose installed
* Python 3.12 virtual environment (if running bare-metal)

### Running the Infrastructure via Docker
To bring up the Central Inference Server, Redis database, and the Streaming Dashboard UI concurrently, execute:

```bash
git clone [https://github.com/yourusername/aiops-switch-agentic-ai.git](https://github.com/yourusername/aiops-switch-agentic-ai.git)
cd aiops-switch-agentic-ai
docker-compose up --build