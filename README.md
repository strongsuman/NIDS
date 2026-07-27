# 🚀 AI-Powered Real-Time Network Intrusion Detection System (NIDS)

An enterprise-ready, real-time AI-based **Network Intrusion Detection System (NIDS)** that captures live network packets, extracts 47 statistical flow features, classifies traffic using Machine Learning (Random Forest trained on CICIDS2017), explains predictions using SHAP, generates automated threat alerts, logs events in SQLite, and provides an interactive multi-page Streamlit dashboard and FastAPI REST backend.

---

## 🎯 Key Capabilities

- **⚡ Real-Time Flow Classification**: Analyzes live network streams and classifies traffic into 15 attack categories (DoS Hulk, DDoS, PortScan, FTP/SSH BruteForce, Botnet, Web Attacks, Benign).
- **📡 Live Packet Capture & Synthetic Traffic Feed**: Integrated Scapy sniffer module with a fallback **Synthetic Traffic Simulator** for demonstration across all OS environments without requiring root/admin raw socket access.
- **📊 Interactive Cybersecurity Dashboard**: Streamlit multi-page UI featuring Live Traffic Monitor, Threat Alert Banners, Interactive Plotly Visualizations, Log History & Reports with CSV export, and ML Model Performance Metrics.
- **🧠 Explainable AI (SHAP)**: Provides model transparency with top feature contribution charts for every detected intrusion.
- **⚡ FastAPI Backend**: REST API endpoints for remote flow prediction, SHAP explanations, log queries, system health, and background sniffer stream control.
- **🐳 Docker Containerization**: Multi-container setup orchestrating FastAPI, Streamlit, and SQLite using `docker-compose up`.

---

## 🏗️ Project Architecture

```text
                               Live Network / Synthetic Stream
                                              │
                                              ▼
                                 Packet Sniffer (Scapy / Generator)
                                              │
                                              ▼
                                Flow Extractor (47 CICIDS2017 Features)
                                              │
                                              ▼
                               Random Forest ML Classifier & Scaler
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
               Alert Engine            SQLite Database           SHAP Explainer
             (Severity & Rules)        (Persistent Logs)       (Feature Impact)
                    │                         │                         │
                    └─────────────────────────┼─────────────────────────┘
                                              ▼
                                   FastAPI REST Backend
                                              │
                                              ▼
                                  Streamlit Multi-Page UI
```

---

## 📁 Directory Structure

```text
e:\NIDS/
│
├── models/                         # Pre-trained ML model and preprocessing artifacts
│   ├── nids_best_model_random_forest.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   ├── feature_names.pkl
│   └── preprocessing_config.pkl
│
├── predictor/                      # Inference and SHAP explainability engine
│   └── predict.py
│
├── feature_extraction/             # Flow aggregation into 47 CICIDS2017 features
│   └── flow_extractor.py
│
├── packet_capture/                 # Scapy packet sniffer & live traffic simulator
│   └── sniffer.py
│
├── utils/                          # Configuration and alert severity engine
│   ├── config.py
│   └── alert_engine.py
│
├── database/                       # SQLite database ORM & querying module
│   └── db.py
│
├── api/                            # FastAPI web server and REST endpoints
│   └── main.py
│
├── dashboard/                      # Multi-page Streamlit web dashboard
│   └── app.py
│
├── docker/                         # Docker build configuration
│   └── Dockerfile
│
├── tests/                          # Automated unit test suite
│   ├── test_predictor.py
│   ├── test_flow_extractor.py
│   ├── test_db.py
│   └── test_api.py
│
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 🛠️ Quickstart & Local Setup

### 1. Prerequisites
- Python 3.10+
- `pip` package manager

### 2. Install Dependencies
```bash
pip install -r requirements.txt
pip install fastapi uvicorn streamlit scapy plotly
```

### 3. Launch FastAPI Backend
```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```
Access interactive API docs at: `http://127.0.0.1:8000/docs`

### 4. Launch Streamlit Dashboard
```bash
streamlit run dashboard/app.py
```
Open browser at: `http://localhost:8501`

---

## 🐳 Docker Deployment

To launch the complete NIDS system with Docker Compose:

```bash
docker-compose up --build
```
- **FastAPI API**: `http://localhost:8000`
- **Streamlit Dashboard**: `http://localhost:8501`

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API status and metadata |
| `GET` | `/health` | System readiness & ML model status |
| `POST` | `/predict` | Classify a network flow vector & log threat alert |
| `POST` | `/explain` | Generate SHAP feature importance for a flow sample |
| `GET` | `/logs` | Fetch historical intrusion logs with filters & pagination |
| `GET` | `/statistics` | Summary metrics, attack counts, and severity breakdown |
| `POST` | `/capture/start` | Start live background packet sniffer / simulator |
| `POST` | `/capture/stop` | Stop live packet sniffer |
| `GET` | `/capture/status` | Check sniffer status |
| `DELETE` | `/logs` | Clear historical database logs |

---

## 🧪 Automated Testing

Run pytest across all unit test suites:

```bash
pytest tests/ -v
```

---

## 🎓 Interview & Placement Highlights

1. **End-to-End Real-World Application**: Goes beyond offline Jupyter Notebooks to demonstrate live packet capture, feature scaling, model inference, alert generation, API endpoints, SQLite persistence, and UI monitoring.
2. **Explainable AI (XAI)**: Uses SHAP (SHapley Additive exPlanations) to prove why the ML model flagged a flow (e.g. high `Flow Packets/s` or abnormal `Fwd Header Length`).
3. **Resilient System Design**: Features a background thread traffic simulator allowing seamless demonstration even without root network privileges.
