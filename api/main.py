import sys
from pathlib import Path

# Add project root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import time
import logging
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from predictor.predict import get_predictor
from utils.alert_engine import generate_alert
from database.db import init_db, insert_log, get_logs, get_statistics, clear_logs
from packet_capture.sniffer import SyntheticTrafficSimulator

logger = logging.getLogger("NIDS_API")
logging.basicConfig(level=logging.INFO)

# Initialize database tables
init_db()

# Global background sniffer instance
simulator_instance: Optional[SyntheticTrafficSimulator] = None

app = FastAPI(
    title="AI-Powered Real-Time Network Intrusion Detection System (NIDS)",
    description="FastAPI Backend for real-time packet classification, attack detection rules, SQLite logging, and SHAP explainability.",
    version="2.0.0"
)

# Enable CORS for Streamlit / external frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic Schemas
class FlowPredictionRequest(BaseModel):
    src_ip: Optional[str] = "192.168.1.100"
    dst_ip: Optional[str] = "192.168.1.1"
    src_port: Optional[int] = 49152
    dst_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    features: Dict[str, float] = Field(
        default_factory=dict,
        description="47 CICIDS2017 feature dictionary"
    )

class SnifferControlRequest(BaseModel):
    attack_mode: Optional[str] = Field("MIXED", description="BENIGN, DOS, DDOS, PORTSCAN, BRUTEFORCE, MIXED")

def _on_simulated_packet(packet_meta: Dict[str, Any], feature_dict: Dict[str, float]):
    """Callback for automated flow processing from background sniffer."""
    try:
        predictor = get_predictor()
        pred = predictor.predict_single(feature_dict)
        alert = generate_alert(packet_meta, pred)
        insert_log(alert)
    except Exception as e:
        logger.error(f"Error processing background traffic flow: {e}")

@app.on_event("startup")
def startup_event():
    """Warm up predictor model on app launch."""
    try:
        get_predictor()
        logger.info("NIDS ML Predictor warmed up successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize ML Predictor on startup: {e}")

@app.get("/", tags=["Metadata"])
def root():
    return {
        "system": "AI-Powered Real-Time Network Intrusion Detection System (NIDS)",
        "status": "Operational",
        "version": "2.0.0",
        "docs_url": "/docs"
    }

@app.get("/health", tags=["Health"])
def health_check():
    predictor = get_predictor()
    model_loaded = predictor.model is not None
    return {
        "status": "healthy" if model_loaded else "unhealthy",
        "model_loaded": model_loaded,
        "features_count": len(predictor.feature_names),
        "classes_count": len(predictor.label_encoder.classes_) if model_loaded else 0,
        "timestamp": time.time()
    }

@app.post("/predict", tags=["Prediction"])
def predict_flow(request: FlowPredictionRequest):
    """
    Classify a network flow vector using the trained Random Forest model and log the alert into SQLite DB.
    """
    try:
        predictor = get_predictor()
        feature_dict = request.features.copy()
        if "Destination Port" not in feature_dict and request.dst_port:
            feature_dict["Destination Port"] = float(request.dst_port)
            
        prediction = predictor.predict_single(feature_dict)
        
        packet_meta = {
            "timestamp": time.time(),
            "src_ip": request.src_ip,
            "dst_ip": request.dst_ip,
            "src_port": request.src_port,
            "dst_port": request.dst_port,
            "protocol": request.protocol,
            "flow_duration": feature_dict.get("Flow Duration", 0.0),
            "total_packets": feature_dict.get("Total Fwd Packets", 0.0),
            "total_bytes": feature_dict.get("Total Length of Fwd Packets", 0.0)
        }
        
        alert = generate_alert(packet_meta, prediction)
        log_id = insert_log(alert)
        
        return {
            "log_id": log_id,
            "alert": alert,
            "prediction": prediction
        }
    except Exception as e:
        logger.error(f"Prediction API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/explain", tags=["Explainability"])
def explain_flow(request: FlowPredictionRequest, top_n: int = Query(5, ge=1, le=47)):
    """
    Generates SHAP explainability feature impacts for a given network flow.
    """
    try:
        predictor = get_predictor()
        feature_dict = request.features.copy()
        if "Destination Port" not in feature_dict and request.dst_port:
            feature_dict["Destination Port"] = float(request.dst_port)
            
        explanation = predictor.explain_sample(feature_dict, top_n=top_n)
        return explanation
    except Exception as e:
        logger.error(f"SHAP explanation API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs", tags=["Logs"])
def fetch_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    attack_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    only_intrusions: bool = Query(False)
):
    """
    Retrieve historical network intrusion logs stored in SQLite database.
    """
    try:
        logs = get_logs(
            limit=limit,
            offset=offset,
            attack_type=attack_type,
            severity=severity,
            only_intrusions=only_intrusions
        )
        return {
            "count": len(logs),
            "offset": offset,
            "limit": limit,
            "logs": logs
        }
    except Exception as e:
        logger.error(f"Logs retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/statistics", tags=["Analytics"])
def fetch_statistics():
    """
    Retrieve overall summary metrics and threat breakdown for dashboard analytics.
    """
    try:
        stats = get_statistics()
        return stats
    except Exception as e:
        logger.error(f"Statistics retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/capture/start", tags=["Packet Capture"])
def start_capture(control: Optional[SnifferControlRequest] = None):
    """
    Starts the real-time background packet sniffer / traffic simulator stream.
    """
    global simulator_instance
    mode = control.attack_mode if control else "MIXED"
    
    if simulator_instance is not None and simulator_instance.running:
        simulator_instance.set_attack_mode(mode)
        return {"status": "already_running", "attack_mode": mode}
        
    simulator_instance = SyntheticTrafficSimulator(callback=_on_simulated_packet)
    simulator_instance.set_attack_mode(mode)
    simulator_instance.start()
    
    return {"status": "started", "attack_mode": mode}

@app.post("/capture/stop", tags=["Packet Capture"])
def stop_capture():
    """
    Stops the background packet sniffer / traffic simulator stream.
    """
    global simulator_instance
    if simulator_instance is not None:
        simulator_instance.stop()
        simulator_instance = None
        return {"status": "stopped"}
    return {"status": "not_running"}

@app.get("/capture/status", tags=["Packet Capture"])
def capture_status():
    global simulator_instance
    is_running = simulator_instance is not None and simulator_instance.running
    mode = simulator_instance.attack_mode if is_running else "STOPPED"
    return {
        "running": is_running,
        "attack_mode": mode
    }

@app.delete("/logs", tags=["Logs"])
def clear_all_logs():
    """
    Clears all historical records in SQLite database.
    """
    try:
        clear_logs()
        return {"status": "cleared", "message": "All intrusion logs have been deleted."}
    except Exception as e:
        logger.error(f"Clear logs error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
