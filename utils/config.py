import os
from pathlib import Path

# Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Models Directory
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "nids_best_model_random_forest.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.pkl"
CONFIG_PATH = MODELS_DIR / "preprocessing_config.pkl"

# Database Path
DB_DIR = BASE_DIR / "database"
DB_PATH = DB_DIR / "nids.db"

# Server Config
API_HOST = os.getenv("NIDS_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("NIDS_API_PORT", 8000))
API_BASE_URL = f"http://{API_HOST}:{API_PORT}"

# Severity Mapping for Attack Types
SEVERITY_MAP = {
    "BENIGN": "INFO",
    "DoS Hulk": "HIGH",
    "DoS GoldenEye": "HIGH",
    "DoS slowloris": "HIGH",
    "DoS Slowhttptest": "HIGH",
    "DDoS": "HIGH",
    "Heartbleed": "HIGH",
    "Infiltration": "HIGH",
    "Bot": "MEDIUM",
    "PortScan": "MEDIUM",
    "FTP-Patator": "MEDIUM",
    "SSH-Patator": "MEDIUM",
    "Web Attack ? Brute Force": "MEDIUM",
    "Web Attack ? Sql Injection": "HIGH",
    "Web Attack ? XSS": "MEDIUM"
}

# Clean labels for presentation
CLEAN_LABEL_MAP = {
    "BENIGN": "Benign",
    "Bot": "Botnet",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS GoldenEye",
    "DoS Hulk": "DoS Hulk",
    "DoS Slowhttptest": "DoS SlowHTTP",
    "DoS slowloris": "DoS Slowloris",
    "FTP-Patator": "FTP BruteForce",
    "Heartbleed": "Heartbleed Vulnerability",
    "Infiltration": "Network Infiltration",
    "PortScan": "Port Scan",
    "SSH-Patator": "SSH BruteForce",
    "Web Attack ? Brute Force": "Web BruteForce",
    "Web Attack ? Sql Injection": "Web SQL Injection",
    "Web Attack ? XSS": "Web XSS Attack"
}
