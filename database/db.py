import os
import sqlite3
import datetime
from typing import Dict, List, Any, Optional
import logging

from utils.config import DB_PATH, DB_DIR

logger = logging.getLogger("NIDS_DB")
logger.setLevel(logging.INFO)

def get_connection():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the SQLite database table structure if it doesn't exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intrusion_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            formatted_time TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            attack_type TEXT,
            raw_label TEXT,
            severity TEXT,
            confidence REAL,
            is_intrusion INTEGER,
            flow_duration REAL,
            total_packets REAL,
            total_bytes REAL
        );
    """)
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")

def insert_log(alert_data: Dict[str, Any]) -> int:
    """Inserts a new network traffic alert record into the database."""
    conn = get_connection()
    cursor = conn.cursor()
    
    ts = alert_data.get("timestamp", datetime.datetime.now().timestamp())
    formatted_time = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("""
        INSERT INTO intrusion_logs (
            timestamp, formatted_time, src_ip, dst_ip, src_port, dst_port,
            protocol, attack_type, raw_label, severity, confidence, is_intrusion,
            flow_duration, total_packets, total_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        ts,
        formatted_time,
        alert_data.get("src_ip", "0.0.0.0"),
        alert_data.get("dst_ip", "0.0.0.0"),
        int(alert_data.get("src_port", 0)),
        int(alert_data.get("dst_port", 0)),
        alert_data.get("protocol", "TCP"),
        alert_data.get("attack_type", "Benign"),
        alert_data.get("raw_label", "BENIGN"),
        alert_data.get("severity", "INFO"),
        float(alert_data.get("confidence", 0.0)),
        1 if alert_data.get("is_intrusion") else 0,
        float(alert_data.get("flow_duration", 0.0)),
        float(alert_data.get("total_packets", 0.0)),
        float(alert_data.get("total_bytes", 0.0))
    ))
    
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def get_logs(
    limit: int = 100,
    offset: int = 0,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    only_intrusions: bool = False
) -> List[Dict[str, Any]]:
    """Retrieves paginated intrusion logs with optional filters."""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM intrusion_logs WHERE 1=1"
    params = []
    
    if attack_type and attack_type != "All":
        query += " AND attack_type = ?"
        params.append(attack_type)
        
    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)
        
    if only_intrusions:
        query += " AND is_intrusion = 1"
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    result = [dict(row) for row in rows]
    conn.close()
    return result

def get_statistics() -> Dict[str, Any]:
    """Calculates overall summary metrics and distribution for dashboard and APIs."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM intrusion_logs;")
    total_flows = cursor.fetchone()["total"]
    
    cursor.execute("SELECT COUNT(*) as attacks FROM intrusion_logs WHERE is_intrusion = 1;")
    total_attacks = cursor.fetchone()["attacks"]
    
    cursor.execute("SELECT COUNT(*) as high FROM intrusion_logs WHERE severity = 'HIGH';")
    high_threats = cursor.fetchone()["high"]
    
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM intrusion_logs 
        GROUP BY attack_type 
        ORDER BY count DESC;
    """)
    attack_counts = {row["attack_type"]: row["count"] for row in cursor.fetchall()}
    
    cursor.execute("""
        SELECT severity, COUNT(*) as count 
        FROM intrusion_logs 
        GROUP BY severity;
    """)
    severity_counts = {row["severity"]: row["count"] for row in cursor.fetchall()}
    
    conn.close()
    
    malicious_ratio = (total_attacks / total_flows * 100) if total_flows > 0 else 0.0
    
    return {
        "total_flows": total_flows,
        "total_attacks": total_attacks,
        "high_threats": high_threats,
        "malicious_ratio": round(malicious_ratio, 2),
        "attack_distribution": attack_counts,
        "severity_distribution": severity_counts
    }

def clear_logs():
    """Clears all historical intrusion logs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM intrusion_logs;")
    conn.commit()
    conn.close()
