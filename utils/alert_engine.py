from typing import Dict, Any
from utils.config import SEVERITY_MAP

def generate_alert(packet_meta: Dict[str, Any], prediction: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a structured alert payload based on packet metadata and prediction result.
    """
    raw_label = prediction.get("raw_label", "BENIGN")
    attack_name = prediction.get("predicted_attack", "Benign")
    confidence = prediction.get("confidence", 0.0)
    is_intrusion = prediction.get("is_intrusion", False)
    
    severity = SEVERITY_MAP.get(raw_label, "INFO") if is_intrusion else "INFO"
    
    # Adjust severity dynamically if model confidence is lower
    if is_intrusion and confidence < 0.6:
        severity = "LOW"
    elif is_intrusion and severity == "INFO":
        severity = "MEDIUM"
        
    return {
        "timestamp": packet_meta.get("timestamp"),
        "src_ip": packet_meta.get("src_ip", "0.0.0.0"),
        "dst_ip": packet_meta.get("dst_ip", "0.0.0.0"),
        "src_port": packet_meta.get("src_port", 0),
        "dst_port": packet_meta.get("dst_port", 0),
        "protocol": packet_meta.get("protocol", "TCP"),
        "attack_type": attack_name,
        "raw_label": raw_label,
        "severity": severity,
        "confidence": confidence,
        "is_intrusion": is_intrusion,
        "flow_duration": packet_meta.get("flow_duration", 0),
        "total_packets": packet_meta.get("total_packets", 0),
        "total_bytes": packet_meta.get("total_bytes", 0)
    }
