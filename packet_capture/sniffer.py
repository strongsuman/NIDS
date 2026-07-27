import time
import random
import threading
import logging
from typing import Callable, Optional, Dict, Any, List

logger = logging.getLogger("NIDS_Sniffer")
logger.setLevel(logging.INFO)

# Sample IPs for simulation
BENIGN_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.42", "10.0.0.5", "172.16.0.8"]
ATTACK_IPS = ["172.16.0.100", "192.168.1.200", "10.0.0.99", "185.220.101.5", "45.146.164.110"]
SERVER_IPS = ["192.168.1.1", "10.0.0.1", "192.168.1.50"]

COMMON_PORTS = [80, 443, 22, 21, 53, 8080, 3306, 8443]

class SyntheticTrafficSimulator:
    """
    Generates realistic real-time network flow vectors for live testing and demonstration.
    Supports generating normal web/DNS traffic and distinct attack vector signatures.
    """
    def __init__(self, callback: Callable[[Dict[str, Any], Dict[str, float]], None]):
        self.callback = callback
        self.running = False
        self.thread = None
        self.attack_mode = "MIXED" # BENIGN, DOS, DDOS, PORTSCAN, BRUTEFORCE, MIXED

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("Synthetic Traffic Simulator started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
        logger.info("Synthetic Traffic Simulator stopped.")

    def set_attack_mode(self, mode: str):
        self.attack_mode = mode

    def _run_loop(self):
        while self.running:
            # Decide flow type based on attack_mode
            if self.attack_mode == "BENIGN":
                flow_type = "BENIGN"
            elif self.attack_mode == "DOS":
                flow_type = "DoS Hulk" if random.random() > 0.3 else "BENIGN"
            elif self.attack_mode == "DDOS":
                flow_type = "DDoS" if random.random() > 0.2 else "BENIGN"
            elif self.attack_mode == "PORTSCAN":
                flow_type = "PortScan" if random.random() > 0.3 else "BENIGN"
            elif self.attack_mode == "BRUTEFORCE":
                flow_type = "FTP-Patator" if random.random() > 0.5 else "SSH-Patator"
            else: # MIXED
                rand_val = random.random()
                if rand_val < 0.65:
                    flow_type = "BENIGN"
                elif rand_val < 0.75:
                    flow_type = "DoS Hulk"
                elif rand_val < 0.85:
                    flow_type = "PortScan"
                elif rand_val < 0.93:
                    flow_type = "DDoS"
                else:
                    flow_type = "FTP-Patator"

            packet_meta, feature_dict = self._generate_flow_signature(flow_type)
            try:
                self.callback(packet_meta, feature_dict)
            except Exception as e:
                logger.error(f"Error in traffic simulator callback: {e}")

            time.sleep(random.uniform(0.5, 1.5))

    def _generate_flow_signature(self, flow_type: str) -> tuple:
        now = time.time()
        
        if flow_type == "BENIGN":
            src_ip = random.choice(BENIGN_IPS)
            dst_ip = random.choice(SERVER_IPS)
            dst_port = random.choice([80, 443, 53])
            src_port = random.randint(49152, 65535)
            protocol = 6 if dst_port != 53 else 17
            
            features = {
                "Destination Port": float(dst_port),
                "Flow Duration": float(random.randint(10000, 500000)),
                "Total Fwd Packets": float(random.randint(2, 10)),
                "Total Length of Fwd Packets": float(random.randint(100, 1500)),
                "Fwd Packet Length Max": float(random.randint(60, 500)),
                "Fwd Packet Length Min": 0.0,
                "Fwd Packet Length Mean": float(random.randint(40, 200)),
                "Bwd Packet Length Max": float(random.randint(200, 1400)),
                "Bwd Packet Length Min": 0.0,
                "Flow Bytes/s": float(random.randint(1000, 50000)),
                "Flow Packets/s": float(random.randint(10, 100)),
                "Flow IAT Mean": float(random.randint(1000, 50000)),
                "Flow IAT Std": float(random.randint(500, 20000)),
                "Flow IAT Max": float(random.randint(5000, 100000)),
                "Flow IAT Min": float(random.randint(1, 100)),
                "Fwd IAT Mean": float(random.randint(2000, 60000)),
                "Fwd IAT Std": float(random.randint(1000, 30000)),
                "Fwd IAT Min": float(random.randint(1, 100)),
                "Bwd IAT Total": float(random.randint(10000, 300000)),
                "Bwd IAT Mean": float(random.randint(2000, 60000)),
                "Bwd IAT Std": float(random.randint(1000, 30000)),
                "Bwd IAT Max": float(random.randint(5000, 100000)),
                "Bwd IAT Min": float(random.randint(1, 100)),
                "Fwd PSH Flags": 0.0,
                "Fwd URG Flags": 0.0,
                "Fwd Header Length": 40.0,
                "Bwd Header Length": 40.0,
                "Bwd Packets/s": float(random.randint(5, 50)),
                "Min Packet Length": 0.0,
                "Max Packet Length": 1460.0,
                "Packet Length Mean": float(random.randint(60, 400)),
                "Packet Length Variance": float(random.randint(1000, 50000)),
                "FIN Flag Count": float(random.choice([0, 1])),
                "RST Flag Count": 0.0,
                "PSH Flag Count": 1.0,
                "ACK Flag Count": 1.0,
                "URG Flag Count": 0.0,
                "Down/Up Ratio": 1.0,
                "Init_Win_bytes_forward": 8192.0,
                "Init_Win_bytes_backward": 8192.0,
                "act_data_pkt_fwd": 2.0,
                "min_seg_size_forward": 20.0,
                "Active Mean": 0.0,
                "Active Std": 0.0,
                "Active Max": 0.0,
                "Active Min": 0.0,
                "Idle Std": 0.0
            }
            
        elif "DoS" in flow_type or flow_type == "DDoS":
            src_ip = random.choice(ATTACK_IPS)
            dst_ip = random.choice(SERVER_IPS)
            dst_port = 80
            src_port = random.randint(1024, 65535)
            protocol = 6
            
            features = {
                "Destination Port": 80.0,
                "Flow Duration": float(random.randint(5000000, 60000000)),
                "Total Fwd Packets": float(random.randint(100, 5000)),
                "Total Length of Fwd Packets": float(random.randint(50000, 500000)),
                "Fwd Packet Length Max": 1460.0,
                "Fwd Packet Length Min": 0.0,
                "Fwd Packet Length Mean": 350.0,
                "Bwd Packet Length Max": 0.0,
                "Bwd Packet Length Min": 0.0,
                "Flow Bytes/s": float(random.randint(100000, 2000000)),
                "Flow Packets/s": float(random.randint(500, 10000)),
                "Flow IAT Mean": float(random.randint(10, 500)),
                "Flow IAT Std": float(random.randint(5, 100)),
                "Flow IAT Max": float(random.randint(100, 2000)),
                "Flow IAT Min": 1.0,
                "Fwd IAT Mean": float(random.randint(10, 500)),
                "Fwd IAT Std": float(random.randint(5, 100)),
                "Fwd IAT Min": 1.0,
                "Bwd IAT Total": 0.0,
                "Bwd IAT Mean": 0.0,
                "Bwd IAT Std": 0.0,
                "Bwd IAT Max": 0.0,
                "Bwd IAT Min": 0.0,
                "Fwd PSH Flags": 1.0,
                "Fwd URG Flags": 0.0,
                "Fwd Header Length": float(random.randint(2000, 100000)),
                "Bwd Header Length": 0.0,
                "Bwd Packets/s": 0.0,
                "Min Packet Length": 0.0,
                "Max Packet Length": 1460.0,
                "Packet Length Mean": 350.0,
                "Packet Length Variance": 120000.0,
                "FIN Flag Count": 0.0,
                "RST Flag Count": float(random.choice([0, 1])),
                "PSH Flag Count": 1.0,
                "ACK Flag Count": 0.0,
                "URG Flag Count": 0.0,
                "Down/Up Ratio": 0.0,
                "Init_Win_bytes_forward": 29200.0,
                "Init_Win_bytes_backward": -1.0,
                "act_data_pkt_fwd": float(random.randint(50, 2000)),
                "min_seg_size_forward": 32.0,
                "Active Mean": 0.0,
                "Active Std": 0.0,
                "Active Max": 0.0,
                "Active Min": 0.0,
                "Idle Std": 0.0
            }
            
        elif flow_type == "PortScan":
            src_ip = random.choice(ATTACK_IPS)
            dst_ip = random.choice(SERVER_IPS)
            dst_port = random.choice([21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 8080])
            src_port = random.randint(40000, 60000)
            protocol = 6
            
            features = {
                "Destination Port": float(dst_port),
                "Flow Duration": float(random.randint(50, 5000)),
                "Total Fwd Packets": 1.0,
                "Total Length of Fwd Packets": 0.0,
                "Fwd Packet Length Max": 0.0,
                "Fwd Packet Length Min": 0.0,
                "Fwd Packet Length Mean": 0.0,
                "Bwd Packet Length Max": 0.0,
                "Bwd Packet Length Min": 0.0,
                "Flow Bytes/s": 0.0,
                "Flow Packets/s": float(random.randint(200, 2000)),
                "Flow IAT Mean": 0.0,
                "Flow IAT Std": 0.0,
                "Flow IAT Max": 0.0,
                "Flow IAT Min": 0.0,
                "Fwd IAT Mean": 0.0,
                "Fwd IAT Std": 0.0,
                "Fwd IAT Min": 0.0,
                "Bwd IAT Total": 0.0,
                "Bwd IAT Mean": 0.0,
                "Bwd IAT Std": 0.0,
                "Bwd IAT Max": 0.0,
                "Bwd IAT Min": 0.0,
                "Fwd PSH Flags": 0.0,
                "Fwd URG Flags": 0.0,
                "Fwd Header Length": 24.0,
                "Bwd Header Length": 0.0,
                "Bwd Packets/s": 0.0,
                "Min Packet Length": 0.0,
                "Max Packet Length": 0.0,
                "Packet Length Mean": 0.0,
                "Packet Length Variance": 0.0,
                "FIN Flag Count": 0.0,
                "RST Flag Count": 1.0,
                "PSH Flag Count": 0.0,
                "ACK Flag Count": 0.0,
                "URG Flag Count": 0.0,
                "Down/Up Ratio": 0.0,
                "Init_Win_bytes_forward": 1024.0,
                "Init_Win_bytes_backward": -1.0,
                "act_data_pkt_fwd": 0.0,
                "min_seg_size_forward": 24.0,
                "Active Mean": 0.0,
                "Active Std": 0.0,
                "Active Max": 0.0,
                "Active Min": 0.0,
                "Idle Std": 0.0
            }
            
        else: # Brute Force
            src_ip = random.choice(ATTACK_IPS)
            dst_ip = random.choice(SERVER_IPS)
            dst_port = 22 if "SSH" in flow_type else 21
            src_port = random.randint(30000, 60000)
            protocol = 6
            
            features = {
                "Destination Port": float(dst_port),
                "Flow Duration": float(random.randint(100000, 2000000)),
                "Total Fwd Packets": float(random.randint(10, 40)),
                "Total Length of Fwd Packets": float(random.randint(500, 3000)),
                "Fwd Packet Length Max": 300.0,
                "Fwd Packet Length Min": 0.0,
                "Fwd Packet Length Mean": 80.0,
                "Bwd Packet Length Max": 500.0,
                "Bwd Packet Length Min": 0.0,
                "Flow Bytes/s": float(random.randint(5000, 25000)),
                "Flow Packets/s": float(random.randint(20, 100)),
                "Flow IAT Mean": float(random.randint(5000, 30000)),
                "Flow IAT Std": float(random.randint(2000, 10000)),
                "Flow IAT Max": float(random.randint(20000, 80000)),
                "Flow IAT Min": 10.0,
                "Fwd IAT Mean": float(random.randint(10000, 50000)),
                "Fwd IAT Std": float(random.randint(5000, 20000)),
                "Fwd IAT Min": 10.0,
                "Bwd IAT Total": float(random.randint(50000, 1500000)),
                "Bwd IAT Mean": float(random.randint(10000, 50000)),
                "Bwd IAT Std": float(random.randint(5000, 20000)),
                "Bwd IAT Max": float(random.randint(20000, 80000)),
                "Bwd IAT Min": 10.0,
                "Fwd PSH Flags": 1.0,
                "Fwd URG Flags": 0.0,
                "Fwd Header Length": 200.0,
                "Bwd Header Length": 200.0,
                "Bwd Packets/s": float(random.randint(10, 50)),
                "Min Packet Length": 0.0,
                "Max Packet Length": 500.0,
                "Packet Length Mean": 90.0,
                "Packet Length Variance": 8000.0,
                "FIN Flag Count": 1.0,
                "RST Flag Count": 0.0,
                "PSH Flag Count": 1.0,
                "ACK Flag Count": 1.0,
                "URG Flag Count": 0.0,
                "Down/Up Ratio": 1.0,
                "Init_Win_bytes_forward": 5840.0,
                "Init_Win_bytes_backward": 5840.0,
                "act_data_pkt_fwd": float(random.randint(5, 20)),
                "min_seg_size_forward": 20.0,
                "Active Mean": 0.0,
                "Active Std": 0.0,
                "Active Max": 0.0,
                "Active Min": 0.0,
                "Idle Std": 0.0
            }

        packet_meta = {
            "timestamp": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP" if protocol == 6 else ("UDP" if protocol == 17 else "ICMP"),
            "flow_duration": features["Flow Duration"],
            "total_packets": features["Total Fwd Packets"],
            "total_bytes": features["Total Length of Fwd Packets"]
        }

        return packet_meta, features
