import time
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional

class Flow:
    """
    Tracks state and calculates flow features for a 5-tuple network flow.
    (src_ip, dst_ip, src_port, dst_port, protocol)
    """
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = time.time()
        self.last_seen = self.start_time
        
        self.fwd_packets = 0
        self.bwd_packets = 0
        
        self.fwd_lengths = []
        self.bwd_lengths = []
        
        self.fwd_iats = []
        self.bwd_iats = []
        self.flow_iats = []
        
        self.fwd_last_pkt_time = None
        self.bwd_last_pkt_time = None
        
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        
        # Flags
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.fwd_psh_flags = 0
        self.fwd_urg_flags = 0
        
        self.init_win_bytes_fwd = 0
        self.init_win_bytes_bwd = 0
        self.act_data_pkt_fwd = 0
        self.min_seg_size_fwd = 0

    def add_packet(self, pkt_len: int, direction: str, header_len: int = 20, flags: Optional[Dict[str, int]] = None, window_size: int = 0):
        current_time = time.time()
        pkt_iat = (current_time - self.last_seen) * 1e6 # microseconds
        
        if len(self.fwd_lengths) + len(self.bwd_lengths) > 0:
            self.flow_iats.append(pkt_iat)
            
        self.last_seen = current_time
        
        if flags:
            self.fin_count += flags.get("FIN", 0)
            self.syn_count += flags.get("SYN", 0)
            self.rst_count += flags.get("RST", 0)
            self.psh_count += flags.get("PSH", 0)
            self.ack_count += flags.get("ACK", 0)
            self.urg_count += flags.get("URG", 0)
            
        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_lengths.append(pkt_len)
            self.fwd_header_len += header_len
            
            if flags and flags.get("PSH", 0):
                self.fwd_psh_flags += 1
            if flags and flags.get("URG", 0):
                self.fwd_urg_flags += 1
                
            if self.fwd_last_pkt_time is not None:
                self.fwd_iats.append((current_time - self.fwd_last_pkt_time) * 1e6)
            self.fwd_last_pkt_time = current_time
            
            if self.fwd_packets == 1:
                self.init_win_bytes_fwd = window_size
                self.min_seg_size_fwd = header_len
            if pkt_len > header_len:
                self.act_data_pkt_fwd += 1
                
        else: # bwd
            self.bwd_packets += 1
            self.bwd_lengths.append(pkt_len)
            self.bwd_header_len += header_len
            
            if self.bwd_last_pkt_time is not None:
                self.bwd_iats.append((current_time - self.bwd_last_pkt_time) * 1e6)
            self.bwd_last_pkt_time = current_time
            
            if self.bwd_packets == 1:
                self.init_win_bytes_bwd = window_size

    def get_features(self) -> Dict[str, float]:
        """
        Extracts 47 CICIDS2017 features matching feature_names.pkl
        """
        duration = max((self.last_seen - self.start_time) * 1e6, 1.0) # microseconds
        
        all_lengths = self.fwd_lengths + self.bwd_lengths
        tot_fwd_len = sum(self.fwd_lengths)
        tot_bwd_len = sum(self.bwd_lengths)
        tot_len = tot_fwd_len + tot_bwd_len
        tot_pkts = self.fwd_packets + self.bwd_packets
        
        flow_bytes_s = (tot_len / (duration / 1e6)) if duration > 0 else 0.0
        flow_pkts_s = (tot_pkts / (duration / 1e6)) if duration > 0 else 0.0
        bwd_pkts_s = (self.bwd_packets / (duration / 1e6)) if duration > 0 else 0.0
        
        fwd_len_max = max(self.fwd_lengths) if self.fwd_lengths else 0.0
        fwd_len_min = min(self.fwd_lengths) if self.fwd_lengths else 0.0
        fwd_len_mean = np.mean(self.fwd_lengths) if self.fwd_lengths else 0.0
        
        bwd_len_max = max(self.bwd_lengths) if self.bwd_lengths else 0.0
        bwd_len_min = min(self.bwd_lengths) if self.bwd_lengths else 0.0
        
        flow_iat_mean = np.mean(self.flow_iats) if self.flow_iats else 0.0
        flow_iat_std = np.std(self.flow_iats) if self.flow_iats else 0.0
        flow_iat_max = max(self.flow_iats) if self.flow_iats else 0.0
        flow_iat_min = min(self.flow_iats) if self.flow_iats else 0.0
        
        fwd_iat_mean = np.mean(self.fwd_iats) if self.fwd_iats else 0.0
        fwd_iat_std = np.std(self.fwd_iats) if self.fwd_iats else 0.0
        fwd_iat_min = min(self.fwd_iats) if self.fwd_iats else 0.0
        
        bwd_iat_tot = sum(self.bwd_iats) if self.bwd_iats else 0.0
        bwd_iat_mean = np.mean(self.bwd_iats) if self.bwd_iats else 0.0
        bwd_iat_std = np.std(self.bwd_iats) if self.bwd_iats else 0.0
        bwd_iat_max = max(self.bwd_iats) if self.bwd_iats else 0.0
        bwd_iat_min = min(self.bwd_iats) if self.bwd_iats else 0.0
        
        pkt_len_min = min(all_lengths) if all_lengths else 0.0
        pkt_len_max = max(all_lengths) if all_lengths else 0.0
        pkt_len_mean = np.mean(all_lengths) if all_lengths else 0.0
        pkt_len_var = np.var(all_lengths) if all_lengths else 0.0
        
        down_up_ratio = (self.bwd_packets / self.fwd_packets) if self.fwd_packets > 0 else 0.0
        
        return {
            "Destination Port": float(self.dst_port),
            "Flow Duration": float(duration),
            "Total Fwd Packets": float(self.fwd_packets),
            "Total Length of Fwd Packets": float(tot_fwd_len),
            "Fwd Packet Length Max": float(fwd_len_max),
            "Fwd Packet Length Min": float(fwd_len_min),
            "Fwd Packet Length Mean": float(fwd_len_mean),
            "Bwd Packet Length Max": float(bwd_len_max),
            "Bwd Packet Length Min": float(bwd_len_min),
            "Flow Bytes/s": float(flow_bytes_s),
            "Flow Packets/s": float(flow_pkts_s),
            "Flow IAT Mean": float(flow_iat_mean),
            "Flow IAT Std": float(flow_iat_std),
            "Flow IAT Max": float(flow_iat_max),
            "Flow IAT Min": float(flow_iat_min),
            "Fwd IAT Mean": float(fwd_iat_mean),
            "Fwd IAT Std": float(fwd_iat_std),
            "Fwd IAT Min": float(fwd_iat_min),
            "Bwd IAT Total": float(bwd_iat_tot),
            "Bwd IAT Mean": float(bwd_iat_mean),
            "Bwd IAT Std": float(bwd_iat_std),
            "Bwd IAT Max": float(bwd_iat_max),
            "Bwd IAT Min": float(bwd_iat_min),
            "Fwd PSH Flags": float(self.fwd_psh_flags),
            "Fwd URG Flags": float(self.fwd_urg_flags),
            "Fwd Header Length": float(self.fwd_header_len),
            "Bwd Header Length": float(self.bwd_header_len),
            "Bwd Packets/s": float(bwd_pkts_s),
            "Min Packet Length": float(pkt_len_min),
            "Max Packet Length": float(pkt_len_max),
            "Packet Length Mean": float(pkt_len_mean),
            "Packet Length Variance": float(pkt_len_var),
            "FIN Flag Count": float(self.fin_count),
            "RST Flag Count": float(self.rst_count),
            "PSH Flag Count": float(self.psh_count),
            "ACK Flag Count": float(self.ack_count),
            "URG Flag Count": float(self.urg_count),
            "Down/Up Ratio": float(down_up_ratio),
            "Init_Win_bytes_forward": float(self.init_win_bytes_fwd),
            "Init_Win_bytes_backward": float(self.init_win_bytes_bwd),
            "act_data_pkt_fwd": float(self.act_data_pkt_fwd),
            "min_seg_size_forward": float(self.min_seg_size_fwd),
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Std": 0.0
        }
