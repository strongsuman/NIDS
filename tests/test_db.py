import unittest
from database.db import init_db, insert_log, get_logs, get_statistics

class TestDatabase(unittest.TestCase):
    def test_database_operations(self):
        init_db()
        
        test_alert = {
            "src_ip": "172.16.0.100",
            "dst_ip": "192.168.1.1",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "attack_type": "DoS Hulk",
            "raw_label": "DoS Hulk",
            "severity": "HIGH",
            "confidence": 0.98,
            "is_intrusion": True,
            "flow_duration": 50000.0,
            "total_packets": 100.0,
            "total_bytes": 50000.0
        }
        
        log_id = insert_log(test_alert)
        self.assertIsInstance(log_id, int)
        self.assertGreater(log_id, 0)
        
        logs = get_logs(limit=10)
        self.assertGreater(len(logs), 0)
        
        stats = get_statistics()
        self.assertGreater(stats["total_flows"], 0)
        self.assertIn("DoS Hulk", stats["attack_distribution"])

if __name__ == "__main__":
    unittest.main()
