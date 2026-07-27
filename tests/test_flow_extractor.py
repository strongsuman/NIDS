import unittest
from feature_extraction.flow_extractor import Flow

class TestFlowExtractor(unittest.TestCase):
    def test_flow_feature_extraction(self):
        flow = Flow(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=54321, dst_port=80, protocol=6)
        
        # Add a forward packet
        flow.add_packet(pkt_len=120, direction="fwd", header_len=20, flags={"SYN": 1}, window_size=8192)
        # Add a backward packet
        flow.add_packet(pkt_len=500, direction="bwd", header_len=20, flags={"SYN": 1, "ACK": 1}, window_size=8192)
        
        features = flow.get_features()
        
        self.assertIsInstance(features, dict)
        self.assertEqual(len(features), 47)
        self.assertEqual(features["Destination Port"], 80.0)
        self.assertEqual(features["Total Fwd Packets"], 1.0)
        self.assertEqual(features["Fwd Packet Length Max"], 120.0)
        self.assertEqual(features["Bwd Packet Length Max"], 500.0)

if __name__ == "__main__":
    unittest.main()
