import unittest
from fastapi.testclient import TestClient
from api.main import app

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("system", data)
        self.assertEqual(data["status"], "Operational")

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["features_count"], 47)

    def test_predict_endpoint(self):
        payload = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "features": {
                "Destination Port": 80.0,
                "Flow Duration": 1000.0
            }
        }
        response = self.client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("log_id", data)
        self.assertIn("alert", data)
        self.assertIn("prediction", data)

    def test_statistics_endpoint(self):
        response = self.client.get("/statistics")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_flows", data)
        self.assertIn("malicious_ratio", data)

if __name__ == "__main__":
    unittest.main()
