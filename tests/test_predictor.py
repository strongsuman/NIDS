import unittest
import pandas as pd
from predictor.predict import get_predictor

class TestPredictor(unittest.TestCase):
    def test_predictor_initialization(self):
        predictor = get_predictor()
        self.assertIsNotNone(predictor.model)
        self.assertEqual(len(predictor.feature_names), 47)
        self.assertGreater(len(predictor.label_encoder.classes_), 0)

    def test_predictor_single_sample(self):
        predictor = get_predictor()
        res = predictor.predict_single({})
        self.assertIn("predicted_attack", res)
        self.assertIn("confidence", res)
        self.assertIn("is_intrusion", res)
        self.assertIsInstance(res["confidence"], float)
        self.assertTrue(0.0 <= res["confidence"] <= 1.0)

    def test_predictor_batch(self):
        predictor = get_predictor()
        df = pd.DataFrame([{}, {}])
        results = predictor.predict_batch(df)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIn("predicted_attack", r)

    def test_predictor_explainability(self):
        predictor = get_predictor()
        explanation = predictor.explain_sample({}, top_n=5)
        self.assertIn("predicted_attack", explanation)
        self.assertIn("top_features", explanation)
        self.assertLessEqual(len(explanation["top_features"]), 5)

if __name__ == "__main__":
    unittest.main()
