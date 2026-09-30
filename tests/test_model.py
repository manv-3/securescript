"""
Tests for SecureScript Baseline Machine Learning Model.
"""

import os
import pytest
from securescript.models.baseline import BaselineXSSClassifier, generate_benchmark_dataset


class TestBaselineClassifier:

    @pytest.fixture(scope="class")
    def trained_classifier(self):
        saved_model_path = os.path.join(os.path.dirname(__file__), "..", "data", "baseline_model.joblib")
        clf = BaselineXSSClassifier()
        if os.path.exists(saved_model_path):
            clf.load(saved_model_path)
        else:
            texts, labels = generate_benchmark_dataset()
            clf.train(texts, labels)
        return clf

    def test_benign_prediction(self, trained_classifier):
        """Benign query must be predicted as label 0 with low confidence."""
        label, conf = trained_classifier.predict("standard user profile settings")
        assert label == 0
        assert conf < 0.5

    def test_malicious_prediction(self, trained_classifier):
        """Overt XSS query must be predicted as label 1 with high confidence."""
        label, conf = trained_classifier.predict("<script>alert(1)</script>")
        assert label == 1
        assert conf > 0.5

    def test_mathematical_expression_not_flagged(self, trained_classifier):
        """Mathematical inequality should not be misclassified as malicious."""
        label, conf = trained_classifier.predict("count < 100 and count > 10")
        assert label == 0
