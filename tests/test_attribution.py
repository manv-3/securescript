"""
Unit tests for SecureScript Explainability and Token Attribution Engine.
"""

import os
from securescript.models.bilstm import BiLSTMClassifier
from securescript.models.attribution import SaliencyExplainer


class TestSaliencyExplainer:

    @classmethod
    def setup_class(cls):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        m_path = os.path.join(base_dir, "..", "data", "bilstm_model.pt")
        t_path = os.path.join(base_dir, "..", "data", "tokenizer.json")
        cls.classifier = BiLSTMClassifier()
        cls.classifier.load(m_path, t_path)
        cls.explainer = SaliencyExplainer(cls.classifier)

    def test_explain_malicious_script_payload(self):
        payload = "<script>alert(document.cookie)</script>"
        res = self.explainer.explain(payload)
        assert res.is_malicious is True
        assert res.prediction_score >= 0.85
        assert len(res.character_attributions) > 0
        assert len(res.hotspots) > 0

    def test_explain_benign_text(self):
        text = "Welcome to python programming tutorial"
        res = self.explainer.explain(text)
        assert res.is_malicious is False
        assert res.prediction_score < 0.50

    def test_explain_empty_text(self):
        res = self.explainer.explain("")
        assert res.is_malicious is False
        assert res.prediction_score == 0.0
        assert len(res.hotspots) == 0
