"""
Unit tests and SLA latency benchmarks for SecureScript PyTorch Bi-LSTM Classifier.
"""

import os
import time
import pytest
import torch

from securescript.models.bilstm import BiLSTMClassifier, XSSBiLSTM, generate_deep_learning_dataset
from securescript.models.tokenizer import CharTokenizer


class TestCharTokenizer:

    def setup_method(self):
        self.tokenizer = CharTokenizer(max_length=50)

    def test_encode_and_decode(self):
        text = "<script>alert(1)</script>"
        encoded = self.tokenizer.encode(text)
        assert len(encoded) == 50
        assert encoded[0] != 0  # Not padding
        decoded = self.tokenizer.decode(encoded)
        assert decoded == text

    def test_save_and_load(self, tmp_path):
        save_file = str(tmp_path / "test_tok.json")
        self.tokenizer.save(save_file)
        new_tok = CharTokenizer(max_length=50)
        new_tok.load(save_file)
        assert new_tok.vocab_size == self.tokenizer.vocab_size


class TestBiLSTMClassifier:

    @pytest.fixture(scope="class")
    def classifier(self):
        model_path = os.path.join(os.path.dirname(__file__), "..", "data", "bilstm_model.pt")
        tok_path = os.path.join(os.path.dirname(__file__), "..", "data", "tokenizer.json")

        clf = BiLSTMClassifier()
        if os.path.exists(model_path) and os.path.exists(tok_path):
            clf.load(model_path, tok_path)
        else:
            texts, labels = generate_deep_learning_dataset()
            clf.train_model(texts[:400], labels[:400], epochs=2, batch_size=32)
        return clf

    def test_model_forward_pass_dimensions(self):
        """Verifies tensor shape [batch, 1] through the neural layers."""
        model = XSSBiLSTM(vocab_size=120, embedding_dim=32, hidden_dim=64)
        dummy_input = torch.randint(0, 100, (4, 50))  # Batch 4, seq_len 50
        output = model(dummy_input)
        assert output.shape == (4, 1)
        assert ((output >= 0.0) & (output <= 1.0)).all()

    def test_predict_malicious_payload(self, classifier):
        """Overt XSS vector is classified with high confidence."""
        label, conf, lat = classifier.predict("<script>alert(1)</script>")
        assert label == 1
        assert conf >= 0.5
        assert lat < 20.0  # Must be faster than 20ms

    def test_predict_benign_text(self, classifier):
        """Benign queries are classified with low confidence."""
        label, conf, lat = classifier.predict("search for books and laptops")
        assert label == 0
        assert conf < 0.5
        assert lat < 20.0

    def test_inference_latency_sla(self, classifier):
        """
        NFR-1 SLA: Deep learning inference overhead must strictly remain < 20ms per sample.
        Evaluated across 50 consecutive CPU queries.
        """
        payloads = [
            "<svg/onload=alert('xss')>",
            "Hello world, standard user input",
            "<iframe src='javascript:alert(1)'>",
            "SELECT * FROM items WHERE price < 100",
            "<img src=x onerror=alert(document.cookie)>"
        ]

        latencies = []
        for _ in range(10):
            for p in payloads:
                _, _, lat = classifier.predict(p)
                latencies.append(lat)

        avg_lat = sum(latencies) / len(latencies)
        max_lat = max(latencies)

        assert avg_lat < 15.0, f"Average latency too high: {avg_lat:.2f} ms"
        assert max_lat < 20.0, f"Peak latency exceeded 20ms SLA: {max_lat:.2f} ms"
