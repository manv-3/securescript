"""
Integration tests for SecureScript Adversarial and Evasion Benchmark Suite.
"""

from securescript.core.adversarial import AdversarialEvaluator


class TestAdversarialBenchmark:

    @classmethod
    def setup_class(cls):
        cls.evaluator = AdversarialEvaluator()

    def test_adversarial_detection_rate_meets_sla(self):
        """Validates that attack detection rate (recall) >= 98.0%."""
        results = self.evaluator.run_benchmark()
        assert results.attack_detection_rate >= 98.0
        assert results.attacks_blocked >= 30

    def test_benign_false_positive_rate_meets_sla(self):
        """Validates that false positive rate <= 1.5%."""
        results = self.evaluator.run_benchmark()
        assert results.false_positive_rate <= 1.5
        assert results.benign_passed >= 16

    def test_pipeline_latency_meets_sla(self):
        """Validates that average hybrid pipeline latency is well below 20ms."""
        results = self.evaluator.run_benchmark()
        assert results.avg_pipeline_latency_ms < 10.0
