"""
SecureScript Model Explainability & Token Attribution Engine.

Uses gradient-based saliency mapping to attribute neural classification confidence
to specific characters and syntax tokens within an inspected payload.
Enables security analysts to understand WHY a payload was flagged as malicious.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch

from securescript.core.normalizer import normalize
from securescript.models.bilstm import BiLSTMClassifier, XSSBiLSTM
from securescript.models.tokenizer import CharTokenizer


@dataclass
class HotspotSpan:
    """A contiguous substring identified as an attack trigger."""
    start: int
    end: int
    substring: str
    attribution_score: float
    description: str


@dataclass
class AttributionResult:
    """Full explainability breakdown for a payload."""
    raw_text: str
    normalized_text: str
    prediction_score: float
    is_malicious: bool
    character_attributions: List[Dict[str, Any]]  # [{"char": "s", "score": 0.85, "index": 0}, ...]
    hotspots: List[HotspotSpan]
    top_trigger_tokens: List[str]


class SaliencyExplainer:
    """
    Computes embedding-level gradient saliency for XSSBiLSTM models.
    """

    def __init__(self, classifier: BiLSTMClassifier):
        self.classifier = classifier
        self.model = classifier.model
        self.tokenizer = classifier.tokenizer
        self.device = classifier.device

    def explain(self, text: str, threshold: float = 0.5) -> AttributionResult:
        """
        Calculates character-level attribution scores for the given payload.
        """
        norm_result = normalize(text)
        normalized = norm_result.normalized

        if not normalized:
            return AttributionResult(
                raw_text=text,
                normalized_text="",
                prediction_score=0.0,
                is_malicious=False,
                character_attributions=[],
                hotspots=[],
                top_trigger_tokens=[]
            )

        # Tokenize
        encoded = self.tokenizer.encode(normalized)
        tensor_in = torch.tensor([encoded], dtype=torch.long, device=self.device)

        self.model.eval()

        # We need gradient of the output with respect to the embedding vectors
        embedding_layer = self.model.embedding
        embeddings = embedding_layer(tensor_in).clone().detach().requires_grad_(True)

        # Forward pass starting from embeddings
        lstm_out, _ = self.model.bilstm(embeddings)
        pooled, _ = torch.max(lstm_out, dim=1)
        dropped = self.model.dropout(pooled)
        dense = self.model.relu(self.model.fc1(dropped))
        out = self.model.sigmoid(self.model.fc2(dense))

        pred_score = float(out.item())
        is_mal = pred_score >= threshold

        # Backward pass to obtain gradient w.r.t embeddings
        self.model.zero_grad()
        out.backward()

        if embeddings.grad is not None:
            # Saliency = L2 norm of gradients along embedding dimension
            grad = embeddings.grad[0].cpu().numpy()  # [seq_len, embedding_dim]
            saliency = np.linalg.norm(grad, axis=1)  # [seq_len]
        else:
            saliency = np.zeros(len(encoded))

        # Truncate saliency to the actual payload length (ignoring trailing padding zeros)
        actual_len = min(len(normalized), self.tokenizer.max_length)
        raw_scores = saliency[:actual_len]

        # Normalize scores to [0.0, 1.0]
        max_val = np.max(raw_scores) if len(raw_scores) > 0 and np.max(raw_scores) > 0 else 1.0
        norm_scores = (raw_scores / max_val).tolist() if len(raw_scores) > 0 else []

        char_attrs: List[Dict[str, Any]] = []
        for i, (ch, sc) in enumerate(zip(normalized[:actual_len], norm_scores)):
            char_attrs.append({
                "index": i,
                "char": ch,
                "score": round(float(sc), 4)
            })

        # Identify contiguous high-attribution hotspots (scores >= 0.4)
        hotspots = self._extract_hotspots(normalized[:actual_len], norm_scores)
        top_tokens = [h.substring for h in hotspots]

        return AttributionResult(
            raw_text=text,
            normalized_text=normalized,
            prediction_score=round(pred_score, 4),
            is_malicious=is_mal,
            character_attributions=char_attrs,
            hotspots=hotspots,
            top_trigger_tokens=top_tokens
        )

    def _extract_hotspots(self, text: str, scores: List[float], cutoff: float = 0.35) -> List[HotspotSpan]:
        """Extracts contiguous spans of high-saliency characters."""
        hotspots: List[HotspotSpan] = []
        in_hotspot = False
        start_idx = 0
        current_scores: List[float] = []

        for i, score in enumerate(scores):
            if score >= cutoff:
                if not in_hotspot:
                    in_hotspot = True
                    start_idx = i
                    current_scores = [score]
                else:
                    current_scores.append(score)
            else:
                if in_hotspot:
                    in_hotspot = False
                    sub = text[start_idx:i]
                    if len(sub.strip()) > 1:
                        avg_sc = float(np.mean(current_scores))
                        desc = self._classify_span(sub)
                        hotspots.append(HotspotSpan(
                            start=start_idx,
                            end=i,
                            substring=sub,
                            attribution_score=round(avg_sc, 4),
                            description=desc
                        ))
                    current_scores = []

        if in_hotspot:
            sub = text[start_idx:len(text)]
            if len(sub.strip()) > 1:
                avg_sc = float(np.mean(current_scores))
                desc = self._classify_span(sub)
                hotspots.append(HotspotSpan(
                    start=start_idx,
                    end=len(text),
                    substring=sub,
                    attribution_score=round(avg_sc, 4),
                    description=desc
                ))

        # Sort hotspots by attribution score descending
        hotspots.sort(key=lambda h: h.attribution_score, reverse=True)
        return hotspots[:5]

    @staticmethod
    def _classify_span(span: str) -> str:
        """Assigns an analytical semantic label to an extracted hotspot span."""
        low = span.lower()
        if "script" in low:
            return "Active Script Tag Context"
        if "onerror" in low or "onload" in low or "onclick" in low:
            return "DOM Event Handler Vector"
        if "javascript:" in low:
            return "Pseudo-Protocol Execution Context"
        if "eval(" in low or "alert(" in low:
            return "Dangerous Execution Sink Invocation"
        if "document." in low or "cookie" in low:
            return "Sensitive DOM Credential Access"
        if "<svg" in low or "<img" in low or "<iframe" in low:
            return "Malicious HTML Element Injection"
        return "High-Saliency Syntactic Anomaly"
