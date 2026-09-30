"""
SecureScript Model Export and Production Compilation Suite.

Compiles and exports PyTorch XSSBiLSTM models to optimized serialization formats:
- TorchScript (.pt) for high-performance C++ / Python CPU deployments
- Latency profiling and validation against the < 20ms SLA
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import torch

from securescript.models.bilstm import BiLSTMClassifier, XSSBiLSTM


@dataclass
class ExportBenchmark:
    """Benchmark comparing standard PyTorch vs. TorchScript execution."""
    torchscript_path: str
    eager_latency_ms: float
    scripted_latency_ms: float
    speedup_factor: float
    output_consistent: bool


def export_torchscript(
    model_path: str,
    tokenizer_path: str,
    output_path: str,
    seq_length: int = 200
) -> ExportBenchmark:
    """
    Exports a trained XSSBiLSTM model to TorchScript and benchmarks inference speed.
    """
    clf = BiLSTMClassifier(max_length=seq_length)
    clf.load(model_path, tokenizer_path)
    model = clf.model
    model.eval()

    # Dummy tensor for tracing
    dummy_input = torch.zeros((1, seq_length), dtype=torch.long, device=clf.device)

    # 1. Measure Eager Mode Latency
    times_eager = []
    with torch.no_grad():
        for _ in range(50):
            t0 = time.perf_counter()
            _ = model(dummy_input)
            times_eager.append((time.perf_counter() - t0) * 1000.0)
    avg_eager = sum(times_eager[10:]) / len(times_eager[10:])

    # 2. Trace and Save TorchScript Model
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    traced_model = torch.jit.trace(model, dummy_input)
    traced_model.save(output_path)

    # 3. Load Traced Model and Measure Latency
    loaded_scripted = torch.jit.load(output_path, map_location=clf.device)
    loaded_scripted.eval()

    times_scripted = []
    with torch.no_grad():
        for _ in range(50):
            t0 = time.perf_counter()
            _ = loaded_scripted(dummy_input)
            times_scripted.append((time.perf_counter() - t0) * 1000.0)
    avg_scripted = sum(times_scripted[10:]) / len(times_scripted[10:])

    # 4. Consistency Check
    with torch.no_grad():
        eager_out = model(dummy_input).item()
        scripted_out = loaded_scripted(dummy_input).item()
    consistent = abs(eager_out - scripted_out) < 1e-4

    speedup = avg_eager / avg_scripted if avg_scripted > 0 else 1.0

    return ExportBenchmark(
        torchscript_path=output_path,
        eager_latency_ms=round(avg_eager, 3),
        scripted_latency_ms=round(avg_scripted, 3),
        speedup_factor=round(speedup, 2),
        output_consistent=consistent
    )


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    m_path = os.path.join(base_dir, "..", "..", "data", "bilstm_model.pt")
    t_path = os.path.join(base_dir, "..", "..", "data", "tokenizer.json")
    out_path = os.path.join(base_dir, "..", "..", "data", "bilstm_traced.pt")

    print(f"Exporting model from {m_path} to TorchScript...")
    bm = export_torchscript(m_path, t_path, out_path)
    print("\n--- Export Benchmark Results ---")
    print(f"Scripted Model:     {bm.torchscript_path}")
    print(f"Eager Latency:      {bm.eager_latency_ms} ms")
    print(f"TorchScript Lat:    {bm.scripted_latency_ms} ms (Target: < 20.0 ms)")
    print(f"Speedup:            {bm.speedup_factor}x")
    print(f"Consistent Output:  {bm.output_consistent}")
