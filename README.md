# SecureScript: Intelligent Real-Time XSS Detection Framework

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green.svg)](https://fastapi.tiangolo.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.x-orange.svg)](https://pytorch.org/)
[![Status](https://img.shields.io/badge/Status-Phase%201%20In%20Progress-yellow.svg)](#)

SecureScript is a multi-tiered, intelligent Cross-Site Scripting (XSS) detection framework that balances sub-millisecond throughput with deep learning accuracy. It couples a fast-path lexical grammar parser (for obvious benign/malicious traffic) with a trained Bidirectional LSTM neural network (for ambiguous, obfuscated, and polyglot payloads) and client-side Content Security Policy (CSP) telemetry.

---

## Key Features

- **Recursive Normalization Engine ($k=4$):** Strips null bytes, unquotes multi-pass URL hex sequences (`%2527` $\rightarrow$ `'`), converts HTML numeric/character entities, extracts Base64 payloads, and decodes Unicode escapes.
- **Fast-Path Lexical State Parser:** Utilizes a Finite-State Automaton (FSM) and lexical tokenization (`libinjection`) to detect context switches (literal data $\rightarrow$ active script execution) in $< 2\,\text{ms}$.
- **Deep Learning Classifier (Bi-LSTM / 1D-CNN):** Evaluates suspicious payloads using character/subword token embeddings in PyTorch to generalize over zero-day mutations ($\ge 98.0\%$ accuracy, $\le 1.5\%$ FPR, $< 20\,\text{ms}$ inference).
- **Asynchronous ASGI Middleware:** Seamlessly drops into FastAPI/Starlette applications to inspect query parameters, request bodies, and headers with configurable actions (`PASS`, `AUDIT`, `BLOCK HTTP 403`).
- **DOM-Based XSS Correlation:** Ingests W3C standard CSP violation reports (`report-to` / `report-uri`) to capture in-browser execution sinks (`innerHTML`, `eval`) invisible at the network perimeter.
- **Real-Time Security Operations Dashboard:** Live analytics for threat volume, token attributions, confidence scores, and CSP alerts.

---

## Architectural Pipeline

```
Incoming HTTP Request
       │
       ▼
[1. Recursive Normalization Engine] ─── (Decodes multi-pass URL, HTML, Base64 up to k=4)
       │
       ▼
[2. Fast-Path Lexer (State Switch?)] ── No ──► PASS (Clean, < 2ms)
       │ Suspicious
       ▼
[3. PyTorch Deep Learning Classifier]
       │
       ├─ Confidence < Threshold ──► PASS / AUDIT
       │
       └─ Confidence >= Threshold ─► BLOCK (HTTP 403) & Trigger Alert
                                           │
                                           ▼
                                [4. SIEM Dashboard & CSP Ingestion]
```

---

## 2-Day Execution Roadmap

| Phase | Timeline | Core Focus | Deliverables |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Day 1** | Deterministic Engine & Proxy Middleware | Normalizer (`normalizer.py`), Lexer (`lexer.py`), FastAPI ASGI Middleware (`middleware.py`), Baseline model |
| **Phase 2** | **Day 2** | Neural Engine, CSP Telemetry & Portal | PyTorch Bi-LSTM (`model.py`), W3C CSP Ingest (`csp_collector.py`), Live Dashboard, Penetration Tests |

---

## Project Structure

```
SecureScript/
├── AGENT.md                 # Operating manual & context guide for AI agents
├── README.md                # Project documentation & usage instructions
├── requirements.txt         # Python dependencies
├── pytest.ini               # Pytest configuration
├── data/
│   ├── raw/                 # Raw security datasets (OWASP, Payload-All-The-Things)
│   └── processed/           # Cleaned and labeled train/val/test datasets
├── securescript/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── normalizer.py    # Recursive multi-pass decoding engine (k=4)
│   │   ├── lexer.py         # Fast-path AST & finite-state token parser
│   │   └── rules.py         # Known dangerous execution sink & token rules
│   ├── models/
│   │   ├── __init__.py
│   │   ├── dataset.py       # PyTorch Dataset & DataLoader
│   │   ├── tokenizer.py     # Subword / character tokenizer
│   │   └── bilstm.py        # PyTorch Bi-LSTM classifier
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── asgi.py          # Asynchronous FastAPI/Starlette proxy middleware
│   ├── telemetry/
│   │   ├── __init__.py
│   │   └── csp.py           # W3C CSP violation collector & correlator
│   └── dashboard/
│       ├── app.py           # Real-time monitoring console
│       └── static/          # UI assets and styles
└── tests/
    ├── test_normalizer.py   # Unit tests for multi-layer unquoting & de-obfuscation
    ├── test_lexer.py        # Unit tests for fast-path lexical transitions
    ├── test_middleware.py   # Integration tests for HTTP 403 blocking & pass
    └── test_model.py        # Tests for PyTorch inference and tokenization
```

---

## Quick Start & Installation

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/your-org/SecureScript.git
cd SecureScript
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
pytest tests/ -v
```

### 3. Launch Interception Proxy & Demo Server
```bash
python -m uvicorn securescript.middleware.asgi:demo_app --reload --port 8000
```

---

## Technical Specifications & SLAs

| Evaluation Metric | Target SLA | Implementation Component |
| :--- | :--- | :--- |
| **Fast-Path Latency** | $< 2\,\text{ms}$ per request | `securescript.core.lexer` |
| **DL Inference Latency** | $< 20\,\text{ms}$ per request | `securescript.models.bilstm` (TorchScript / ONNX) |
| **Detection Accuracy** | $\ge 98.0\%$ | PyTorch Bi-LSTM Model |
| **False Positive Rate** | $\le 1.5\%$ | Hybrid Fast-Path + DL Filter |
| **Recursion Depth** | Fixed $k = 4$ | `securescript.core.normalizer` |

---

## License & Attribution
Developed for the **HCL Internship Program** (September 2026).  
Based on research specifications in *SecureScript: An Intelligent Real-Time Cross-Site Scripting (XSS) Detection Framework Using Hybrid Lexical Analysis and Deep Learning*.
