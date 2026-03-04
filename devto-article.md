---
title: "I Scanned 50+ ML Repos for torch.load() Vulnerabilities — Here's What I Found"
published: false
description: "CWE-502 (unsafe deserialization) is everywhere in ML/AI code. I built a free scanner to find it."
tags: machinelearning, security, python, pytorch
---

# I Scanned 50+ ML Repos for torch.load() Vulnerabilities

**TL;DR:** `torch.load()` uses pickle, which can execute arbitrary code. I found 500+ unsafe patterns across major ML projects including Ray, TensorRT-LLM, and TorchServe's core handler. I built a free scanner with 29 detection patterns covering 2025-2026 CVEs — you can use it right now.

## The Problem

Every time your ML code does this:

```python
model = torch.load("model.pt")
```

It's executing **arbitrary Python code** from that file. Not just loading weights — actually running whatever code the file author embedded.

This is [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html). It's been known for years, but the ML community is still catching up.

## What I Found

I scanned 50+ popular ML/AI repositories on GitHub. Results:

| Repository | Stars | Unsafe Patterns | Mitigated? |
|-----------|-------|----------------|------------|
| ray-project/ray | 40K | 163 | **No** |
| NVIDIA/TensorRT-LLM | 12K | 89 | HMAC validated |
| huggingface/transformers | 148K | 60 | Partially (safetensors) |
| NVIDIA/NeMo | 17K | 53 | Partially |
| ModelTC/lightllm | 3K | 38 | **No** (CVE-2026-26220) |
| coqui-ai/TTS | 37K | 31 | **No** |
| mlflow/mlflow | 20K | 27 | Partially |
| facebookresearch/detectron2 | 34K | 17 | **No** |
| pytorch/serve (TorchServe) | 4K | 20 | **No** (core handler!) |
| Lightning-AI/pytorch-lightning | 31K | 10 | Partially |
| keras-team/keras | 65K | 0 | Clean |
| onnx/onnx | 20K | 0 | Clean |

**Total: 500+ unsafe deserialization patterns across major projects.** Ray has 163 patterns with zero mitigation. LightLLM has unauthenticated pickle.loads on WebSocket endpoints (CVE-2026-26220, still unfixed). 0% false positive rate on 35+ clean repos scanned.

## The Fix Is Simple

PyTorch 2.6+ added `weights_only=True`:

```python
# UNSAFE (default before PyTorch 2.6)
model = torch.load("model.pt")

# SAFE
model = torch.load("model.pt", weights_only=True)
```

Or use [safetensors](https://github.com/huggingface/safetensors) instead of pickle-based formats entirely.

## The Scanner

I built **torchload-checker** — a free, open-source scanner that catches:

- `torch.load()` without `weights_only=True`
- `pickle.load()` / `pickle.loads()`
- `cloudpickle`, `dill`, `joblib.load`
- `yaml.load` without SafeLoader
- `numpy.load(allow_pickle=True)`
- `pandas.read_pickle()`
- `tf.keras.models.load_model` (safe_mode bypasses — 3 CVEs in 2025)
- `zmq.recv_pyobj()` (CVE-2025-30165, CVE-2025-23254)
- `langchain.load` serialization injection (CVE-2025-68664)
- `langgraph pickle_fallback` (CVE-2026-27794)
- `pip.main()` picklescan bypass (CVE-2025-1716)
- `onnx.save_external_data` path traversal (CVE-2025-51480)
- `__reduce__` deserialization hooks
- `exec()`/`eval()` in model loading contexts
- And more (29 total)

### Install & Run

```bash
pip install torchload-checker
torchload-checker /path/to/your/repo
```

### GitHub Action (add to your CI)

```yaml
- uses: jeremysommerfeld8910-cpu/torchload-checker@v0.7.0
  with:
    severity: HIGH
    sarif: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: torchload-results.sarif
```

This automatically scans your code on every PR and uploads findings to GitHub's Security tab.

### SARIF Output

```bash
torchload-checker /path/to/repo --sarif > results.sarif
```

Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and any SARIF-compatible tool.

## Key Features

- **29 detection patterns** for unsafe deserialization (updated for 2025-2026 CVEs)
- **Multi-line detection** — catches function calls split across lines
- **Mitigation awareness** — reports when safetensors or weights_only=True are already used
- **Baseline mode** — adopt incrementally without fixing everything at once
- **Zero dependencies** — pure Python, no external packages
- **SARIF output** — integrates with GitHub Code Scanning

## Try It Now

- **Web Scanner**: [torchload-web](https://root-independent-eve-shame.trycloudflare.com) — paste a repo URL, get instant results
- **GitHub**: [jeremysommerfeld8910-cpu/torchload-checker](https://github.com/jeremysommerfeld8910-cpu/torchload-checker)
- **PyPI**: `pip install torchload-checker`
- **GitHub Action**: Add to your workflow in 3 lines
- **API**: `POST /api/v1/scan` with `{"repo_url": "owner/repo"}`

---

*Built by the EPNA security research team. We've reported 20+ CVEs found using this scanner.*
