# torchload-web

Web UI and REST API for scanning ML/AI repositories for unsafe deserialization vulnerabilities (CWE-502).

[![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen)](https://github.com/jeremysommerfeld8910-cpu/torchload-web)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CWE-502](https://img.shields.io/badge/CWE--502-29%20patterns-orange)](https://cwe.mitre.org/data/definitions/502.html)
[![FP Rate](https://img.shields.io/badge/false%20positives-0%25-brightgreen)](https://github.com/jeremysommerfeld8910-cpu/torchload-web)

Powered by [torchload-checker](https://github.com/jeremysommerfeld8910-cpu/torchload-checker) — 29 detection patterns covering `torch.load()`, `pickle`, ZeroMQ `recv_pyobj()`, LangChain serialization, Keras safe_mode bypasses, and more. Updated for 2025-2026 CVEs.

## Features

- **Web UI** - Paste a GitHub repo URL and get results instantly
- **REST API** - JSON API for programmatic access
- **29 Detection Patterns** - torch.load, pickle, ZeroMQ recv_pyobj, LangChain load, Keras load_model, cloudpickle, dill, joblib, yaml.load, and more (updated for 2025-2026 CVEs)
- **Mitigation Detection** - Checks for safetensors, weights_only=True, safe_loader usage
- **Severity Ratings** - CRITICAL, HIGH, MEDIUM, LOW with CWE references
- **Result Caching** - 1-hour cache for repeated scans
- **Rate Limiting** - 3 free scans/day
- **OpenAPI Docs** - Interactive API documentation at `/api/docs`
- **Shields.io Badges** - Embed scan results in your README

## Quick Start

```bash
# Clone and run locally
git clone https://github.com/jeremysommerfeld8910-cpu/torchload-web.git
cd torchload-web
pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8100
```

Open http://localhost:8100 in your browser.

## API Usage

### Scan a Repository

```bash
curl -X POST https://your-domain.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "pytorch/pytorch"}'
```

**Response:**
```json
{
  "status": "complete",
  "repo_url": "https://github.com/pytorch/pytorch",
  "total_findings": 31,
  "severity_summary": {"HIGH": 31},
  "findings": [
    {
      "file": "src/model.py",
      "line": 42,
      "pattern": "torch.load(no weights_only)",
      "severity": "HIGH",
      "cwe": "CWE-502"
    }
  ],
  "mitigations": {
    "safetensors": false,
    "weights_only_true": false
  }
}
```

### Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scan` | POST | Scan a GitHub repository |
| `/api/v1/health` | GET | Health check |
| `/api/v1/stats` | GET | Scan statistics |
| `/api/v1/badge/{owner}/{repo}` | GET | Shields.io badge |
| `/api/docs` | GET | Swagger UI documentation |
| `/api/redoc` | GET | ReDoc documentation |

### Add a Badge to Your README

```markdown
![CWE-502](https://your-domain.com/api/v1/badge/owner/repo)
```

## Docker

```bash
docker build -t torchload-web .
docker run -p 8100:8100 torchload-web
```

## Deploy

### Render.com (Free Tier)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

The repo includes a `render.yaml` for one-click deployment.

### Docker (Any Platform)

```bash
docker build -t torchload-web .
docker run -d -p 8100:8100 --name torchload-web torchload-web
```

## Testing

```bash
pip install pytest httpx
pytest test_app.py -v
```

30 tests covering URL validation, rate limiting, API endpoints, CORS, and documentation.

## Detection Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
| `torch.load()` (no weights_only) | HIGH | Arbitrary code execution via pickle |
| `pickle.load()` / `pickle.loads()` | HIGH | Python object deserialization |
| `cloudpickle.load()` | HIGH | Extended pickle with code execution |
| `dill.load()` / `dill.loads()` | HIGH | Full Python object serialization |
| `joblib.load()` | HIGH | Scikit-learn model loading |
| `yaml.load()` (unsafe) | HIGH | YAML deserialization with code execution |
| `shelve.open()` | MEDIUM | Python shelf (pickle-backed) |
| `marshal.loads()` | MEDIUM | Python bytecode deserialization |
| `numpy.load()` (allow_pickle) | MEDIUM | NumPy array loading with pickle |
| `pandas.read_pickle()` | MEDIUM | Pandas pickle deserialization |
| `torch.save()` + `torch.load()` | HIGH | Unsafe save/load cycle |
| `exec()` / `eval()` in model loading | CRITICAL | Direct code execution |
| `__reduce__` methods | HIGH | Custom pickle deserialization hooks |
| `torch.jit.load()` | HIGH | TorchScript models can contain arbitrary Python code |
| `jsonpickle.decode()` | HIGH | JSON-pickle RCE — same risk as pickle |
| `scipy.io.loadmat()` | MEDIUM | Can unpickle object arrays from MATLAB files |
| `pandas.read_msgpack()` | HIGH | Deprecated but dangerous — arbitrary object deserialization |
| `torch.load(weights_only=False)` | CRITICAL | Explicitly disabling safety check |
| `numpy.load(allow_pickle=True)` | MEDIUM | Explicitly enabling pickle in numpy |
| `yaml.load()` (no SafeLoader) | HIGH | YAML deserialization with code execution |
| `safetensors` (mitigation) | INFO | Safe serialization detected |
| `zmq.recv_pyobj()` | HIGH | ZeroMQ pickle deserialization (CVE-2025-30165) |
| `langchain.load()` | HIGH | LangChain serialization injection (CVE-2025-68664) |
| `langgraph pickle_fallback` | MEDIUM | LangGraph cache poisoning (CVE-2026-27794) |
| `pip.main()` | CRITICAL | Picklescan bypass vector (CVE-2025-1716) |
| `onnx.save_external_data()` | MEDIUM | ONNX path traversal (CVE-2025-51480) |
| `keras.load_model()` | HIGH | safe_mode bypasses (CVE-2025-1550/8747/9905) |
| Custom `Unpickler` subclass | HIGH | Custom deserialization with potential backdoors |
| `torch.jit.load()` | HIGH | TorchScript models with embedded Python |

## Real-World Results

Scanned 50+ popular ML/AI repositories. **500+ findings across major repos:**

| Repository | Stars | Findings | Status |
|-----------|-------|----------|--------|
| ray-project/ray | 40K | 163 | Unsafe patterns |
| NVIDIA/TensorRT-LLM | 12K | 89 | HMAC mitigated |
| huggingface/transformers | 148K | 60 | Partial (safetensors) |
| NVIDIA/NeMo | 17K | 53 | Partial |
| ModelTC/lightllm | 3K | 38 | CVE-2026-26220 UNFIXED |
| mlflow/mlflow | 20K | 27 | Partial |
| facebookresearch/detectron2 | 34K | 17 | Zero mitigations |
| keras-team/keras | 65K | 0 | Clean |
| onnx/onnx | 20K | 0 | Clean |

**0% false positive rate** across 35+ clean repos (TensorFlow, scikit-learn, Keras, ONNX, XGBoost, etc.).

## CLI Usage (pip install)

```bash
pip install torchload-checker
torchload-checker /path/to/repo --summary
torchload-checker /path/to/repo --sarif > results.sarif
torchload-checker /path/to/repo --fail-on CRITICAL --exclude-tests
```

## Related

- [torchload-checker](https://github.com/jeremysommerfeld8910-cpu/torchload-checker) - CLI scanner and GitHub Action
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html) - Deserialization of Untrusted Data
- [PyTorch Security Advisory](https://pytorch.org/docs/stable/notes/serialization.html) - Official guidance on torch.load safety

## License

MIT
