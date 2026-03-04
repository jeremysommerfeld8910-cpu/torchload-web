# Reddit r/netsec Post
_Copy/paste ready_

## Title:
torchload-checker: CWE-502 scanner for ML/AI codebases — 29 detection patterns, 2025-2026 CVE coverage, SARIF output

## Body:

Released v0.7.0 of torchload-checker, a static analysis tool focused on unsafe deserialization in ML/AI Python codebases. Updated with 5 new CVE-driven detection patterns from 2025-2026 research.

**Problem:** ML frameworks extensively use pickle-based serialization (torch.load, joblib.load, etc.) which allows arbitrary code execution. This is CWE-502, and it's endemic in the ML ecosystem.

**Detection patterns (29 total, including new CVE-driven patterns):**
- torch.load without weights_only=True
- pickle.load/loads, cloudpickle, dill
- joblib.load without trusted sources
- yaml.load without SafeLoader
- numpy.load with allow_pickle=True
- pandas.read_pickle
- tf.keras.models.load_model (safe_mode bypasses — CVE-2025-1550, CVE-2025-8747, CVE-2025-9905)
- zmq.recv_pyobj() — pickle over ZeroMQ (CVE-2025-30165, CVE-2025-23254)
- langchain.load serialization injection (CVE-2025-68664 "LangGrinch")
- langgraph pickle_fallback cache poisoning (CVE-2026-27794)
- pip.main() picklescan bypass (CVE-2025-1716)
- onnx.save_external_data path traversal (CVE-2025-51480)
- __reduce__ deserialization hooks
- exec/eval in model loading contexts (CWE-94)
- shelve.open, marshal.loads
- Custom unpickler subclasses

**Output formats:** JSON, SARIF (integrates with GitHub Code Scanning), human-readable

**Results from scanning major repos (0% false positive rate on 35+ clean repos):**
- ray-project/ray: 163 findings
- NVIDIA/TensorRT-LLM: 89 findings (HMAC mitigated)
- huggingface/transformers: 60 findings
- ModelTC/lightllm: 38 findings (CVE-2026-26220 — unauthenticated pickle.loads on WebSocket, UNFIXED)
- mlflow/mlflow: 27 findings
- detectron2: 17 findings, zero mitigations

**Install:**
```
pip install torchload-checker
```

**CI integration:**
```yaml
- uses: jeremysommerfeld8910-cpu/torchload-checker@v0.7.0
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: torchload-results.sarif
```

Zero dependencies. Pure Python. ~500 LOC.

GitHub: github.com/jeremysommerfeld8910-cpu/torchload-checker
