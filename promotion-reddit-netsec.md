# Reddit r/netsec Post
_Copy/paste ready_

## Title:
torchload-checker: CWE-502 scanner for ML/AI codebases — 22 detection patterns, SARIF output, GitHub Action

## Body:

Released v0.5.1 of torchload-checker, a static analysis tool focused on unsafe deserialization in ML/AI Python codebases.

**Problem:** ML frameworks extensively use pickle-based serialization (torch.load, joblib.load, etc.) which allows arbitrary code execution. This is CWE-502, and it's endemic in the ML ecosystem.

**Detection patterns (22 total):**
- torch.load without weights_only=True
- pickle.load/loads, cloudpickle, dill
- joblib.load without trusted sources
- yaml.load without SafeLoader
- numpy.load with allow_pickle=True
- pandas.read_pickle
- tf.keras.models.load_model with custom_objects
- onnx.load with external data
- __reduce__ deserialization hooks
- exec/eval in model loading contexts (CWE-94)
- shelve.open, marshal.loads
- Custom unpickler subclasses

**Output formats:** JSON, SARIF (integrates with GitHub Code Scanning), human-readable

**Results from scanning major repos:**
- transformers: 46 findings (7 critical)
- NeMo: 53 findings
- DeepSpeed: 24 findings (13 critical)
- detectron2: 16 findings, zero mitigations

**Install:**
```
pip install torchload-checker
```

**CI integration:**
```yaml
- uses: jeremysommerfeld8910-cpu/torchload-checker@v0.5.1
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: torchload-results.sarif
```

Zero dependencies. Pure Python. ~500 LOC.

GitHub: github.com/jeremysommerfeld8910-cpu/torchload-checker
