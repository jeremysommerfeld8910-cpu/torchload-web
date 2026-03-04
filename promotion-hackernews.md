# Hacker News Show HN Post
_Copy/paste ready_

## Title:
Show HN: torchload-checker – Scan ML repos for unsafe pickle deserialization (CWE-502)

## URL:
https://github.com/jeremysommerfeld8910-cpu/torchload-checker

## First Comment (post immediately after submission):

torch.load() uses pickle, which can execute arbitrary code. This is well-known in security circles but most ML codebases still haven't migrated.

I built torchload-checker to scan for this and related patterns. It detects 29 types of unsafe deserialization across Python ML frameworks, updated for 2025-2026 CVEs:

- torch.load without weights_only
- pickle/cloudpickle/dill/joblib
- zmq.recv_pyobj (CVE-2025-30165)
- langchain.load serialization injection (CVE-2025-68664)
- keras.load_model safe_mode bypasses (3 CVEs)
- yaml.load without SafeLoader
- numpy.load with allow_pickle
- And more

I scanned 50+ popular repos. Some highlights:
- ray-project/ray: 163 findings
- NVIDIA/TensorRT-LLM: 89 findings (HMAC mitigated)
- huggingface/transformers: 60 findings
- facebookresearch/detectron2: 17 findings with zero mitigations
- 0% false positive rate on 35+ clean repos

PyTorch 2.6+ changed the default to weights_only=True, which is great, but legacy code is everywhere.

The tool outputs SARIF for GitHub Code Scanning integration, has a GitHub Action for CI, and is zero-dependency pure Python. ~500 LOC.

`pip install torchload-checker`

Happy to discuss the technical details of the detection patterns or findings.
