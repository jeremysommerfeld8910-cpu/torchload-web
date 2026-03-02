# Hacker News Show HN Post
_Copy/paste ready_

## Title:
Show HN: torchload-checker – Scan ML repos for unsafe pickle deserialization (CWE-502)

## URL:
https://github.com/jeremysommerfeld8910-cpu/torchload-checker

## First Comment (post immediately after submission):

torch.load() uses pickle, which can execute arbitrary code. This is well-known in security circles but most ML codebases still haven't migrated.

I built torchload-checker to scan for this and related patterns. It detects 18 types of unsafe deserialization across Python ML frameworks:

- torch.load without weights_only
- pickle/cloudpickle/dill/joblib
- yaml.load without SafeLoader
- numpy.load with allow_pickle
- exec/eval in model loading
- And more

I scanned 50+ popular repos. Some highlights:
- huggingface/transformers: 46 findings
- NVIDIA/NeMo: 53 findings
- facebookresearch/detectron2: 16 findings with zero mitigations

PyTorch 2.6+ changed the default to weights_only=True, which is great, but legacy code is everywhere.

The tool outputs SARIF for GitHub Code Scanning integration, has a GitHub Action for CI, and is zero-dependency pure Python. ~500 LOC.

`pip install torchload-checker`

Happy to discuss the technical details of the detection patterns or findings.
