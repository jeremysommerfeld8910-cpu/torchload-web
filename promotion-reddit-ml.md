# Reddit r/MachineLearning Post
_Copy/paste ready — Jeremy just posts this_

## Title:
I built a free scanner that finds unsafe torch.load() in ML repos — found 200+ vulns in major projects [Project]

## Body:

**TL;DR:** `torch.load()` uses pickle under the hood, which can execute arbitrary code. I scanned 50+ popular ML repos and found 200+ unsafe deserialization patterns. Built an open-source scanner with 18 detection patterns.

### What I found:

| Repository | Stars | Unsafe Patterns | Status |
|-----------|-------|----------------|--------|
| NVIDIA/NeMo | 17K | 53 | Partial mitigation |
| huggingface/transformers | 148K | 46 | Partial (safetensors) |
| coqui-ai/TTS | 37K | 31 | No mitigation |
| microsoft/DeepSpeed | 37K | 24 | Partial |
| pytorch/serve | 4K | 20 | **Core handler affected** |
| facebookresearch/detectron2 | 34K | 16 | Zero mitigations |
| pytorch/examples | 23K | 15 | Partial |
| run-llama/llama_index | 47K | 11 | Production pickle.load |
| Lightning-AI/pytorch-lightning | 31K | 10 | Partial |
| comfyanonymous/ComfyUI | 105K | 2 | Mostly migrated |

### The fix is simple:

```python
# UNSAFE (default before PyTorch 2.6)
model = torch.load("model.pt")

# SAFE
model = torch.load("model.pt", weights_only=True)
```

Or use safetensors instead of pickle-based formats.

### The scanner

**torchload-checker** detects 18 patterns including:
- `torch.load()` without `weights_only=True`
- `pickle.load/loads`, `cloudpickle`, `dill`, `joblib.load`
- `yaml.load` without SafeLoader
- `numpy.load(allow_pickle=True)`
- `exec/eval` in model loading contexts
- And more

```bash
pip install torchload-checker
torchload-checker /path/to/your/repo
```

GitHub Action for CI:
```yaml
- uses: jeremysommerfeld8910-cpu/torchload-checker@v0.5.0
  with:
    severity: HIGH
```

**Links:**
- GitHub: github.com/jeremysommerfeld8910-cpu/torchload-checker
- PyPI: `pip install torchload-checker`

This is CWE-502 (Deserialization of Untrusted Data). It's been known for years but the ML community is still catching up. PyTorch 2.6+ changed the default to `weights_only=True`, which helps, but most codebases haven't updated yet.

Happy to answer questions about the findings or methodology.
