# torchload-checker v0.5.0 Promotion Plan
_Updated: 2026-03-02. Ready to execute — all drafts written._

## Status: READY FOR JEREMY
All content drafted. Jeremy just needs to copy/paste and post.

## Posts to Make

### 1. dev.to Article — READY
- File: `~/torchload-web/devto-article.md`
- Title: "I Scanned 50+ ML Repos for torch.load() Vulnerabilities — Here's What I Found"
- Tags: machinelearning, security, python, pytorch
- Action: Jeremy publishes via dev.to account

### 2. Reddit r/MachineLearning — READY
- File: `~/torchload-web/promotion-reddit-ml.md`
- Full post with table of findings, code examples, links
- Flair: [Project]

### 3. Reddit r/netsec — READY
- File: `~/torchload-web/promotion-reddit-netsec.md`
- Technical focus: all 18 patterns, SARIF, CI integration
- r/netsec wants quality technical content

### 4. Reddit r/Python — TODO (Jeremy posts)
- Similar to r/ML post but Python-focused
- Emphasize zero-dependency, pure Python, pip install

### 5. Hacker News (Show HN) — READY
- File: `~/torchload-web/promotion-hackernews.md`
- Title + first comment drafted
- Link: GitHub repo

### 6. GitHub Awesome Lists — TODO (needs PRs)
- awesome-python-security
- awesome-machine-learning
- awesome-pytorch
- awesome-static-analysis

### 7. Twitter/X — TODO (needs Jeremy's account)
- Thread: "I scanned 50+ ML repos for unsafe torch.load()..."

## Timing
- All posts within same 24h window for maximum visibility
- Best times: Tuesday-Thursday, 9-11 AM EST
- Target: March 4-5, 2026 (coincides with Intuition contest for visibility)

## Blockers for Jeremy
- [ ] Publish dev.to article
- [ ] Post Reddit threads (3 subreddits)
- [ ] Submit Show HN
- [ ] PyPI account + API token for `twine upload dist/*`
- [ ] Render.com account for permanent URL (render.yaml ready)
- [ ] Awesome list PR submissions

## Product Stats (v0.5.0)
- 18 detection patterns (CWE-502 + CWE-94)
- 200+ findings across 50+ repos
- GitHub Action marketplace-ready
- SARIF output for Code Scanning
- Zero dependencies, pure Python
- 23 tests passing
- Web scanner live (Cloudflare tunnel)
- PyPI package built (dist/torchload_checker-0.5.0-py3-none-any.whl)
