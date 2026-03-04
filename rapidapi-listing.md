# RapidAPI Listing Spec: torchload-checker API

## API Name
ML Security Scanner (torchload-checker)

## Category
Security > Code Analysis

## Description
Scan GitHub repositories for unsafe deserialization vulnerabilities (CWE-502) in ML/AI code. 29 detection patterns covering torch.load(), pickle, cloudpickle, ZeroMQ recv_pyobj, LangChain serialization, Keras safe_mode bypasses, and more. Updated for 2025-2026 CVEs. Returns JSON results with severity, line numbers, and mitigation status. 0% false positive rate on 35+ clean repos.

## Base URL
https://root-independent-eve-shame.trycloudflare.com (temporary, changes on restart)
→ Permanent URL needed: Render.com (render.yaml ready), Railway, or Cloudflare named tunnel
→ BLOCKER: Jeremy needs to create account on one of these platforms

## New Endpoints (v0.7.0)

### GET /api/v1/stats
Public scan statistics (total scans, cache hits, errors).

### GET /api/v1/badge/{owner}/{repo}
Shields.io-compatible JSON badge for repo scan status.

### GET /api/docs
Interactive OpenAPI documentation (Swagger UI).

### GET /api/redoc
Alternative API documentation (ReDoc).

## Endpoints

### POST /api/v1/scan
Scan a GitHub repository for CWE-502 vulnerabilities.

**Request Body:**
```json
{
    "repo_url": "owner/repo"
}
```

**Response (200):**
```json
{
    "status": "complete",
    "repo_url": "https://github.com/owner/repo",
    "scanned_at": "2026-03-02T18:00:00Z",
    "total_findings": 31,
    "severity_summary": {"HIGH": 31},
    "findings": [
        {
            "file": "src/model.py",
            "line": 42,
            "pattern": "torch.load(no weights_only)",
            "code": "model = torch.load(checkpoint_path)",
            "severity": "HIGH",
            "cwe": "CWE-502",
            "description": "torch.load without weights_only parameter..."
        }
    ],
    "mitigations": {
        "safetensors": false,
        "weights_only_true": false,
        "safe_loader": true
    }
}
```

### GET /api/v1/health
Health check endpoint.

## Pricing
- Free: 3 scans/day
- Basic ($9/mo): 50 scans/day
- Pro ($29/mo): Unlimited scans + priority queue
- Enterprise: Contact

## RapidAPI Setup Steps
1. Create RapidAPI Hub account (needs Jeremy)
2. Add API with base URL
3. Define endpoints + test
4. Set pricing tiers
5. Publish to marketplace

## Expected Revenue
$50-200/month after 3 months (based on RapidAPI case studies)
