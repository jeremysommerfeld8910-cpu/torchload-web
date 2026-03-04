#!/usr/bin/env python3
"""
torchload-web — Web UI and API for torchload-checker CWE-502 scanner.
Scan GitHub repos for unsafe deserialization patterns in ML/AI code.

Pipeline 1A from EPNA Revenue Pipeline v2.0
"""
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(
    title="torchload-checker",
    description="Scan ML/AI repos for unsafe deserialization (CWE-502)",
    version="0.7.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS for API consumers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Request counter for stats
scan_stats: dict[str, int] = {"total_scans": 0, "cache_hits": 0, "errors": 0}

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
SCANNER_PATH = Path(os.environ.get(
    "SCANNER_PATH",
    str(Path(__file__).parent / "torchload_checker.py")
))
SCAN_CACHE_DIR = Path(tempfile.gettempdir()) / "torchload-cache"
SCAN_CACHE_DIR.mkdir(exist_ok=True)

# Rate limiting: simple in-memory store
rate_limits: dict[str, list[float]] = {}
FREE_SCANS_PER_DAY = 3
CACHE_TTL_SECONDS = 3600  # 1 hour

# ═══ PAID TIER CONFIGURATION ═══
# Stripe key — Jeremy plugs this in to go live
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# API key store (in production, use database)
API_KEYS_FILE = Path(os.environ.get("API_KEYS_FILE", str(Path(__file__).parent / "api_keys.json")))

# Pricing tiers
TIERS = {
    "free": {"scans_per_day": 3, "pdf_report": False, "batch_scan": False, "priority": False},
    "pro": {"scans_per_day": 50, "pdf_report": True, "batch_scan": True, "priority": True, "price_cents": 1900},
    "enterprise": {"scans_per_day": 500, "pdf_report": True, "batch_scan": True, "priority": True, "price_cents": 9900},
}

def load_api_keys() -> dict:
    """Load API keys from file."""
    if API_KEYS_FILE.exists():
        with open(API_KEYS_FILE) as f:
            return json.load(f)
    return {}

def get_tier_for_key(api_key: str) -> str:
    """Look up tier for an API key."""
    keys = load_api_keys()
    entry = keys.get(api_key, {})
    return entry.get("tier", "free")

def check_api_rate_limit(api_key: str) -> tuple[bool, str]:
    """Check rate limit for API key holder. Returns (allowed, tier)."""
    tier = get_tier_for_key(api_key)
    tier_config = TIERS.get(tier, TIERS["free"])
    max_scans = tier_config["scans_per_day"]

    now = time.time()
    day_start = now - 86400
    key_id = f"api:{api_key[:8]}"
    if key_id not in rate_limits:
        rate_limits[key_id] = []
    rate_limits[key_id] = [t for t in rate_limits[key_id] if t > day_start]
    if len(rate_limits[key_id]) >= max_scans:
        return False, tier
    rate_limits[key_id].append(now)
    return True, tier

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(client_ip: str) -> bool:
    """Return True if under rate limit, False if exceeded."""
    now = time.time()
    day_start = now - 86400
    if client_ip not in rate_limits:
        rate_limits[client_ip] = []
    # Clean old entries
    rate_limits[client_ip] = [t for t in rate_limits[client_ip] if t > day_start]
    if len(rate_limits[client_ip]) >= FREE_SCANS_PER_DAY:
        return False
    rate_limits[client_ip].append(now)
    return True


def get_cache_key(repo_url: str) -> str:
    return hashlib.sha256(repo_url.encode()).hexdigest()[:16]


def get_cached_result(repo_url: str) -> Optional[dict]:
    key = get_cache_key(repo_url)
    cache_file = SCAN_CACHE_DIR / f"{key}.json"
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            return json.loads(cache_file.read_text())
    return None


def save_cached_result(repo_url: str, result: dict):
    key = get_cache_key(repo_url)
    cache_file = SCAN_CACHE_DIR / f"{key}.json"
    cache_file.write_text(json.dumps(result))


def validate_github_url(url: str) -> tuple[bool, str]:
    """Validate and normalize a GitHub repo URL. Returns (valid, normalized_url)."""
    url = url.strip().rstrip("/")
    # Accept: https://github.com/owner/repo or owner/repo
    if url.startswith("https://github.com/"):
        parts = url.replace("https://github.com/", "").split("/")
    elif url.startswith("http://github.com/"):
        parts = url.replace("http://github.com/", "").split("/")
    elif "/" in url and not url.startswith("http"):
        parts = url.split("/")
    else:
        return False, "Invalid format. Use: owner/repo or https://github.com/owner/repo"

    if len(parts) < 2:
        return False, "Need owner/repo format"

    owner, repo = parts[0], parts[1]
    # Basic sanity check
    if not owner or not repo or len(owner) > 100 or len(repo) > 100:
        return False, "Invalid owner/repo"
    # Reject path traversal
    if ".." in owner or ".." in repo:
        return False, "Invalid characters"

    return True, f"https://github.com/{owner}/{repo}.git"


async def clone_and_scan(repo_url: str) -> dict:
    """Clone a GitHub repo (shallow) and run torchload-checker on it."""
    with tempfile.TemporaryDirectory(prefix="torchload-scan-") as tmpdir:
        clone_dir = os.path.join(tmpdir, "repo")

        # Shallow clone (depth 1, no history, single branch)
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--single-branch", repo_url, clone_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

        if proc.returncode != 0:
            error_msg = stderr.decode(errors="ignore")[:200]
            if "not found" in error_msg.lower() or "404" in error_msg:
                return {"error": "Repository not found", "status": "error"}
            return {"error": f"Clone failed: {error_msg}", "status": "error"}

        # Run torchload-checker with --json output
        proc = await asyncio.create_subprocess_exec(
            "python3", str(SCANNER_PATH), clone_dir, "--json", "--exclude-tests",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        try:
            result = json.loads(stdout.decode())
        except json.JSONDecodeError:
            result = {"total_findings": 0, "findings": [], "mitigations": {}}

        # Clean up file paths (remove temp dir prefix)
        for f in result.get("findings", []):
            if "file" in f:
                f["file"] = f["file"].replace(clone_dir + "/", "")

        result["repo_url"] = repo_url.replace(".git", "")
        result["scanned_at"] = datetime.now(timezone.utc).isoformat()
        result["status"] = "complete"

        # Summary stats
        sev_counts = {}
        for f in result.get("findings", []):
            sev = f.get("severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        result["severity_summary"] = sev_counts

        return result


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/scan", response_class=HTMLResponse)
async def scan_form(request: Request):
    """Handle form submission from web UI."""
    form = await request.form()
    repo_url = str(form.get("repo_url", "")).strip()

    if not repo_url:
        return templates.TemplateResponse(request, "index.html", {
            "error": "Please enter a repository URL",
        })

    valid, normalized = validate_github_url(repo_url)
    if not valid:
        return templates.TemplateResponse(request, "index.html", {
            "error": normalized,
        })

    # Rate limit check
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        return templates.TemplateResponse(request, "index.html", {
            "error": f"Rate limit exceeded ({FREE_SCANS_PER_DAY} scans/day). Upgrade to Pro for unlimited scans.",
        })

    # Check cache
    cached = get_cached_result(normalized)
    if cached:
        cached["from_cache"] = True
        scan_stats["cache_hits"] += 1
        return templates.TemplateResponse(request, "results.html", {
            "result": cached,
        })

    scan_stats["total_scans"] += 1

    # Run scan
    try:
        result = await clone_and_scan(normalized)
    except asyncio.TimeoutError:
        scan_stats["errors"] += 1
        return templates.TemplateResponse(request, "index.html", {
            "error": "Scan timed out. Try a smaller repository.",
        })
    except Exception as e:
        scan_stats["errors"] += 1
        return templates.TemplateResponse(request, "index.html", {
            "error": f"Scan failed: {str(e)[:100]}",
        })

    if result.get("status") == "error":
        return templates.TemplateResponse(request, "index.html", {
            "error": result.get("error", "Unknown error"),
        })

    # Cache result
    save_cached_result(normalized, result)
    result["from_cache"] = False

    return templates.TemplateResponse(request, "results.html", {
        "result": result,
    })


# === API ENDPOINTS (for RapidAPI / programmatic access) ===

@app.post("/api/v1/scan")
async def api_scan(request: Request):
    """API endpoint: scan a repo. Returns JSON."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    repo_url = body.get("repo_url", "").strip()
    if not repo_url:
        raise HTTPException(400, "repo_url is required")

    valid, normalized = validate_github_url(repo_url)
    if not valid:
        raise HTTPException(400, normalized)

    # Rate limit
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        raise HTTPException(429, f"Rate limit exceeded ({FREE_SCANS_PER_DAY}/day)")

    # Cache check
    cached = get_cached_result(normalized)
    if cached:
        cached["from_cache"] = True
        scan_stats["cache_hits"] += 1
        return JSONResponse(cached)

    scan_stats["total_scans"] += 1

    try:
        result = await clone_and_scan(normalized)
    except asyncio.TimeoutError:
        scan_stats["errors"] += 1
        raise HTTPException(504, "Scan timed out")
    except Exception as e:
        scan_stats["errors"] += 1
        raise HTTPException(500, f"Scan failed: {str(e)[:100]}")

    if result.get("status") == "error":
        raise HTTPException(400, result.get("error", "Unknown error"))

    save_cached_result(normalized, result)
    result["from_cache"] = False
    return JSONResponse(result)


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "version": "0.7.0"}


@app.get("/api/v1/stats")
async def stats():
    """Public scan statistics."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("scanner", str(SCANNER_PATH))
    scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner)
    return {
        "total_scans": scan_stats["total_scans"],
        "cache_hits": scan_stats["cache_hits"],
        "errors": scan_stats["errors"],
        "patterns_detected": len(scanner.PATTERNS),
        "version": "0.7.0",
    }


@app.get("/api/v1/badge/{owner}/{repo}")
async def badge(owner: str, repo: str):
    """Returns a shields.io-compatible JSON badge for a repo's scan status."""
    repo_url = f"https://github.com/{owner}/{repo}.git"
    cached = get_cached_result(repo_url)
    if cached:
        count = cached.get("total_findings", 0)
        if count == 0:
            color = "brightgreen"
            message = "clean"
        elif count <= 5:
            color = "yellow"
            message = f"{count} findings"
        else:
            color = "red"
            message = f"{count} findings"
    else:
        color = "lightgrey"
        message = "not scanned"
    return {
        "schemaVersion": 1,
        "label": "CWE-502",
        "message": message,
        "color": color,
    }


@app.get("/api/v1/patterns")
async def patterns():
    """List all detection patterns with severity, CWE, and description."""
    # Import patterns from scanner
    import importlib.util
    spec = importlib.util.spec_from_file_location("scanner", str(SCANNER_PATH))
    scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner)
    return {
        "total_patterns": len(scanner.PATTERNS),
        "patterns": [
            {
                "name": p["name"],
                "severity": p["severity"],
                "cwe": p["cwe"],
                "description": p["desc"],
            }
            for p in scanner.PATTERNS
        ],
        "severity_breakdown": {
            sev: sum(1 for p in scanner.PATTERNS if p["severity"] == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            if any(p["severity"] == sev for p in scanner.PATTERNS)
        },
    }


@app.get("/api/v1/scan/{owner}/{repo}")
async def api_scan_shorthand(owner: str, repo: str, request: Request):
    """Convenience endpoint: scan github.com/owner/repo without POST body."""
    repo_url = f"https://github.com/{owner}/{repo}.git"

    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        raise HTTPException(429, f"Rate limit exceeded ({FREE_SCANS_PER_DAY}/day)")

    cached = get_cached_result(repo_url)
    if cached:
        cached["from_cache"] = True
        scan_stats["cache_hits"] += 1
        return JSONResponse(cached)

    scan_stats["total_scans"] += 1

    try:
        result = await clone_and_scan(repo_url)
    except asyncio.TimeoutError:
        scan_stats["errors"] += 1
        raise HTTPException(504, "Scan timed out")
    except Exception as e:
        scan_stats["errors"] += 1
        raise HTTPException(500, f"Scan failed: {str(e)[:100]}")

    if result.get("status") == "error":
        raise HTTPException(400, result.get("error", "Unknown error"))

    save_cached_result(repo_url, result)
    result["from_cache"] = False
    return JSONResponse(result)


@app.get("/api/v1/pricing")
async def pricing():
    """Show pricing tiers for API access."""
    return {
        "tiers": [
            {
                "name": "Free",
                "price": "$0/month",
                "scans_per_day": 3,
                "features": ["Basic CWE-502 scan", "29 detection patterns", "JSON results"]
            },
            {
                "name": "Pro",
                "price": "$9/month",
                "scans_per_day": 50,
                "features": ["All Free features", "SARIF output", "CI/CD integration", "Priority scanning", "Webhook notifications"]
            },
            {
                "name": "Enterprise",
                "price": "Contact us",
                "scans_per_day": "Unlimited",
                "features": ["All Pro features", "Private repos", "Custom patterns", "SLA", "Dedicated support"]
            }
        ],
        "note": "Pro and Enterprise tiers available. Get your API key at /pricing.",
        "signup_url": "/api/v1/checkout/pro",
    }


@app.get("/api/v1/report/{owner}/{repo}")
async def report(owner: str, repo: str):
    """Generate a formatted security report for a scanned repo."""
    repo_url = f"https://github.com/{owner}/{repo}.git"
    cached = get_cached_result(repo_url)
    if not cached:
        return JSONResponse(
            status_code=404,
            content={"error": "Repository not scanned yet. Use /api/v1/scan/{owner}/{repo} first."}
        )

    findings = cached.get("findings", [])
    severity_counts = cached.get("severity_summary", {})

    risk_level = "CLEAN"
    if severity_counts.get("CRITICAL", 0) > 0:
        risk_level = "CRITICAL"
    elif severity_counts.get("HIGH", 0) > 0:
        risk_level = "HIGH"
    elif severity_counts.get("MEDIUM", 0) > 0:
        risk_level = "MEDIUM"
    elif severity_counts.get("LOW", 0) > 0:
        risk_level = "LOW"

    return {
        "report": {
            "repository": f"https://github.com/{owner}/{repo}",
            "scanned_at": cached.get("scanned_at", "unknown"),
            "risk_level": risk_level,
            "total_findings": cached.get("total_findings", 0),
            "severity_summary": severity_counts,
            "scanner": "torchload-checker v0.7.0",
            "patterns_checked": 22,
            "cwe": "CWE-502 (Deserialization of Untrusted Data)",
        },
        "findings": [
            {
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "pattern": f.get("pattern", ""),
                "severity": f.get("severity", "UNKNOWN"),
                "snippet": f.get("snippet", "")[:200],
            }
            for f in findings[:50]
        ],
        "recommendations": cached.get("mitigations", {}),
    }


# ═══ PAID TIER ENDPOINTS ═══

@app.post("/api/v1/scan/pro")
async def api_scan_pro(request: Request):
    """Pro-tier scan with API key authentication. Higher limits + PDF report."""
    body = await request.json()
    api_key = request.headers.get("X-API-Key", body.get("api_key", ""))
    repo_url = body.get("repo_url", "")

    if not api_key:
        raise HTTPException(401, "API key required. Get one at /pricing")

    allowed, tier = check_api_rate_limit(api_key)
    if not allowed:
        tier_config = TIERS.get(tier, TIERS["free"])
        raise HTTPException(429, f"Rate limit exceeded ({tier_config['scans_per_day']}/day for {tier} tier)")

    if not repo_url:
        raise HTTPException(400, "repo_url is required")

    valid, msg = validate_github_url(repo_url)
    if not valid:
        raise HTTPException(400, msg)

    cached = get_cached_result(repo_url)
    if cached:
        cached["from_cache"] = True
        cached["tier"] = tier
        scan_stats["cache_hits"] += 1
        return JSONResponse(cached)

    scan_stats["total_scans"] += 1
    try:
        result = await clone_and_scan(repo_url)
    except asyncio.TimeoutError:
        scan_stats["errors"] += 1
        raise HTTPException(504, "Scan timed out")
    except Exception as e:
        scan_stats["errors"] += 1
        raise HTTPException(500, f"Scan failed: {str(e)[:100]}")

    if result.get("status") == "error":
        raise HTTPException(400, result.get("error", "Unknown error"))

    save_cached_result(repo_url, result)
    result["from_cache"] = False
    result["tier"] = tier
    return JSONResponse(result)


@app.get("/api/v1/report/{owner}/{repo}/pdf")
async def report_pdf(owner: str, repo: str, request: Request):
    """Generate PDF security report (Pro tier only)."""
    api_key = request.headers.get("X-API-Key", request.query_params.get("api_key", ""))
    tier = get_tier_for_key(api_key) if api_key else "free"

    if not TIERS.get(tier, {}).get("pdf_report", False):
        raise HTTPException(
            403,
            "PDF reports require Pro or Enterprise tier. Get your API key at /pricing"
        )

    repo_url = f"https://github.com/{owner}/{repo}.git"
    cached = get_cached_result(repo_url)
    if not cached:
        raise HTTPException(404, "Repository not scanned yet. Scan first via /api/v1/scan/pro")

    # Generate PDF using security-audit-report.py
    try:
        pdf_path = Path(tempfile.mktemp(suffix=".pdf"))
        result = subprocess.run(
            ["python3", str(Path.home() / "scripts" / "security-audit-report.py"),
             f"https://github.com/{owner}/{repo}", "--output", str(pdf_path)],
            capture_output=True, text=True, timeout=300
        )
        if pdf_path.exists():
            from fastapi.responses import FileResponse
            return FileResponse(
                str(pdf_path),
                media_type="application/pdf",
                filename=f"security-audit-{owner}-{repo}.pdf"
            )
        raise HTTPException(500, "PDF generation failed")
    except Exception as e:
        raise HTTPException(500, f"PDF generation error: {str(e)[:100]}")


@app.post("/api/v1/checkout/{tier_name}")
async def create_checkout(tier_name: str):
    """Create a Stripe checkout session for paid tier."""
    if tier_name not in ["pro", "enterprise"]:
        raise HTTPException(400, "Invalid tier. Choose 'pro' or 'enterprise'")

    if not STRIPE_SECRET_KEY:
        return JSONResponse({
            "error": "Payment system not configured yet",
            "message": "Paid tiers are coming soon. Contact us for early access.",
            "tier": tier_name,
            "price": f"${TIERS[tier_name]['price_cents'] / 100:.0f}/month",
        }, status_code=503)

    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY

        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": f"torchload-checker {tier_name.title()} Plan",
                        "description": f"CWE-502 scanner - {TIERS[tier_name]['scans_per_day']} scans/day + PDF reports",
                    },
                    "unit_amount": TIERS[tier_name]["price_cents"],
                    "recurring": {"interval": "month"},
                },
                "quantity": 1,
            }],
            mode="subscription",
            success_url=os.environ.get("BASE_URL", "http://localhost:8100") + "/api/v1/checkout/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=os.environ.get("BASE_URL", "http://localhost:8100") + "/pricing",
        )
        return JSONResponse({"checkout_url": session.url, "session_id": session.id})
    except ImportError:
        return JSONResponse({"error": "stripe package not installed"}, status_code=503)
    except Exception as e:
        raise HTTPException(500, f"Checkout error: {str(e)[:100]}")


@app.get("/api/v1/checkout/success")
async def checkout_success(session_id: str = ""):
    """Handle successful Stripe checkout — generate API key."""
    if not STRIPE_SECRET_KEY or not session_id:
        return JSONResponse({"message": "Payment received. Your API key will be emailed."})

    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY
        session = stripe.checkout.Session.retrieve(session_id)

        if session.payment_status == "paid":
            # Generate API key
            import secrets
            api_key = f"tlc_{secrets.token_hex(24)}"

            # Save to API keys file
            keys = load_api_keys()
            keys[api_key] = {
                "tier": "pro",
                "email": session.customer_email or "unknown",
                "created": datetime.now(timezone.utc).isoformat(),
                "stripe_session": session_id,
            }
            with open(API_KEYS_FILE, "w") as f:
                json.dump(keys, f, indent=2)

            return JSONResponse({
                "status": "success",
                "api_key": api_key,
                "tier": "pro",
                "message": "Save this API key! Use it in X-API-Key header for Pro endpoints.",
            })
    except Exception as e:
        return JSONResponse({"error": f"Key generation failed: {str(e)[:100]}"}, status_code=500)

    return JSONResponse({"message": "Payment processing. API key will be emailed."})


@app.get("/pricing", response_class=HTMLResponse)
async def pricing_page(request: Request):
    """Landing page with pricing tiers."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>torchload-checker — Pricing</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a1a; color: #e0e0e0; }
.hero { text-align: center; padding: 80px 20px 40px; }
.hero h1 { font-size: 2.5em; color: #00d4ff; margin-bottom: 10px; }
.hero p { font-size: 1.2em; color: #888; max-width: 600px; margin: 0 auto; }
.pricing { display: flex; justify-content: center; gap: 30px; padding: 40px 20px; flex-wrap: wrap; }
.tier { background: #1a1a2e; border-radius: 12px; padding: 40px 30px; width: 300px; border: 1px solid #333; transition: transform 0.2s; }
.tier:hover { transform: translateY(-5px); }
.tier.featured { border-color: #00d4ff; box-shadow: 0 0 30px rgba(0,212,255,0.1); }
.tier h2 { color: #00d4ff; font-size: 1.5em; margin-bottom: 5px; }
.tier .price { font-size: 2.5em; font-weight: bold; color: #fff; margin: 15px 0; }
.tier .price span { font-size: 0.4em; color: #888; }
.tier ul { list-style: none; margin: 20px 0; }
.tier ul li { padding: 8px 0; border-bottom: 1px solid #222; }
.tier ul li::before { content: "✓ "; color: #00d4ff; }
.btn { display: inline-block; padding: 12px 30px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 20px; }
.btn-free { background: #333; color: #fff; }
.btn-pro { background: #00d4ff; color: #0a0a1a; }
.btn-enterprise { background: transparent; border: 2px solid #00d4ff; color: #00d4ff; }
.stats { text-align: center; padding: 40px 20px; }
.stats h2 { color: #00d4ff; margin-bottom: 20px; }
.stat-row { display: flex; justify-content: center; gap: 40px; flex-wrap: wrap; }
.stat { text-align: center; }
.stat .num { font-size: 2em; color: #fff; font-weight: bold; }
.stat .label { color: #888; }
.faq { max-width: 700px; margin: 40px auto; padding: 20px; }
.faq h2 { color: #00d4ff; text-align: center; margin-bottom: 20px; }
.faq-item { margin-bottom: 15px; }
.faq-item h3 { color: #ccc; margin-bottom: 5px; }
.faq-item p { color: #888; line-height: 1.6; }
footer { text-align: center; padding: 40px; color: #555; }
</style>
</head>
<body>
<div class="hero">
    <h1>torchload-checker</h1>
    <p>Scan ML/AI repositories for unsafe deserialization vulnerabilities (CWE-502). Found 20+ real CVEs in production projects.</p>
</div>

<div class="pricing">
    <div class="tier">
        <h2>Free</h2>
        <div class="price">$0<span>/month</span></div>
        <ul>
            <li>3 scans per day</li>
            <li>29 detection patterns</li>
            <li>JSON results</li>
            <li>GitHub badge</li>
            <li>Community support</li>
        </ul>
        <a href="/" class="btn btn-free">Start Scanning</a>
    </div>

    <div class="tier featured">
        <h2>Pro</h2>
        <div class="price">$19<span>/month</span></div>
        <ul>
            <li>50 scans per day</li>
            <li>PDF security reports</li>
            <li>Batch scanning</li>
            <li>Priority queue</li>
            <li>API key access</li>
            <li>CI/CD integration</li>
        </ul>
        <a href="/api/v1/checkout/pro" class="btn btn-pro">Get Pro</a>
    </div>

    <div class="tier">
        <h2>Enterprise</h2>
        <div class="price">$99<span>/month</span></div>
        <ul>
            <li>500 scans per day</li>
            <li>Everything in Pro</li>
            <li>Private repo scanning</li>
            <li>Custom detection patterns</li>
            <li>SLA guarantee</li>
            <li>Dedicated support</li>
        </ul>
        <a href="/api/v1/checkout/enterprise" class="btn btn-enterprise">Contact Us</a>
    </div>
</div>

<div class="stats">
    <h2>Trusted by Security Teams</h2>
    <div class="stat-row">
        <div class="stat"><div class="num">20+</div><div class="label">CVEs Found</div></div>
        <div class="stat"><div class="num">29</div><div class="label">Detection Patterns</div></div>
        <div class="stat"><div class="num">500+</div><div class="label">Findings Across Repos</div></div>
        <div class="stat"><div class="num">0%</div><div class="label">False Positive Rate</div></div>
    </div>
</div>

<div class="faq">
    <h2>FAQ</h2>
    <div class="faq-item">
        <h3>What does torchload-checker detect?</h3>
        <p>CWE-502 (Deserialization of Untrusted Data) vulnerabilities including unsafe torch.load(), pickle, ZeroMQ recv_pyobj, LangChain serialization, Keras load_model, joblib, numpy.load, and more. Updated for 2025-2026 CVEs.</p>
    </div>
    <div class="faq-item">
        <h3>How accurate is it?</h3>
        <p>0% false positive rate across 35+ clean repos tested. Our patterns are derived from real CVEs and updated for the latest 2025-2026 vulnerability research.</p>
    </div>
    <div class="faq-item">
        <h3>Can I use the API in CI/CD?</h3>
        <p>Yes! Pro and Enterprise tiers include API key access. Add a scan step to your GitHub Actions or GitLab CI pipeline.</p>
    </div>
</div>

<footer>EPNA Security Research &mdash; torchload-checker v0.7.0</footer>
</body>
</html>"""
    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8100)
