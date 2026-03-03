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
    version="0.5.0",
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
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def scan_form(request: Request):
    """Handle form submission from web UI."""
    form = await request.form()
    repo_url = str(form.get("repo_url", "")).strip()

    if not repo_url:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Please enter a repository URL",
        })

    valid, normalized = validate_github_url(repo_url)
    if not valid:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": normalized,
        })

    # Rate limit check
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": f"Rate limit exceeded ({FREE_SCANS_PER_DAY} scans/day). Upgrade to Pro for unlimited scans.",
        })

    # Check cache
    cached = get_cached_result(normalized)
    if cached:
        cached["from_cache"] = True
        scan_stats["cache_hits"] += 1
        return templates.TemplateResponse("results.html", {
            "request": request,
            "result": cached,
        })

    scan_stats["total_scans"] += 1

    # Run scan
    try:
        result = await clone_and_scan(normalized)
    except asyncio.TimeoutError:
        scan_stats["errors"] += 1
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Scan timed out. Try a smaller repository.",
        })
    except Exception as e:
        scan_stats["errors"] += 1
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": f"Scan failed: {str(e)[:100]}",
        })

    if result.get("status") == "error":
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": result.get("error", "Unknown error"),
        })

    # Cache result
    save_cached_result(normalized, result)
    result["from_cache"] = False

    return templates.TemplateResponse("results.html", {
        "request": request,
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
    return {"status": "ok", "version": "0.5.0"}


@app.get("/api/v1/stats")
async def stats():
    """Public scan statistics."""
    return {
        "total_scans": scan_stats["total_scans"],
        "cache_hits": scan_stats["cache_hits"],
        "errors": scan_stats["errors"],
        "patterns_detected": 18,
        "version": "0.5.0",
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8100)
