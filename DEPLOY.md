# torchload-web Deployment Guide

## Quick Start (Local)
```bash
pip install fastapi uvicorn jinja2 python-multipart
python3 app.py  # Runs on http://127.0.0.1:8100
```

## Production (Render.com)
1. Create account at render.com
2. New Web Service → Connect GitHub repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
5. Environment: Python 3.11+
6. Free tier: Sufficient for MVP

## Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8100
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8100"]
```

## Environment Variables
- `SCANNER_PATH`: Path to torchload_checker.py (default: ./torchload_checker.py)
- `PORT`: Server port (default: 8100)

## Requirements
```
fastapi>=0.100.0
uvicorn>=0.20.0
jinja2>=3.1.0
python-multipart>=0.0.5
```

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | / | Web UI |
| POST | /scan | Web form scan |
| POST | /api/v1/scan | API scan (JSON) |
| GET | /api/v1/scan/{owner}/{repo} | Quick scan |
| GET | /api/v1/health | Health check |
| GET | /api/v1/stats | Scan statistics |
| GET | /api/v1/patterns | Detection patterns |
| GET | /api/v1/badge/{owner}/{repo} | Shields.io badge |
| GET | /api/v1/report/{owner}/{repo} | Security report |
| GET | /api/v1/pricing | Pricing tiers |
| GET | /api/docs | OpenAPI docs |
| GET | /api/redoc | ReDoc docs |

## Monitoring
- Health: `curl /api/v1/health`
- Stats: `curl /api/v1/stats`
- Badge: `![CWE-502](https://your-domain/api/v1/badge/owner/repo)`
