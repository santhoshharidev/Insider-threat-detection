# Mocktivate - Backend Prototype

This repository contains a FastAPI-based backend prototype for Mocktivate — an AI-powered mock interview platform.

Quick start (Windows PowerShell):

1. Create a virtual environment and install dependencies

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
```

2. Run the API

```powershell
uvicorn app.main:app --reload --port 8000
```

API endpoints (prototype):
- GET / -> health
- POST /api/auth/signup -> signup (stub)
- POST /api/auth/login -> login (stub)
- POST /api/interviews/start -> start interview
- POST /api/interviews/answer -> answer question
- GET /api/admin/stats -> admin stats (stub)

Notes:
- This is a prototype. Replace AI stubs with an LLM integration, secure the code runner (use sandboxing), and integrate a real payment gateway before production.
