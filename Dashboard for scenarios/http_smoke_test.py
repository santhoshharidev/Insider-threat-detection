import requests
import json

BASE = "http://127.0.0.1:8001"

def test_root():
    r = requests.get(BASE + "/")
    print("GET / ->", r.status_code, r.json())

def test_start_interview():
    payload = {"kind": "hr", "mode": "text"}
    r = requests.post(BASE + "/api/interviews/start", json=payload)
    try:
        print("POST /api/interviews/start ->", r.status_code, r.json())
    except Exception:
        print("POST /api/interviews/start ->", r.status_code, r.text)

if __name__ == '__main__':
    test_root()
    test_start_interview()
