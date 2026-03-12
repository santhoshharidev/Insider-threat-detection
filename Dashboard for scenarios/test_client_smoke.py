from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def run_tests():
    print("GET /")
    r = client.get("/")
    print(r.status_code, r.json())

    print("POST /api/interviews/start")
    r = client.post("/api/interviews/start", json={"kind": "hr", "mode": "text"})
    print(r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)

if __name__ == '__main__':
    run_tests()
