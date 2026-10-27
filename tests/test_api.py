from fastapi.testclient import TestClient

from api import app
from cloudsentinel.sample_data import sample_events

client = TestClient(app)

def test_health():
    assert client.get("/health").json() == {"status": "ok"}

def test_analyze():
    response = client.post("/analyze", json={"events": sample_events().to_dict(orient="records")})
    assert response.status_code == 200
    assert "alerts" in response.json()
