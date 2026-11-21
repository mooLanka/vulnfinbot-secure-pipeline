import pytest
from app.guardrails import MAX_MESSAGE_LENGTH

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy"}

def test_successful_chat(client):
    response = client.post("/api/chat", json={"message": "How can I manage my monthly budget?"})
    assert response.status_code == 200
    body = response.get_json()
    assert isinstance(body["response"], str) and body["response"]
    assert body["blocked"] is False

def test_empty_message_rejected(client):
    response = client.post("/api/chat", json={"message": "   "})
    assert response.status_code == 400

def test_missing_message_rejected(client):
    response = client.post("/api/chat", json={"text": "hello"})
    assert response.status_code == 400

def test_invalid_json_rejected(client):
    response = client.post("/api/chat", data="{not valid json", content_type="application/json")
    assert response.status_code == 400

def test_too_long_message_rejected(client):
    response = client.post("/api/chat", json={"message": "a" * (MAX_MESSAGE_LENGTH + 1)})
    assert response.status_code == 400

@pytest.mark.parametrize("value", [123, True, ["hi"], {"nested": "hi"}, None])
def test_unexpected_input_types(client, value):
    response = client.post("/api/chat", json={"message": value})
    assert response.status_code == 400

def test_security_headers_present(client):
    headers = client.get("/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
