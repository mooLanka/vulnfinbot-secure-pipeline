from flask import Blueprint, jsonify, make_response, request
from .ai import generate_reply
from .guardrails import InputValidationError, validate_message

api_bp = Blueprint("api", __name__)

_INDEX_HTML = (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>Mini-VulnFinBot</title></head><body>"
    "<h1>Mini-VulnFinBot</h1><ul>"
    "<li><a href=\"/health\">GET /health</a></li>"
    "<li>POST /api/chat (application/json)</li>"
    "</ul></body></html>"
)

@api_bp.get("/")
def index():
    return make_response(_INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"})

@api_bp.get("/health")
def health():
    return jsonify(status="healthy"), 200

@api_bp.post("/api/chat")
def chat():
    if not request.is_json:
        return jsonify(error="unsupported_media_type", message="Content-Type must be application/json."), 415

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify(error="invalid_request", message="Request body must be valid JSON."), 400
    if not isinstance(payload, dict):
        return jsonify(error="invalid_request", message="Request body must be a JSON object."), 400

    try:
        message = validate_message(payload.get("message"))
    except InputValidationError as exc:
        return jsonify(error="invalid_request", message=str(exc)), 400

    result = generate_reply(message)
    return jsonify(
        response=result.text,
        blocked=result.blocked,
        risk_categories=list(result.categories),
        engine=result.engine,
    ), 200
