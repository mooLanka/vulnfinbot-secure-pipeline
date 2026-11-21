import logging
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException
from .routes import api_bp

MAX_BODY_BYTES = 8 * 1024

_SAFE_HTTP_MESSAGES = {
    400: "Invalid request.",
    404: "Resource not found.",
    405: "Method not allowed.",
    413: "Request body is too large.",
    415: "Content-Type must be application/json.",
    429: "Too many requests.",
}

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_BODY_BYTES, JSON_SORT_KEYS=False)
    if config:
        app.config.update(config)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    app.register_blueprint(api_bp)

    @app.after_request
    def _security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        app.logger.info("%s %s -> %s", request.method, request.path, response.status_code)
        return response

    @app.errorhandler(HTTPException)
    def _http_error(exc):
        code = exc.code or 500
        return jsonify(error="http_error", message=_SAFE_HTTP_MESSAGES.get(code, "Request could not be processed."), status=code), code

    @app.errorhandler(Exception)
    def _unexpected_error(exc):
        app.logger.exception("Unhandled application error")
        return jsonify(error="internal_error", message="An internal error occurred.", status=500), 500

    return app
