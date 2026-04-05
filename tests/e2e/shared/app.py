"""
Shared test application.
Reads APP_MODE env var and behaves accordingly:
  healthy       -> 200 OK always
  error-5xx     -> 500 always  (simulates DB crash / unhandled exception)
  error-4xx     -> 403 always  (simulates missing IAM / wrong auth)
  intermittent  -> 200 or 502 randomly (simulates flapping dependency)
"""
import json
import os
import random
import time

from flask import Flask, jsonify, request

app = Flask(__name__)
MODE = os.environ.get("APP_MODE", "healthy")
APP_NAME = os.environ.get("APP_NAME", f"cloudctl-test-{MODE}")


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    if MODE == "healthy":
        return jsonify({
            "status": "ok",
            "app": APP_NAME,
            "path": f"/{path}",
            "latency_ms": random.randint(10, 80),
        }), 200

    if MODE == "error-5xx":
        # Simulate unhandled exception — DB connection timeout
        time.sleep(random.uniform(0.1, 0.3))   # feels like a slow DB call
        return jsonify({
            "error": "Internal Server Error",
            "message": "upstream connect error or disconnect/reset before headers. "
                       "reset reason: connection timeout",
            "code":    500,
        }), 500

    if MODE == "error-4xx":
        return jsonify({
            "error":   "Forbidden",
            "message": "User does not have permission to access this resource. "
                       "Check IAM policies / role bindings.",
            "code":    403,
        }), 403

    if MODE == "intermittent":
        # ~50 % chance of a bad gateway
        if random.random() < 0.5:
            time.sleep(random.uniform(0.5, 2.0))   # slow then fail
            return jsonify({
                "error":   "Bad Gateway",
                "message": "Upstream service unavailable (connection reset by peer)",
                "code":    502,
            }), 502
        return jsonify({
            "status": "ok",
            "app": APP_NAME,
            "latency_ms": random.randint(50, 400),
        }), 200

    return jsonify({"error": "unknown mode"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
