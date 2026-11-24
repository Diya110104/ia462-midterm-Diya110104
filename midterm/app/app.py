"""IA 462 midterm - minimal Flask service used as the hardened-container target.

Adjust the routes to match your Lab 4 application if it differed. Keep the
app free of secrets: configuration comes only from environment variables.
"""
import os
import platform

from flask import Flask, abort, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # reject oversized bodies

# In-memory store only: the container runs with a read-only root filesystem.
ITEMS: dict[int, dict] = {}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/")
def index():
    return jsonify(service="ia462-midterm", status="ok")


@app.get("/health")
def health():
    return jsonify(status="healthy")


@app.get("/whoami")
def whoami():
    """Shows the process is not root - handy for the video walkthrough."""
    return jsonify(uid=os.getuid(), gid=os.getgid(), python=platform.python_version())


@app.get("/api/items")
def list_items():
    return jsonify(list(ITEMS.values()))


@app.post("/api/items")
def create_item():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name or len(name) > 100:
        abort(400, description="'name' is required (1-100 chars)")
    item_id = len(ITEMS) + 1
    ITEMS[item_id] = {"id": item_id, "name": name}
    return jsonify(ITEMS[item_id]), 201


@app.get("/api/items/<int:item_id>")
def get_item(item_id: int):
    if item_id not in ITEMS:
        abort(404)
    return jsonify(ITEMS[item_id])


if __name__ == "__main__":
    # Local development only; the container uses gunicorn.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
