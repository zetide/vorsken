# tests/fixtures/vulnerable_sample.py
"""
Vulnerable sample code for StackSecAI integration testing.
Each function demonstrates one OWASP API Security Top 10 (2023) risk.
DO NOT deploy this code. For testing purposes only.
"""

# ── API1:2023 - Broken Object Level Authorization (BOLA) ─────────────────────
# User-supplied ID is passed directly to DB query without ownership check.

def get_user_order(order_id: int, db):
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    return db.execute(query).fetchone()


# ── API2:2023 - Broken Authentication ────────────────────────────────────────
# JWT token is decoded without signature verification.

import base64, json as _json

def get_current_user(token: str) -> dict:
    payload = token.split(".")[1]
    padding = "=" * (4 - len(payload) % 4)
    return _json.loads(base64.b64decode(payload + padding))


# ── API3:2023 - Broken Object Property Level Authorization ───────────────────
# All fields including password_hash are returned to the caller.

def get_user_profile(user_id: int, db) -> dict:
    row = db.execute(
        "SELECT id, name, email, password_hash, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    return dict(row)


# ── API4:2023 - Unrestricted Resource Consumption ────────────────────────────
# No rate limiting, pagination cap, or resource guard on the query.

def search_items(keyword: str, db) -> list:
    rows = db.execute(
        f"SELECT * FROM items WHERE name LIKE '%{keyword}%'"
    ).fetchall()
    return [dict(r) for r in rows]


# ── API5:2023 - Broken Function Level Authorization ──────────────────────────
# Admin endpoint checks only login state, not role.

def delete_user(user_id: int, current_user: dict, db):
    if not current_user.get("logged_in"):
        raise PermissionError("Not authenticated")
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── API6:2023 - Unrestricted Access to Sensitive Business Flows ──────────────
# No bot detection, CAPTCHA, or velocity check on bulk purchase.

def purchase_item(item_id: int, quantity: int, user_id: int, db):
    db.execute(
        "INSERT INTO orders (item_id, quantity, user_id) VALUES (?, ?, ?)",
        (item_id, quantity, user_id),
    )


# ── API7:2023 - Server Side Request Forgery (SSRF) ───────────────────────────
# User-controlled URL is fetched without validation or allowlist.

import urllib.request

def fetch_metadata(url: str) -> bytes:
    with urllib.request.urlopen(url) as resp:
        return resp.read()


# ── API8:2023 - Security Misconfiguration ────────────────────────────────────
# Debug mode enabled and full exception tracebacks exposed to client.
# Hardcoded secret key used for session signing.

SECRET_KEY = "hardcoded-secret-key-do-not-use"
DEBUG = True

def create_app():
    import flask
    app = flask.Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DEBUG"] = DEBUG
    app.config["PROPAGATE_EXCEPTIONS"] = True
    return app


# ── API9:2023 - Improper Inventory Management ────────────────────────────────
# Deprecated v1 endpoint still active alongside current v2.

def register_routes(app):
    @app.route("/api/v1/users")          # legacy endpoint — never removed
    def list_users_v1():
        return {"version": "v1", "deprecated": True}

    @app.route("/api/v2/users")
    def list_users_v2():
        return {"version": "v2"}


# ── API10:2023 - Unsafe Consumption of APIs ──────────────────────────────────
# External API response is trusted and used without validation.

import requests

def enrich_user_data(user_id: int) -> dict:
    resp = requests.get(f"https://external-api.example.com/users/{user_id}")
    data = resp.json()                   # no status check, no schema validation
    return {
        "name":  data["name"],
        "email": data["email"],
        "role":  data.get("role", "user"),
    }
