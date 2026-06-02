# tests/fixtures/vulnerable_sample.py
"""
Vulnerable sample code for vorsken integration testing.
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
    # SQLI-VULN-FSTRING: f-string SQL (existing sample; sql-injection must fire)
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


# ── AI-generated code risks ──────────────────────────────────────────────────
# Patterns commonly produced by LLM coding assistants that hand excessive
# capability to an LLM agent. Detected by rules under rules/custom/ai-generated/.

# AI-GEN-1a: ShellTool given to an agent — arbitrary shell execution.
from langchain_community.tools import ShellTool  # noqa: E402

shell = ShellTool()

# AI-GEN-1b: PythonREPLTool in an agent tool list — arbitrary Python execution.
from langchain_experimental.tools import PythonREPLTool  # noqa: E402

tools = [PythonREPLTool()]

# AI-GEN-1c: FileManagementToolkit without root_dir — unrestricted FS access.
from langchain_community.agent_toolkits import FileManagementToolkit  # noqa: E402

fm = FileManagementToolkit()

# AI-GEN-1d: PythonAstREPLTool — arbitrary Python execution.
from langchain_experimental.tools import PythonAstREPLTool  # noqa: E402

ast_tool = PythonAstREPLTool()

# SAFE: FileManagementToolkit scoped with root_dir — must NOT fire.
fm_safe = FileManagementToolkit(root_dir="/tmp/agent_workspace")


# ── SQL Injection (CWE-89) - sql-injection rule fixtures ─────────────────────
# SQL passed to execute()/executemany() as a dynamically constructed string.
# The sql-injection rule (rules/custom/sql_injection.yml) MUST fire on the
# VULN cases and MUST NOT fire on the SAFE (parameterized / static) cases.
# The f-string form is exercised by search_items above (SQLI-VULN-FSTRING).


def sqli_concat(user_id, db):
    # SQLI-VULN-CONCAT: query built by string concatenation
    return db.execute("SELECT * FROM accounts WHERE id = " + user_id).fetchone()


def sqli_format(table, db):
    # SQLI-VULN-FORMAT: query built with str.format()
    return db.execute("SELECT * FROM {}".format(table)).fetchall()


def sqli_percent(name, db):
    # SQLI-VULN-PERCENT: query built with single-% formatting
    return db.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchone()


def sqli_safe_param(user_id, db):
    # SQLI-SAFE-PARAM: parameterized query, value bound as the second argument
    query = "SELECT * FROM accounts WHERE id = ?"
    return db.execute(query, (user_id,)).fetchone()


def sqli_safe_placeholder(user_id, db):
    # SQLI-SAFE-PLACEHOLDER: %s is a bound placeholder, not % formatting
    return db.execute("SELECT * FROM accounts WHERE id = %s", (user_id,)).fetchone()


def sqli_safe_static(db):
    # SQLI-SAFE-STATIC: fully static query, no interpolation
    return db.execute("SELECT COUNT(*) FROM accounts").fetchone()


# ── Dangerous AI/ML library kwargs (CWE-94 / CWE-502) ────────────────────────
# Opt-in flags that enable code execution or unsafe deserialization in AI/ML
# libraries. The dangerous-ai-kwargs rule MUST fire when the flag is literally
# True and MUST NOT fire when it is False or omitted.


def ai_trust_remote_code(loader):
    # AIKW-VULN-TRUST: trust_remote_code=True runs arbitrary model-repo code
    return loader.from_pretrained("some/model", trust_remote_code=True)


def ai_dangerous_deserialization(store, embeddings):
    # AIKW-VULN-DESER: allow_dangerous_deserialization=True permits pickle RCE
    return store.load_local("index", embeddings, allow_dangerous_deserialization=True)


def ai_dangerous_code(make_agent, llm, df):
    # AIKW-VULN-CODE: allow_dangerous_code=True permits arbitrary code execution
    return make_agent(llm, df, allow_dangerous_code=True)


def ai_kwargs_false(loader):
    # AIKW-SAFE-FALSE: explicit =False must NOT fire
    return loader.from_pretrained("some/model", trust_remote_code=False)


def ai_kwargs_omitted(loader):
    # AIKW-SAFE-OMITTED: flag not passed must NOT fire
    return loader.from_pretrained("some/model")


# ── Dynamic code execution / deserialization (CWE-94 / CWE-502) ──────────────
# The code-execution rule MUST fire on exec / compile / pickle.load(s) and MUST
# NOT fire on re.compile (regex) or ordinary code.
import pickle  # noqa: E402
import re  # noqa: E402


def ce_exec(user_code):
    # CE-VULN-EXEC: exec() runs arbitrary Python
    exec(user_code)


def ce_pickle_loads(blob):
    # CE-VULN-PICKLE-LOADS: pickle.loads() deserializes untrusted bytes
    return pickle.loads(blob)


def ce_pickle_load(fp):
    # CE-VULN-PICKLE-LOAD: pickle.load() deserializes an untrusted stream
    return pickle.load(fp)


def ce_compile(src):
    # CE-VULN-COMPILE: builtin compile() turns a string into executable code
    return compile(src, "<string>", "exec")


def ce_re_compile(pattern):
    # CE-SAFE-RE-COMPILE: re.compile is a regex, NOT builtin compile - must NOT fire
    return re.compile(pattern)


def ce_normal(values):
    # CE-SAFE-NORMAL: ordinary code must NOT fire
    return sum(v for v in values)
