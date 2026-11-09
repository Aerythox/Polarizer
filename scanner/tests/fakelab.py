"""An in-memory stand-in for the invoice lab, used to test the scanner offline.

It emulates the lab's vulnerable and fixed behavior with an httpx MockTransport,
so the scanner tests need no running server and no database.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

import httpx

WEAK_SECRET = "secret123"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_token(sub: str, role: str, secret: str = WEAK_SECRET) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": sub, "role": role}).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def build_transport(mode: str) -> httpx.MockTransport:
    """mode is 'vulnerable' or 'fixed'."""
    users = {
        "a": {"_id": "a", "name": "Alice", "email": "alice@example.test", "role": "user"},
        "b": {"_id": "b", "name": "Bob", "email": "bob@example.test", "role": "user"},
        "adm": {"_id": "adm", "name": "Admin", "email": "admin@example.test", "role": "admin"},
    }
    invoices = {
        1001: {"number": 1001, "ownerId": "a", "customer": "Fictional Bakery Co", "amountCents": 125000},
        1002: {"number": 1002, "ownerId": "a", "customer": "Sample Print Shop", "amountCents": 48000},
        1003: {"number": 1003, "ownerId": "b", "customer": "Placeholder Logistics", "amountCents": 990000},
        1004: {"number": 1004, "ownerId": "b", "customer": "Demo Coffee Roasters", "amountCents": 37500},
    }
    editable = {"name", "email"}

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        caller = None
        if auth.startswith("Bearer "):
            claims = _claims(auth[len("Bearer ") :])
            caller = users.get(claims.get("sub"))
            if caller is not None:
                caller = {**caller, "role": claims.get("role", caller["role"])}

        path = request.url.path
        method = request.method

        if path == "/auth/login" and method == "POST":
            return _json(200, {"token": make_token("a", "user")})

        if caller is None:
            return _json(401, {"error": "Missing or invalid token"})

        invoice_match = re.fullmatch(r"/invoices/(\d+)", path)
        if invoice_match and method == "GET":
            number = int(invoice_match.group(1))
            invoice = invoices.get(number)
            if invoice is None:
                return _json(404, {"error": "Invoice not found"})
            if mode == "fixed" and invoice["ownerId"] != caller["_id"]:
                return _json(404, {"error": "Invoice not found"})
            return _json(200, invoice)

        if path == "/invoices" and method == "GET":
            owned = [i for i in invoices.values() if i["ownerId"] == caller["_id"]]
            return _json(200, owned)

        if path == "/admin/users" and method == "GET":
            if mode == "fixed" and caller["role"] != "admin":
                return _json(403, {"error": "Forbidden"})
            return _json(200, list(users.values()))

        if path == "/admin/stats" and method == "GET":
            if caller["role"] != "admin":
                return _json(403, {"error": "Forbidden"})
            return _json(200, {"userCount": len(users), "invoiceCount": len(invoices)})

        if path == "/profile/me" and method == "GET":
            return _json(200, users[caller["_id"]])

        if path == "/profile/me" and method == "PATCH":
            body = json.loads(request.content or b"{}")
            allowed = editable if mode == "fixed" else set(body)
            for key in list(body):
                if key in allowed and key in {"name", "email", "role"}:
                    users[caller["_id"]][key] = body[key]
            return _json(200, users[caller["_id"]])

        return _json(404, {"error": "Not found"})

    return httpx.MockTransport(handler)


def _json(status: int, data) -> httpx.Response:
    return httpx.Response(status, json=data)
