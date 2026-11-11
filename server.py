"""Chatrix: small, dependency-free Python server for the web prototype."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
DB_PATH = DATA / "chatrix.sqlite3"
SECRET_PATH = DATA / ".session-secret"
SESSION_SECRET = SECRET_PATH.read_bytes() if SECRET_PATH.exists() else secrets.token_bytes(48)
if not SECRET_PATH.exists():
    try:
        fd = os.open(SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as secret_file:
            secret_file.write(SESSION_SECRET)
    except FileExistsError:
        SESSION_SECRET = SECRET_PATH.read_bytes()

PBKDF2_ROUNDS = 320_000
SESSION_SECONDS = 14 * 24 * 60 * 60
SECURE_COOKIE = os.environ.get("CHATRIX_COOKIE_SECURE", "0") == "1"
HANDLE_RE = re.compile(r"^[a-zA-Z0-9_]{3,24}$")
ALLOWED_STATIC = {"index.html", "app.css", "app.js"}


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db() -> None:
    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                handle TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                public_key TEXT NOT NULL,
                private_bundle TEXT NOT NULL,
                bundle_iv TEXT NOT NULL,
                bundle_salt TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_a TEXT NOT NULL REFERENCES users(handle) ON DELETE CASCADE,
                user_b TEXT NOT NULL REFERENCES users(handle) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                UNIQUE(user_a, user_b),
                CHECK(user_a < user_b)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                sender TEXT NOT NULL REFERENCES users(handle) ON DELETE CASCADE,
                ciphertext TEXT NOT NULL,
                iv TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                seen INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS messages_conversation_id ON messages(conversation_id, id);
            CREATE INDEX IF NOT EXISTS messages_unread ON messages(conversation_id, sender, seen);
        """)


def normalize_handle(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Please enter a username.")
    handle = value.strip().removeprefix("@").lower()
    if not HANDLE_RE.fullmatch(handle):
        raise ValueError("Username must be 3–24 characters: letters, numbers, and underscores.")
    return handle


def validate_key_bundle(data: dict) -> tuple[str, str, str, str]:
    try:
        public_key = data["publicKey"]
        private_bundle = data["privateBundle"]
        bundle_iv = data["bundleIv"]
        bundle_salt = data["bundleSalt"]
        pub = base64.b64decode(public_key, validate=True)
        encrypted = base64.b64decode(private_bundle, validate=True)
        iv = base64.b64decode(bundle_iv, validate=True)
        salt = base64.b64decode(bundle_salt, validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Could not prepare encryption keys.") from exc
    if len(pub) != 65 or len(iv) != 12 or len(salt) != 16 or not 48 <= len(encrypted) <= 512:
        raise ValueError("Invalid encryption key bundle.")
    return public_key, private_bundle, bundle_iv, bundle_salt


class ChatrixHandler(BaseHTTPRequestHandler):
    server_version = "Chatrix/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        # Avoid logging usernames, message payloads, and request bodies.
        if self.path.startswith("/api/"):
            print(f"{self.log_date_time_string()} {self.address_string()} API {self.command} {urlparse(self.path).path}")
        else:
            super().log_message(fmt, *args)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Cache-Control", "no-store")

    def _json(self, status: int, payload: object, headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request.") from exc
        if length <= 0 or length > 400_000:
            raise ValueError("Invalid request size.")
        try:
            data = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Malformed JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object.")
        return data

    def _check_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        expected = f"http://{self.headers.get('Host', '')}"
        if SECURE_COOKIE:
            expected = f"https://{self.headers.get('Host', '')}"
        return hmac.compare_digest(origin.rstrip("/"), expected)

    def _set_cookie(self, token: str | None) -> str:
        if token is None:
            return "chatrix_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if SECURE_COOKIE else "")
        return f"chatrix_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}" + ("; Secure" if SECURE_COOKIE else "")

    def _make_token(self, handle: str) -> str:
        payload = f"{handle}|{int(time.time()) + SESSION_SECONDS}|{secrets.token_urlsafe(12)}".encode()
        encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        signature = hmac.new(SESSION_SECRET, encoded.encode(), hashlib.sha256).digest()
        return encoded + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")

    def _current_user(self) -> sqlite3.Row | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["chatrix_session"].value
            encoded, signature = token.split(".", 1)
            expected = hmac.new(SESSION_SECRET, encoded.encode(), hashlib.sha256).digest()
            supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
            if not hmac.compare_digest(expected, supplied):
                return None
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
            handle, expires, _nonce = payload.split("|", 2)
            if int(expires) < time.time():
                return None
        except (KeyError, ValueError, UnicodeDecodeError, TypeError):
            return None
        with connect() as db:
            return db.execute("SELECT * FROM users WHERE handle = ?", (handle,)).fetchone()

    def _conversation(self, db: sqlite3.Connection, me: str, peer: str) -> sqlite3.Row | None:
        a, b = sorted((me, peer))
        return db.execute("SELECT * FROM conversations WHERE user_a = ? AND user_b = ?", (a, b)).fetchone()

    def _route_api(self, method: str, path: str, query: dict[str, list[str]]) -> bool:
        if path not in ("/api/login", "/api/register", "/api/logout") and path.startswith("/api/"):
            user = self._current_user()
        else:
            user = None

        if method in ("POST", "PUT", "DELETE") and path.startswith("/api/") and not self._check_origin():
            self._json(HTTPStatus.FORBIDDEN, {"error": "The request origin could not be verified."})
            return True

        if method == "POST" and path == "/api/register":
            try:
                data = self._body()
                handle = normalize_handle(data.get("username"))
                password = data.get("password")
                display_name = data.get("displayName", "").strip() if isinstance(data.get("displayName", ""), str) else ""
                if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
                    raise ValueError("Password must be between 8 and 256 characters.")
                public_key, private_bundle, bundle_iv, bundle_salt = validate_key_bundle(data)
                pass_salt = secrets.token_bytes(16)
                pass_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), pass_salt, PBKDF2_ROUNDS)
                now = int(time.time())
                with connect() as db:
                    db.execute("INSERT INTO users(handle, display_name, password_salt, password_hash, public_key, private_bundle, bundle_iv, bundle_salt, created_at, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                               (handle, display_name[:48], pass_salt, pass_hash, public_key, private_bundle, bundle_iv, bundle_salt, now, now))
                token = self._make_token(handle)
                self._json(HTTPStatus.CREATED, {"me": self._user_json(handle, display_name, public_key), "bundle": {"privateBundle": private_bundle, "bundleIv": bundle_iv, "bundleSalt": bundle_salt}}, {"Set-Cookie": self._set_cookie(token)})
            except sqlite3.IntegrityError:
                self._json(HTTPStatus.CONFLICT, {"error": "That username is already taken."})
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return True

        if method == "POST" and path == "/api/login":
            try:
                data = self._body()
                handle = normalize_handle(data.get("username"))
                password = data.get("password")
                if not isinstance(password, str) or len(password) > 256:
                    raise ValueError("Please check your username and password.")
                with connect() as db:
                    row = db.execute("SELECT * FROM users WHERE handle = ?", (handle,)).fetchone()
                salt = row["password_salt"] if row else bytes(16)
                expected = row["password_hash"] if row else bytes(32)
                supplied = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
                if row is None or not hmac.compare_digest(expected, supplied):
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "Incorrect username or password."})
                    return True
                with connect() as db:
                    db.execute("UPDATE users SET last_seen = ? WHERE handle = ?", (int(time.time()), handle))
                token = self._make_token(handle)
                self._json(HTTPStatus.OK, {"me": self._user_json(handle, row["display_name"], row["public_key"]), "bundle": {"privateBundle": row["private_bundle"], "bundleIv": row["bundle_iv"], "bundleSalt": row["bundle_salt"]}}, {"Set-Cookie": self._set_cookie(token)})
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return True

        if method == "POST" and path == "/api/logout":
            self._json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": self._set_cookie(None)})
            return True

        if path.startswith("/api/") and user is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "Please log in to continue."})
            return True

        if method == "GET" and path == "/api/me":
            self._json(HTTPStatus.OK, {"me": self._user_json(user["handle"], user["display_name"], user["public_key"]), "bundle": {"privateBundle": user["private_bundle"], "bundleIv": user["bundle_iv"], "bundleSalt": user["bundle_salt"]}})
            return True

        if method == "POST" and path == "/api/presence":
            with connect() as db:
                db.execute("UPDATE users SET last_seen = ? WHERE handle = ?", (int(time.time()), user["handle"]))
            self._json(HTTPStatus.OK, {"ok": True})
            return True

        if method == "GET" and path == "/api/users":
            needle = (query.get("q", [""])[0] or "").strip().removeprefix("@").lower()
            if len(needle) < 2:
                self._json(HTTPStatus.OK, {"users": []})
            else:
                pattern = needle.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
                with connect() as db:
                    rows = db.execute("SELECT handle, display_name, public_key, last_seen FROM users WHERE handle LIKE ? ESCAPE '!' AND handle != ? ORDER BY handle LIMIT 18", (pattern, user["handle"])).fetchall()
                self._json(HTTPStatus.OK, {"users": [self._user_json(row["handle"], row["display_name"], row["public_key"], row["last_seen"]) for row in rows]})
            return True

        if method == "GET" and path == "/api/chats":
            now = int(time.time())
            with connect() as db:
                rows = db.execute("""
                    SELECT c.id, CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END AS peer,
                      u.display_name, u.public_key, u.last_seen,
                      (SELECT m.id FROM messages m WHERE m.conversation_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_id,
                      (SELECT m.created_at FROM messages m WHERE m.conversation_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_time,
                      (SELECT m.sender FROM messages m WHERE m.conversation_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_sender,
                      (SELECT m.id FROM messages m WHERE m.conversation_id = c.id AND m.sender = ? AND m.seen = 1 ORDER BY m.id DESC LIMIT 1) AS last_seen_outgoing_id,
                      (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id AND m.sender != ? AND m.seen = 0) AS unread
                    FROM conversations c JOIN users u ON u.handle = CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END
                    WHERE c.user_a = ? OR c.user_b = ? ORDER BY COALESCE(last_time, c.created_at) DESC
                """, (user["handle"], user["handle"], user["handle"], user["handle"], user["handle"], user["handle"])).fetchall()
            chats = []
            for row in rows:
                chats.append({"handle": "@" + row["peer"], "displayName": row["display_name"], "publicKey": row["public_key"], "online": now - row["last_seen"] < 45, "lastSeen": row["last_seen"], "lastId": row["last_id"], "lastTime": row["last_time"], "lastSender": row["last_sender"], "lastSeenOutgoingId": row["last_seen_outgoing_id"], "unread": row["unread"]})
            self._json(HTTPStatus.OK, {"chats": chats})
            return True

        if method == "POST" and path == "/api/chats":
            try:
                data = self._body()
                peer = normalize_handle(data.get("username"))
                if peer == user["handle"]:
                    raise ValueError("You can't start a chat with yourself.")
                now = int(time.time())
                a, b = sorted((user["handle"], peer))
                with connect() as db:
                    target = db.execute("SELECT handle FROM users WHERE handle = ?", (peer,)).fetchone()
                    if not target:
                        self._json(HTTPStatus.NOT_FOUND, {"error": "User not found."})
                        return True
                    db.execute("INSERT OR IGNORE INTO conversations(user_a, user_b, created_at) VALUES(?,?,?)", (a, b, now))
                    row = db.execute("SELECT display_name, public_key, last_seen FROM users WHERE handle = ?", (peer,)).fetchone()
                self._json(HTTPStatus.OK, {"chat": self._user_json(peer, row["display_name"], row["public_key"], row["last_seen"])})
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return True

        match = re.fullmatch(r"/api/chats/([^/]+)/messages", path)
        if match:
            try:
                peer = normalize_handle(unquote(match.group(1)))
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return True
            with connect() as db:
                conversation = self._conversation(db, user["handle"], peer)
                if conversation is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "Chat not found."})
                    return True
                if method == "GET":
                    try:
                        after_id = max(0, int(query.get("after", ["0"])[0]))
                    except ValueError:
                        after_id = 0
                    rows = db.execute("SELECT id, sender, ciphertext, iv, created_at, seen FROM messages WHERE conversation_id = ? AND id > ? ORDER BY id LIMIT 200", (conversation["id"], after_id)).fetchall()
                    self._json(HTTPStatus.OK, {"messages": [{"id": row["id"], "sender": "@" + row["sender"], "ciphertext": row["ciphertext"], "iv": row["iv"], "createdAt": row["created_at"], "seen": bool(row["seen"])} for row in rows]})
                    return True
                if method == "POST":
                    try:
                        data = self._body()
                        ciphertext, iv = data.get("ciphertext"), data.get("iv")
                        if not isinstance(ciphertext, str) or len(ciphertext) > 350_000 or not isinstance(iv, str) or len(iv) > 48:
                            raise ValueError("Message is too large.")
                        cipher_bytes = base64.b64decode(ciphertext, validate=True)
                        iv_bytes = base64.b64decode(iv, validate=True)
                        if len(cipher_bytes) < 17 or len(iv_bytes) != 12:
                            raise ValueError("Invalid encrypted message.")
                        now = int(time.time())
                        cur = db.execute("INSERT INTO messages(conversation_id, sender, ciphertext, iv, created_at) VALUES(?,?,?,?,?)", (conversation["id"], user["handle"], ciphertext, iv, now))
                        self._json(HTTPStatus.CREATED, {"message": {"id": cur.lastrowid, "sender": "@" + user["handle"], "ciphertext": ciphertext, "iv": iv, "createdAt": now, "seen": False}})
                    except ValueError as exc:
                        self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return True

        match = re.fullmatch(r"/api/chats/([^/]+)/seen", path)
        if method == "POST" and match:
            try:
                peer = normalize_handle(unquote(match.group(1)))
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid user."})
                return True
            with connect() as db:
                conversation = self._conversation(db, user["handle"], peer)
                if conversation:
                    db.execute("UPDATE messages SET seen = 1 WHERE conversation_id = ? AND sender != ?", (conversation["id"], user["handle"]))
            self._json(HTTPStatus.OK, {"ok": True})
            return True

        self._json(HTTPStatus.NOT_FOUND, {"error": "Page not found."})
        return True

    @staticmethod
    def _user_json(handle: str, display_name: str, public_key: str, last_seen: int | None = None) -> dict:
        item = {"handle": "@" + handle, "displayName": display_name, "publicKey": public_key}
        if last_seen is not None:
            item["lastSeen"] = last_seen
            item["online"] = int(time.time()) - last_seen < 45
        return item

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            try:
                self._route_api("GET", parsed.path, parse_qs(parsed.query))
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal server error."})
            return
        name = "index.html" if parsed.path in ("/", "") else parsed.path.lstrip("/")
        if name not in ALLOWED_STATIC:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            raw = (WEB / name).read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = {"index.html": "text/html; charset=utf-8", "app.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8"}[name]
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            self._route_api("POST", parsed.path, parse_qs(parsed.query))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal server error."})


if __name__ == "__main__":
    init_db()
    host = os.environ.get("CHATRIX_HOST", "127.0.0.1")
    port = int(os.environ.get("CHATRIX_PORT", "8000"))
    print(f"Chatrix is running at http://{host}:{port}")
    ThreadingHTTPServer((host, port), ChatrixHandler).serve_forever()
