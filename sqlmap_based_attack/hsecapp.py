#!/usr/bin/env python3
"""

secapp_defended.py — Hardened version of the sec app
Defenses added:
  1. Rate limiting per IP (sliding window)
  2. Automatic IP blocking after threshold breaches
  3. SQLMap / SQLi pattern detection
  4. Request fingerprinting (User-Agent, timing)
  5. Honeypot parameter detection
  6. Response normalization (prevents timing oracle)
  7. Structured security event logging
"""

from flask import Flask, request, jsonify, abort
import sqlite3
import time
import re
import hashlib
import logging
import json
import random
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW   = 60        # seconds
RATE_LIMIT_MAX_REQS = 15        # max requests per IP per window
BLOCK_THRESHOLD     = 30        # requests before hard block
BLOCK_DURATION      = 3600      # seconds (1 hour)
MIN_RESPONSE_TIME   = 0.1       # seconds — normalize timing to prevent oracle

# SQLMap and common SQLi signatures to detect
SQLI_PATTERNS = [
    r"('|%27)",                          # single quote / URL encoded
    r"(--|#|%23)",                        # SQL comment markers
    r"\b(OR|AND)\b\s+\d+\s*=\s*\d+",    # OR 1=1 / AND 1=1
    r"\b(UNION|SELECT|INSERT|DROP|UPDATE|DELETE|EXEC)\b",  # SQL keywords
    r"(SLEEP|WAITFOR|BENCHMARK|PG_SLEEP)\s*\(",            # time-based
    r"(EXTRACTVALUE|UPDATEXML|LOAD_FILE)",                  # error/file based
    r"%27|%22|%3D|%3B|%2D%2D",          # URL-encoded SQLi chars
    r"(0x[0-9a-fA-F]+)",                 # hex encoding
    r"(/\*.*?\*/)",                       # inline comments
    r"\b(NULL|TRUE|FALSE)\b.*=",         # boolean manipulation
]

SQLMAP_UA_PATTERNS = [
    "sqlmap",
    "python-requests",
    "nikto",
    "nmap",
    "masscan",
    "dirbuster",
    "hydra",
]

COMPILED_SQLI = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]

# ─────────────────────────────────────────────────────────────
# Security Event Logger
# ─────────────────────────────────────────────────────────────
log_path = Path("security_events.jsonl")

def log_event(event_type: str, ip: str, details: dict):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "ip": ip,
        "details": details
    }
    with open(log_path, "a") as f:
        f.write(json.dumps(event) + "\n")

    # Also log to console
    logging.warning(f"[SECURITY] {event_type} | IP={ip} | {details}")


# ─────────────────────────────────────────────────────────────
# In-memory rate limiter + IP block store
# ─────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self):
        self._lock        = Lock()
        self._requests    = defaultdict(list)   # ip -> [timestamps]
        self._blocked     = {}                  # ip -> unblock_timestamp
        self._total_count = defaultdict(int)    # ip -> total requests ever

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocked:
                if time.time() < self._blocked[ip]:
                    return True
                else:
                    del self._blocked[ip]   # block expired
            return False

    def block(self, ip: str, duration: int = BLOCK_DURATION):
        with self._lock:
            self._blocked[ip] = time.time() + duration
            log_event("IP_BLOCKED", ip, {
                "duration_seconds": duration,
                "unblock_at": datetime.fromtimestamp(
                    self._blocked[ip], tz=timezone.utc
                ).isoformat()
            })

    def record_and_check(self, ip: str) -> tuple:
        """
        Record a request and check rate limit.
        Returns (allowed: bool, current_count: int, remaining: int)
        """
        with self._lock:
            now = time.time()
            window_start = now - RATE_LIMIT_WINDOW

            # Purge old entries
            self._requests[ip] = [
                t for t in self._requests[ip] if t > window_start
            ]

            # Record this request
            self._requests[ip].append(now)
            self._total_count[ip] += 1
            count = len(self._requests[ip])

            # Hard block if total count exceeds absolute threshold
            if self._total_count[ip] >= BLOCK_THRESHOLD:
                return False, count, 0

            allowed   = count <= RATE_LIMIT_MAX_REQS
            remaining = max(0, RATE_LIMIT_MAX_REQS - count)
            return allowed, count, remaining

    def get_stats(self, ip: str) -> dict:
        with self._lock:
            now = time.time()
            window_start = now - RATE_LIMIT_WINDOW
            recent = [t for t in self._requests[ip] if t > window_start]
            return {
                "ip": ip,
                "requests_in_window": len(recent),
                "total_requests": self._total_count[ip],
                "is_blocked": ip in self._blocked,
            }


rate_limiter = RateLimiter()

# ─────────────────────────────────────────────────────────────
# Detection helpers
# ─────────────────────────────────────────────────────────────

def detect_sqli_pattern(value: str) -> list:
    """Return list of matched pattern descriptions."""
    hits = []
    for i, pattern in enumerate(COMPILED_SQLI):
        if pattern.search(value):
            hits.append(SQLI_PATTERNS[i])
    return hits


def detect_sqlmap_ua(user_agent: str) -> bool:
    ua_lower = user_agent.lower()
    return any(sig in ua_lower for sig in SQLMAP_UA_PATTERNS)


def normalize_response_time(start: float):
    """Ensure minimum response time to prevent timing oracle attacks."""
    elapsed = time.time() - start
    if elapsed < MIN_RESPONSE_TIME:
        time.sleep(MIN_RESPONSE_TIME - elapsed + random.uniform(0, 0.05))


# ─────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────

def get_db():
    return sqlite3.connect("users.db")


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        ("admin", "supersecret")
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────
# Flask App
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)


@app.before_request
def firewall():
    """
    Runs before every request.
    Checks: IP block → rate limit → SQLi pattern → User-Agent
    """
    ip         = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    start      = time.time()
    request.start_time = start  # store for response normalization

    # ── 1. Hard IP block check ──────────────────────────────
    if rate_limiter.is_blocked(ip):
        log_event("BLOCKED_REQUEST", ip, {"reason": "IP_IN_BLOCKLIST"})
        abort(403)

    # ── 2. SQLMap / scanner User-Agent detection ────────────
    if detect_sqlmap_ua(user_agent):
        log_event("SCANNER_DETECTED", ip, {"user_agent": user_agent})
        rate_limiter.block(ip, duration=BLOCK_DURATION)
        abort(403)

    # ── 3. Rate limiting ────────────────────────────────────
    allowed, count, remaining = rate_limiter.record_and_check(ip)
    if not allowed:
        log_event("RATE_LIMIT_EXCEEDED", ip, {
            "count": count,
            "window_seconds": RATE_LIMIT_WINDOW
        })
        rate_limiter.block(ip)
        abort(429)

    # ── 4. SQLi pattern detection on all parameters ─────────
    all_params = {**request.args, **request.form}
    for param, value in all_params.items():
        hits = detect_sqli_pattern(value)
        if hits:
            log_event("SQLI_PATTERN_DETECTED", ip, {
                "parameter": param,
                "value": value[:100],
                "patterns_matched": hits,
                "user_agent": user_agent,
            })
            rate_limiter.block(ip, duration=BLOCK_DURATION)
            abort(400)

    # ── 5. Honeypot parameter ───────────────────────────────
    # Legitimate users never send this hidden field
    if request.args.get("__hp") or request.form.get("__hp"):
        log_event("HONEYPOT_TRIGGERED", ip, {"user_agent": user_agent})
        rate_limiter.block(ip, duration=BLOCK_DURATION)
        abort(400)


@app.after_request
def add_security_headers(response):
    """Add standard security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Cache-Control"]            = "no-store"
    # Rate limit headers for legitimate clients
    ip        = request.remote_addr
    stats     = rate_limiter.get_stats(ip)
    remaining = max(0, RATE_LIMIT_MAX_REQS - stats["requests_in_window"])
    response.headers["X-RateLimit-Limit"]     = str(RATE_LIMIT_MAX_REQS)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response


@app.route("/")
def home():
    return """
    <h2>Secure Login (Parameterized + Defended)</h2>
    <form method="GET" action="/login">
        Username: <input name="username"><br>
        Password: <input name="password"><br>
        <input type="hidden" name="__hp" value="" style="display:none">
        <input type="submit">
    </form>
    """


@app.route("/login")
def login():
    start    = getattr(request, "start_time", time.time())
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn   = get_db()
    cursor = conn.cursor()

    # Parameterized query — root fix
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    try:
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
    except Exception:
        conn.close()
        normalize_response_time(start)
        # Never leak DB errors to client
        return "An error occurred. Please try again.", 500

    conn.close()
    normalize_response_time(start)

    if result:
        return f"Welcome {result[1]}!"
    return "Invalid username or password", 401


# ── Admin endpoint: view blocked IPs and security stats ─────
@app.route("/admin/security-stats")
def security_stats():
    # In production: protect with auth middleware
    if request.remote_addr != "127.0.0.1":
        abort(403)

    try:
        events = []
        if log_path.exists():
            for line in log_path.read_text().splitlines()[-50:]:
                events.append(json.loads(line))
        return jsonify({
            "recent_events": events,
            "rate_limit_config": {
                "window_seconds": RATE_LIMIT_WINDOW,
                "max_requests": RATE_LIMIT_MAX_REQS,
                "block_threshold": BLOCK_THRESHOLD,
                "block_duration_seconds": BLOCK_DURATION,
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("[*] Starting defended sec app on http://127.0.0.1:6001")
    print("[*] Security features active:")
    print(f"    - Rate limit : {RATE_LIMIT_MAX_REQS} req/{RATE_LIMIT_WINDOW}s per IP")
    print(f"    - Auto-block : after {BLOCK_THRESHOLD} total requests ({BLOCK_DURATION}s)")
    print(f"    - SQLi patterns : {len(SQLI_PATTERNS)} signatures")
    print(f"    - Scanner UA detection : {len(SQLMAP_UA_PATTERNS)} signatures")
    print(f"    - Honeypot field : active")
    print(f"    - Timing normalization : >{MIN_RESPONSE_TIME}s floor")
    print(f"    - Security log : {log_path}")
    app.run(host="127.0.0.1", port=6001, debug=False)
