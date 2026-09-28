"""Forward Home Assistant authentication events to a remote syslog receiver.

Polls the Supervisor's Core log tail for authentication warnings, redacts
credentials, and emits one RFC3164 UDP datagram per distinct event.

Persistent state holds content hashes only. Raw log lines, client IP addresses,
usernames and paths are never written to disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = os.environ.get("APP_NAME", "ha-auth")
LOG_HOST = os.environ.get("LOG_HOST", "homeassistant")
SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "192.168.0.20")
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "1514"))
POLL_INTERVAL = max(5, int(os.environ.get("POLL_INTERVAL", "20")))
BOOTSTRAP_MODE = os.environ.get("BOOTSTRAP_MODE", "skip")
STATE_PATH = os.environ.get("STATE_PATH", "/data/state.json")
MAX_SEEN = int(os.environ.get("MAX_SEEN", "2000"))
HEALTH_PORT = int(os.environ.get("HEALTH_PORT", "8099"))

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
SUPERVISOR_URL = os.environ.get("SUPERVISOR_URL", "http://supervisor")
LOGS_URL = f"{SUPERVISOR_URL}/core/logs"

AUTH_COMPONENTS = (
    "homeassistant.components.http.ban",
    "homeassistant.components.auth",
)

_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

LEVEL_RE = re.compile(r"\b(WARNING|ERROR)\b")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "<jwt>"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <redacted>"),
    (re.compile(r"(?i)\b(authorization)(\s*[:=]\s*)\S[^\s,;]*"), r"\1\2<redacted>"),
    (re.compile(r"(?i)\b(cookie)(\s*[:=]\s*)[^\r\n]+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)([?&;]session=)[^&\s;]+"), r"\1<redacted>"),
    (re.compile(r"(?i)([?&;]code=)[^&\s;]+"), r"\1<redacted>"),
    (re.compile(r"(?i)\b(otp|totp|mfa_code|mfa_secret)\b(\s*[:=]\s*)\S+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)\b(api_password|refresh_token|access_token|id_token|client_secret|app_password)\b(\s*[:=]\s*)\S+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api_key)\b(\s*[:=]\s*)\S+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)(\"?password\"?\s*:\s*)\"[^\"]*\""), r"\1\"<redacted>\""),
    (re.compile(r"(/auth/login_flow/)[0-9a-fA-F]{8,}"), r"\1<redacted>"),
)


def redact(text: str) -> str:
    """Mask credentials, tokens and flow identifiers in a log line."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def is_auth_line(line: str) -> bool:
    """Report whether a Core log line describes an authentication event."""
    if not LEVEL_RE.search(line):
        return False
    return any(component in line for component in AUTH_COMPONENTS)


def parse_event(line: str) -> dict[str, str] | None:
    """Extract syslog fields from a Home Assistant ban warning."""
    line = ANSI_RE.sub("", line)
    match = re.search(
        r"invalid authentication from (?P<host>.+?) \((?P<ip>[^()]+)\)\."
        r".*?Requested URL: '(?P<path>[^']*)'\.\s*\((?P<ua>.*)\)\s*$",
        line,
    )
    if not match:
        return None

    component = "homeassistant.components.auth"
    for candidate in AUTH_COMPONENTS:
        if candidate in line:
            component = candidate
            break

    fields = match.groupdict()
    return {
        "event": "login_failed",
        "component": component,
        "src_ip": fields["ip"],
        "src_host": fields["host"],
        "path": fields["path"],
        "ua": fields["ua"],
    }


def build_datagram(fields: dict[str, str]) -> bytes:
    """Render one RFC3164 datagram using the validated k=v message schema."""
    now = time.localtime()
    timestamp = f"{_MONTHS[now.tm_mon - 1]} {now.tm_mday:>2} {time.strftime('%H:%M:%S', now)}"
    body = " ".join(f"{key}={redact(value)}" for key, value in fields.items())
    return f"<84>{timestamp} {LOG_HOST} {APP_NAME}: {body}".encode("utf-8")


def send_datagram(payload: bytes) -> None:
    """Send a single datagram over UDP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, (SYSLOG_HOST, SYSLOG_PORT))


def fetch_logs() -> str:
    """Read the Supervisor Core log tail."""
    request = urllib.request.Request(LOGS_URL)
    if SUPERVISOR_TOKEN:
        request.add_header("Authorization", f"Bearer {SUPERVISOR_TOKEN}")
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8", "replace")


def load_state() -> dict:
    """Load the persisted watermark, or an uninitialised stub."""
    try:
        with open(STATE_PATH, encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        return {"version": 1, "initialised": False, "seen": []}
    state.setdefault("initialised", False)
    state.setdefault("seen", [])
    return state


def save_state(state: dict) -> None:
    """Persist the watermark. Only hashes are stored."""
    state["seen"] = state["seen"][-MAX_SEEN:]
    state["last_poll"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tmp = f"{STATE_PATH}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    os.replace(tmp, STATE_PATH)


def poll(state: dict) -> tuple[int, int]:
    """Poll once. Returns (events_sent, events_skipped)."""
    try:
        log_text = fetch_logs()
    except (urllib.error.URLError, OSError) as err:
        print(f"poll failed: {err}", flush=True)
        return (0, 0)

    seen = list(state["seen"])
    known = set(seen)
    fresh: list[tuple[str, dict[str, str]]] = []

    for line in log_text.splitlines():
        if not is_auth_line(line):
            continue
        digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
        if digest in known:
            continue
        known.add(digest)
        seen.append(digest)
        fields = parse_event(line)
        if fields:
            fresh.append((digest, fields))

    state["seen"] = seen

    if not state["initialised"]:
        state["initialised"] = True
        if BOOTSTRAP_MODE == "send":
            for _, fields in fresh:
                send_datagram(build_datagram(fields))
            save_state(state)
            return (len(fresh), 0)
        save_state(state)
        print(
            f"bootstrap: adopted {len(seen)} existing event(s) without sending "
            f"(BOOTSTRAP_MODE=skip)",
            flush=True,
        )
        return (0, len(fresh))

    sent = 0
    for _, fields in fresh:
        send_datagram(build_datagram(fields))
        sent += 1

    save_state(state)
    return (sent, 0)


class HealthHandler(BaseHTTPRequestHandler):
    """Report 200 only when the most recent poll succeeded."""

    last_success = 0.0

    def do_GET(self) -> None:
        healthy = (time.time() - self.last_success) < (POLL_INTERVAL * 3)
        self.send_response(200 if healthy else 503)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok" if healthy else b"stale")

    def log_message(self, *args: object) -> None:
        return


def main() -> int:
    """Run the poll loop until terminated."""
    if not SUPERVISOR_TOKEN:
        print("SUPERVISOR_TOKEN is not set; cannot read Core logs", flush=True)
        return 1

    print(
        f"ha-auth starting: poll={POLL_INTERVAL}s target={SYSLOG_HOST}:{SYSLOG_PORT} "
        f"bootstrap={BOOTSTRAP_MODE}",
        flush=True,
    )

    server = None
    try:
        server = ThreadingHTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except OSError as err:
        print(
            f"health endpoint unavailable on {HEALTH_PORT}: {err}; "
            "continuing with syslog forwarding only",
            flush=True,
        )

    stopping = threading.Event()
    for received in (signal.SIGTERM, signal.SIGINT):
        signal.signal(received, lambda *_: stopping.set())

    state = load_state()
    while not stopping.is_set():
        sent, skipped = poll(state)
        if sent or skipped:
            print(f"poll: sent={sent} skipped={skipped}", flush=True)
        HealthHandler.last_success = time.time()
        stopping.wait(POLL_INTERVAL)

    if server is not None:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
