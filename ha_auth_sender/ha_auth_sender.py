"""Forward Home Assistant authentication events to syslog and Alertmanager.

Polls the Supervisor's Core log tail for authentication warnings, redacts
credentials, and emits one RFC3164 UDP datagram per distinct event. Optionally
also POSTs Alertmanager-shaped alerts and detects per-IP login bursts.

Home Assistant does not log the attempted username on a failed login:
``process_wrong_login`` composes its line from the peer address, the requested
URL and the user agent only. ``attempted_user`` is therefore ``(unknown)`` on all
live data, and burst detection is keyed on per-IP attempt count rather than on
distinct usernames.

Persistent state holds content hashes for deduplication plus bounded per-IP
timing state, so rate limits and burst detection survive a restart. Raw log
lines, usernames and paths are never written to disk.
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
from collections import OrderedDict
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

# Alertmanager sink. Disabled unless ALERTMANAGER_URL is set, so the default
# configuration keeps today's behaviour exactly (syslog only).
ALERTMANAGER_URL = os.environ.get("ALERTMANAGER_URL", "").strip()
ALERTMANAGER_TOKEN_FILE = os.environ.get("ALERTMANAGER_TOKEN_FILE", "").strip()
ALERTMANAGER_TOKEN_OPTION = os.environ.get("ALERTMANAGER_TOKEN", "").strip()
ALERTMANAGER_TIMEOUT = int(os.environ.get("ALERTMANAGER_TIMEOUT", "10"))
INSTANCE = os.environ.get("INSTANCE", "homeassistant")

# Burst detection and outbound throttling.
SPRAY_THRESHOLD = max(1, int(os.environ.get("SPRAY_THRESHOLD", "10")))
SPRAY_WINDOW_MINUTES = max(1, int(os.environ.get("SPRAY_WINDOW_MINUTES", "10")))
EVENT_RATE_LIMIT_SECONDS = max(0, int(os.environ.get("EVENT_RATE_LIMIT_SECONDS", "60")))
SPRAY_RATE_LIMIT_SECONDS = max(0, int(os.environ.get("SPRAY_RATE_LIMIT_SECONDS", "300")))
MAX_TRACKED_IPS = max(1, int(os.environ.get("MAX_TRACKED_IPS", "2048")))
IP_TTL_HOURS = max(1, int(os.environ.get("IP_TTL_HOURS", "24")))

ALERTMANAGER_ENABLED = bool(ALERTMANAGER_URL)

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


# --------------------------------------------------------------------------
# Sanitisation of attacker-controlled strings destined for alert descriptions
# --------------------------------------------------------------------------

# Whitespace-like control characters become a SPACE rather than being deleted.
# Deleting them fuses adjacent words ("root\nadmin" -> "rootadmin"), which
# corrupts both the reported value and any dictionary comparison. str.translate
# keys on ordinals, so the table must map ord(char), not char.
_WS_CONTROL_MAP = {ord(char): " " for char in "\t\n\r\f\v"}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MARKDOWN_RE = re.compile(r"[*_`\[\]()<>|#\\]")
_WHITESPACE_RE = re.compile(r"\s+")

SANITISE_LIMIT = 40
TRUNCATION_MARKER = "...TRUNCATED"
UNKNOWN_USER = "(unknown)"
UNKNOWN_CLASS = "unknown"

DICTIONARY_NAMES = frozenset({
    "admin", "administrator", "admin1", "admin2", "root", "superuser", "super",
    "su", "user", "user1", "test", "testing", "guest", "guest1", "operator",
    "support", "service", "support1", "ha", "homeassistant", "home", "hass",
    "default", "pi", "ubuntu", "debian", "oracle", "postgres", "mysql", "www",
    "www-data", "ftp", "backup", "monitor", "monitoring", "nagios", "jenkins",
    "git", "gitlab", "vault", "homelab", "matrix", "sysadmin", "system", "dev",
    "developer", "devops", "ansible", "docker", "container", "nas", "synology",
    "unifi", "demo", "public", "manager", "info", "security", "password",
    "pass", "changeme", "letmein", "qwerty", "1234", "12345", "123456",
})


def sanitise(value: str | None, limit: int = SANITISE_LIMIT) -> str:
    """Reduce an attacker-controlled string to a safe, bounded token.

    Order matters: whitespace-like controls become spaces first so that word
    boundaries survive, then remaining control bytes are dropped, then markdown
    and link punctuation, then runs of whitespace collapse. Over-long values are
    hard-truncated and carry a marker so a consumer can tell truncation apart
    from a genuinely short value. Anything that reduces to nothing becomes
    ``(unknown)`` -- a value is never invented.
    """
    if value is None:
        return UNKNOWN_USER
    text = str(value).translate(_WS_CONTROL_MAP)
    text = _CONTROL_RE.sub("", text)
    text = _MARKDOWN_RE.sub("", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    if not text:
        return UNKNOWN_USER
    if len(text) > limit:
        return text[:limit] + TRUNCATION_MARKER
    return text


def classify_user(value: str | None) -> tuple[str, str]:
    """Return the sanitised username and its dictionary classification."""
    safe = sanitise(value)
    if safe == UNKNOWN_USER:
        return (UNKNOWN_USER, UNKNOWN_CLASS)
    return (safe, "dictionary" if safe.lower() in DICTIONARY_NAMES else UNKNOWN_CLASS)


# Routes Home Assistant emits are rebuilt from validated parts instead of being
# sanitised as free text. Running the markdown filter across a whole path would
# strip the underscore out of HA's own "/auth/login_flow/<id>" and corrupt it.
_KNOWN_ROUTES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/auth/login_flow/[0-9a-fA-F]{8,}$"), "auth.login_flow"),
    (re.compile(r"^/auth/login_flow/?$"), "auth.login_flow"),
    (re.compile(r"^/auth/token/?$"), "auth.token"),
    (re.compile(r"^/auth/authorize/?$"), "auth.authorize"),
    (re.compile(r"^/auth/providers/?$"), "auth.providers"),
    (re.compile(r"^/auth/refresh_token/?$"), "auth.refresh_token"),
    (re.compile(r"^/?$"), "root"),
)

_FLOW_ID_RE = re.compile(r"^/auth/login_flow/([0-9a-fA-F]{8,})$")
_PATH_SPLIT_RE = re.compile(r"[/?#]")


def canonical_route(path: str | None) -> str:
    """Map a requested URL onto a short token, or sanitise it if unrecognised."""
    if path is None:
        return UNKNOWN_USER
    candidate = _CONTROL_RE.sub("", str(path).strip())[:256]
    for pattern, name in _KNOWN_ROUTES:
        if pattern.match(candidate):
            return name
    # Unrecognised paths ARE attacker-controlled and get strict sanitisation.
    return sanitise(candidate, limit=80)


def extract_flow_id(path: str | None) -> str:
    """Return the hex flow identifier for a login-flow request, else ``-``.

    A flow identifier is a session handle, not a credential: it cannot be used
    to authenticate. It is reported in spray alerts as a "distinct sessions"
    statistic. The syslog path continues to redact it.
    """
    if not path:
        return "-"
    match = _FLOW_ID_RE.match(_CONTROL_RE.sub("", str(path).strip()))
    if not match:
        return "-"
    return match.group(1)[:16]


def extract_username(line: str) -> str | None:
    """Recover a username from a log line, or ``None`` when absent.

    Home Assistant never emits this, so live data yields ``None`` and the caller
    reports ``(unknown)``. The hook exists so the sanitiser and classifier are
    exercised offline and would work unchanged if a source ever added it.
    """
    match = re.search(r"\busername\s*[=:]\s*(\S{1,200})", line, re.IGNORECASE)
    if not match:
        return None
    candidate = match.group(1).strip().strip("'\"")
    return candidate or None


# --------------------------------------------------------------------------
# Credential handling
# --------------------------------------------------------------------------


def load_alertmanager_token() -> str:
    """Read the bearer token at send time. Never logged, never returned.

    Prefers a file so the secret stays out of add-on options: options are stored
    in ``.storage``, shown in the add-on UI, and included in diagnostics dumps.
    Falls back to the option value for simple setups. The result is held only in
    a local variable for the duration of one send.
    """
    if ALERTMANAGER_TOKEN_FILE:
        try:
            with open(ALERTMANAGER_TOKEN_FILE, encoding="utf-8") as handle:
                token = handle.read().strip()
            if token:
                return token
        except OSError as err:
            # The path may legitimately be absent; never echo file contents.
            print(
                f"alertmanager: token file unreadable ({err.__class__.__name__})",
                flush=True,
            )
    return ALERTMANAGER_TOKEN_OPTION


def scrub_token(text: str, token: str) -> str:
    """Remove a live token from text bound for a log line or alert body."""
    if not token:
        return text
    return text.replace(token, "<redacted>")


def scrub_error(err: BaseException, token: str) -> str:
    """Render an exception for logging with the token removed.

    A urllib error stringifies the request, which can carry the Authorization
    header, so the message is scrubbed before it is ever printed.
    """
    return scrub_token(f"{err.__class__.__name__}: {err}", token)


# --------------------------------------------------------------------------
# Per-IP burst detection
# --------------------------------------------------------------------------


class IpTracker:
    """Bounded, expiring record of per-IP attempt timings.

    Ordered by last-seen so the oldest idle entry is evicted first, keeping
    memory flat under a flood from many source addresses.
    """

    def __init__(self, cap: int = MAX_TRACKED_IPS, ttl_hours: int = IP_TTL_HOURS) -> None:
        self._cap = cap
        self._ttl = ttl_hours * 3600
        self._entries: OrderedDict[str, dict] = OrderedDict()

    def _expired(self, entry: dict, now: float) -> bool:
        return not entry["attempts"] or (now - entry["attempts"][-1]) > self._ttl

    def record(self, ip: str, flow_id: str, now: float) -> dict:
        """Record one attempt and return the windowed view for that IP.

        Recording is unconditional: throttling applies only to notifications, so
        detection keeps accumulating while alerts are muted.
        """
        entry = self._entries.get(ip)
        if entry is None or self._expired(entry, now):
            entry = {"attempts": [], "flows": []}
            self._entries[ip] = entry
        self._entries.move_to_end(ip)
        entry["attempts"].append(now)
        if flow_id and flow_id != "-" and flow_id not in entry["flows"]:
            entry["flows"].append(flow_id)
        self._prune(now)
        return entry

    def window(self, ip: str, now: float, minutes: int) -> dict:
        """Return attempts and distinct sessions inside the rolling window."""
        entry = self._entries.get(ip)
        if entry is None:
            return {"attempts": 0, "flows": []}
        cutoff = now - (minutes * 60)
        attempts = [ts for ts in entry["attempts"] if ts >= cutoff]
        flows = [f for f in entry["flows"]]
        return {"attempts": len(attempts), "flows": flows}

    def _prune(self, now: float) -> None:
        for ip in [ip for ip, e in self._entries.items() if self._expired(e, now)]:
            del self._entries[ip]
        while len(self._entries) > self._cap:
            self._entries.popitem(last=False)

    # -- persistence -------------------------------------------------------
    def dump(self) -> dict:
        return {ip: {"a": entry["attempts"], "f": entry["flows"]}
                for ip, entry in self._entries.items()}

    def load(self, blob: dict) -> None:
        if not isinstance(blob, dict):
            return
        for ip, entry in list(blob.items())[: self._cap]:
            if not isinstance(entry, dict):
                continue
            attempts = [float(v) for v in entry.get("a", []) if isinstance(v, (int, float))]
            flows = [str(v)[:16] for v in entry.get("f", []) if isinstance(v, str)]
            if attempts:
                self._entries[str(ip)[:64]] = {"attempts": attempts, "flows": flows}
        self._prune(time.time())


class RateLimiter:
    """Per-key outbound throttle with counted suppressions.

    Suppressed events are counted, never discarded silently, and a single
    summary is drained once per poll cycle.
    """

    def __init__(self) -> None:
        self._last: dict[tuple[str, str], float] = {}
        self._suppressed: dict[str, int] = {}

    def allow(self, kind: str, key: str, now: float, window: int) -> bool:
        """Report whether an alert may be sent now, counting a suppression."""
        if window <= 0:
            return True
        slot = (kind, key)
        previous = self._last.get(slot)
        if previous is not None and (now - previous) < window:
            self._suppressed[kind] = self._suppressed.get(kind, 0) + 1
            return False
        self._last[slot] = now
        return True

    def drain_summary(self) -> str | None:
        """Return one summary line for everything suppressed, then reset."""
        if not self._suppressed:
            return None
        parts = [f"{count} {kind}" for kind, count in sorted(self._suppressed.items())]
        self._suppressed = {}
        return "suppressed " + ", ".join(parts)

    def dump(self) -> dict:
        return {
            "last": {f"{k}\x00{key}": ts for (k, key), ts in self._last.items()},
            "suppressed": dict(self._suppressed),
        }

    def load(self, blob: dict) -> None:
        if not isinstance(blob, dict):
            return
        for slot, ts in (blob.get("last") or {}).items():
            kind, _, key = str(slot).partition("\x00")
            if isinstance(ts, (int, float)) and key:
                self._last[(kind, key)] = float(ts)
        suppressed = blob.get("suppressed") or {}
        if isinstance(suppressed, dict):
            self._suppressed = {str(k): int(v) for k, v in suppressed.items()
                                if isinstance(v, (int, float))}


# --------------------------------------------------------------------------
# Alertmanager sink
# --------------------------------------------------------------------------


def build_alert(
    alertname: str,
    severity: str,
    summary: str,
    description: str,
    instance: str = INSTANCE,
) -> dict:
    """Assemble one Alertmanager-shaped alert.

    Labels carry routing only; the notifier discards everything outside its
    whitelist, so all detail travels in the description. Both ``job`` and
    ``component`` are set to ``homeassistant`` because the notifier's whitelist
    maps its ``component`` output field from ``labels.job`` while its routing
    logic may key on a label literally named ``component``. Setting both covers
    either reading.
    """
    return {
        "labels": {
            "alertname": alertname,
            "job": "homeassistant",
            "component": "homeassistant",
            "instance": instance,
        },
        "annotations": {
            "summary": summary,
            "description": description,
        },
    }


def post_alert(alert: dict) -> tuple[int, str]:
    """POST one alert. Returns (http_status, body). TLS verification is on."""
    token = load_alertmanager_token()
    body = json.dumps(alert).encode("utf-8")
    request = urllib.request.Request(
        ALERTMANAGER_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"{APP_NAME}/{INSTANCE}",
        },
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=ALERTMANAGER_TIMEOUT) as response:
            status = int(getattr(response, "status", 0) or 0)
            text = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        status = int(err.code)
        try:
            text = err.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - body is best-effort only
            text = ""
    except (urllib.error.URLError, OSError) as err:
        # Never include the token in a log line.
        print(f"alertmanager: send failed ({scrub_error(err, token)})", flush=True)
        return (0, scrub_token(str(err), token))
    return (status, scrub_token(text[:200], token))


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


def save_state(state: dict, tracker: "IpTracker | None" = None,
               limiter: "RateLimiter | None" = None) -> None:
    """Persist the watermark plus bounded detection state. Only hashes are
    stored for deduplication; per-IP entries hold attempt timings and flow ids.
    """
    state["seen"] = state["seen"][-MAX_SEEN:]
    state["last_poll"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if tracker is not None:
        state["tracker"] = tracker.dump()
    if limiter is not None:
        state["rate_limits"] = limiter.dump()
    tmp = f"{STATE_PATH}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    os.replace(tmp, STATE_PATH)


def emit_event_alert(fields: dict[str, str], username: str | None,
                     limiter: "RateLimiter") -> bool:
    """Post one per-event alert. Returns True if it was sent, not throttled."""
    safe_user, user_class = classify_user(username)
    route = canonical_route(fields.get("path"))
    flow_id = extract_flow_id(fields.get("path"))
    description = (
        f"login_failed from={sanitise(fields.get('src_ip'), 64)} "
        f"route={route} ua={sanitise(fields.get('ua'), 80)} "
        f"attempted_user={safe_user} user_class={user_class}"
    )
    if not limiter.allow("event", fields.get("src_ip", "-"), time.time(),
                         EVENT_RATE_LIMIT_SECONDS):
        return False
    status, body = post_alert(build_alert(
        "HALoginEvent", "warning",
        f"Failed login from {sanitise(fields.get('src_ip'), 64)}",
        description,
    ))
    print(f"alertmanager: HALoginEvent status={status} flow={flow_id} "
          f"body={body[:80]!r}", flush=True)
    return True


def emit_spray_alert(ip: str, tracker: "IpTracker", limiter: "RateLimiter") -> bool:
    """Post one burst alert if the rolling window is over threshold."""
    now = time.time()
    view = tracker.window(ip, now, SPRAY_WINDOW_MINUTES)
    if view["attempts"] < SPRAY_THRESHOLD:
        return False
    if not limiter.allow("spray", ip, now, SPRAY_RATE_LIMIT_SECONDS):
        return False
    sample = ",".join(view["flows"][:10]) if view["flows"] else "-"
    description = (
        f"spray_ip={sanitise(ip, 64)} "
        f"spray_window_minutes={SPRAY_WINDOW_MINUTES} "
        f"spray_attempts={view['attempts']} "
        f"spray_sessions={len(view['flows'])} "
        f"spray_sample_flow_ids={sanitise(sample, 200)} "
        f"note=keyed_on_attempt_count_no_username_in_ha_logs"
    )
    status, body = post_alert(build_alert(
        "HALoginSpray", "critical",
        f"Login burst from {sanitise(ip, 64)}",
        description,
    ))
    print(f"alertmanager: HALoginSpray status={status} body={body[:80]!r}",
          flush=True)
    return True


def poll(state: dict, tracker: "IpTracker", limiter: "RateLimiter") -> tuple[int, int]:
    """Poll once. Returns (events_sent, events_skipped).

    Syslog emission is unchanged. Alertmanager emission and burst detection are
    additive: recording an attempt always happens, and only the notification is
    throttled, so a muted channel never blinds detection.
    """
    try:
        log_text = fetch_logs()
    except (urllib.error.URLError, OSError) as err:
        print(f"poll failed: {err}", flush=True)
        return (0, 0)

    seen = list(state["seen"])
    known = set(seen)
    fresh: list[tuple[str, dict[str, str], str | None]] = []

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
            fresh.append((digest, fields, extract_username(line)))

    state["seen"] = seen

    if not state["initialised"]:
        state["initialised"] = True
        if BOOTSTRAP_MODE == "send":
            for _, fields, _ in fresh:
                send_datagram(build_datagram(fields))
            save_state(state, tracker, limiter)
            return (len(fresh), 0)
        save_state(state, tracker, limiter)
        print(
            f"bootstrap: adopted {len(seen)} existing event(s) without sending "
            f"(BOOTSTRAP_MODE=skip)",
            flush=True,
        )
        return (0, len(fresh))

    now = time.time()
    sent = 0
    spray_hits: set[str] = set()
    for _, fields, username in fresh:
        # Syslog first, exactly as before.
        send_datagram(build_datagram(fields))
        sent += 1

        ip = fields.get("src_ip", "-")
        tracker.record(ip, extract_flow_id(fields.get("path")), now)
        if ALERTMANAGER_ENABLED:
            emit_event_alert(fields, username, limiter)
        if tracker.window(ip, now, SPRAY_WINDOW_MINUTES)["attempts"] >= SPRAY_THRESHOLD:
            spray_hits.add(ip)

    if ALERTMANAGER_ENABLED:
        for ip in spray_hits:
            emit_spray_alert(ip, tracker, limiter)
        summary = limiter.drain_summary()
        if summary:
            print(f"alertmanager: {summary}", flush=True)

    save_state(state, tracker, limiter)
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
    print(
        f"alertmanager: {'enabled' if ALERTMANAGER_ENABLED else 'disabled'} "
        f"url={'set' if ALERTMANAGER_ENABLED else 'unset'} "
        f"instance={INSTANCE} spray_threshold={SPRAY_THRESHOLD}/"
        f"{SPRAY_WINDOW_MINUTES}min lru={MAX_TRACKED_IPS} ttl={IP_TTL_HOURS}h",
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
    tracker = IpTracker()
    limiter = RateLimiter()
    tracker.load(state.get("tracker") or {})
    limiter.load(state.get("rate_limits") or {})

    while not stopping.is_set():
        sent, skipped = poll(state, tracker, limiter)
        if sent or skipped:
            print(f"poll: sent={sent} skipped={skipped}", flush=True)
        HealthHandler.last_success = time.time()
        stopping.wait(POLL_INTERVAL)

    if server is not None:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
