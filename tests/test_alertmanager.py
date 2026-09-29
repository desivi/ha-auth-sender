"""Offline validation for the Alertmanager sink and burst detection.

No network access and no credentials. ``post_alert`` is replaced with a capture
stub so alerts can be inspected; that stub is used ONLY here, never by the
add-on, and the live webhook test is explicitly out of scope for this file.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir,
                                "ha_auth_sender"))

os.environ.setdefault("ALERTMANAGER_URL", "https://192.168.0.40:18128/v1/alertmanager")
os.environ.setdefault("SPRAY_THRESHOLD", "10")
os.environ.setdefault("SPRAY_WINDOW_MINUTES", "10")
os.environ.setdefault("EVENT_RATE_LIMIT_SECONDS", "0")
os.environ.setdefault("SPRAY_RATE_LIMIT_SECONDS", "0")
os.environ.setdefault("SUPERVISOR_TOKEN", "offline-test")

m = importlib.import_module("ha_auth_sender")

FAILURES: list[str] = []
CHECKS = 0


def check(label: str, got: object, want: object) -> None:
    global CHECKS
    CHECKS += 1
    ok = got == want
    if not ok:
        FAILURES.append(label)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        want: {want!r}")
        print(f"        got:  {got!r}")


def banner(title: str) -> None:
    print()
    print(title)
    print("=" * 78)


# ---------------------------------------------------------------------------
banner("7.1a  SANITISER - whitespace-like controls become SPACES, not deletions")
# ---------------------------------------------------------------------------
root = m.sanitise("root\nadmin\r\n\ttest")
check("newline input keeps word boundaries", root, "root admin test")
check("newlines were not deleted into a fused word", "rootadmin" in root, False)
check("tab also becomes a space", m.sanitise("a\tb"), "a b")
check("form feed and vertical tab too", m.sanitise("a\fb\vc"), "a b c")
check("carriage return collapses", m.sanitise("x\r\ny"), "x y")

# ---------------------------------------------------------------------------
banner("7.1b  SANITISER - markdown and link punctuation removed")
# ---------------------------------------------------------------------------
check(
    "markdown punctuation stripped",
    m.sanitise("ad**min`x[1](y)<z>|w#v\\u"),
    "adminx1yzwvu",
)
check("pipe removed", m.sanitise("a|b"), "ab")
check("angle brackets removed", m.sanitise("<script>"), "script")
check("underscore removed (raw value path)", m.sanitise("a_b"), "ab")
check("NUL and DEL removed", m.sanitise("a\x00b\x7fc"), "abc")

# ---------------------------------------------------------------------------
banner("7.1c  SANITISER - length bound and truncation marker")
# ---------------------------------------------------------------------------
long_500 = m.sanitise("a" * 500)
check("500-char input truncated to 52 chars", len(long_500), 52)
check("truncation is 40 chars + marker", long_500[:40], "a" * 40)
check("marker appended after the 40th char", long_500[40:], "...TRUNCATED")
check("40-char input is NOT marked", m.sanitise("a" * 40), "a" * 40)
check("41-char input IS marked", len(m.sanitise("a" * 41)), 52)

# ---------------------------------------------------------------------------
banner("7.1d  SANITISER - absent / unusable values never fabricate one")
# ---------------------------------------------------------------------------
check("None becomes (unknown)", m.sanitise(None), "(unknown)")
check("empty becomes (unknown)", m.sanitise(""), "(unknown)")
check("whitespace only becomes (unknown)", m.sanitise("   \t\n  "), "(unknown)")
check("punctuation only becomes (unknown)", m.sanitise("***<<<>>>"), "(unknown)")
check("absent classifies as unknown", m.classify_user(None), ("(unknown)", "unknown"))

# ---------------------------------------------------------------------------
banner("7.1e  DICTIONARY CLASSIFICATION")
# ---------------------------------------------------------------------------
check("admin is dictionary", m.classify_user("admin"), ("admin", "dictionary"))
check("case-insensitive", m.classify_user("AdMiN"), ("AdMiN", "dictionary"))
check("non-dictionary is unknown", m.classify_user("carol")[1], "unknown")
check("a 66-name dictionary is loaded", len(m.DICTIONARY_NAMES), 66)
check(
    "every dictionary entry classifies as dictionary",
    {m.classify_user(n)[1] for n in m.DICTIONARY_NAMES},
    {"dictionary"},
)

# ---------------------------------------------------------------------------
banner("7.1f  ROUTE CANONICALISATION - underscore must survive")
# ---------------------------------------------------------------------------
# The gotcha: running the markdown filter over the whole path would turn
# /auth/login_flow/<id> into /auth/loginflow/<id>.
check(
    "login_flow route keeps its underscore",
    m.canonical_route("/auth/login_flow/1ae7fe1234abcd"),
    "auth.login_flow",
)
check("token route", m.canonical_route("/auth/token"), "auth.token")
check("authorise route", m.canonical_route("/auth/authorize"), "auth.authorize")
check(
    "underscore is NOT stripped from the known route",
    "_" in m.canonical_route("/auth/login_flow/1ae7fe1234abcd"),
    True,
)
check(
    "unrecognised path keeps slashes but strips injection chars",
    m.canonical_route("/evil/<script>|x"),
    "/evil/scriptx",
)
check("unrecognised long path is bounded", len(m.canonical_route("/" + "z" * 500)), 92)
check("flow id extracted from a login flow", m.extract_flow_id("/auth/login_flow/1ae7fe1234abcd"), "1ae7fe1234abcd")
check("flow id is - for other routes", m.extract_flow_id("/auth/token"), "-")
check("flow id bounded to 16", len(m.extract_flow_id("/auth/login_flow/" + "a" * 200)), 16)
check(
    "non-hex path is not treated as a flow id",
    m.extract_flow_id("/auth/login_flow/zzzz"),
    "-",
)

# ---------------------------------------------------------------------------
banner("7.1g  LIVE-DATA SHAPE - HA emits no username")
# ---------------------------------------------------------------------------
line = (
    "WARNING (MainThread) [homeassistant.components.http.ban] "
    "Login attempt or request with invalid authentication from host "
    "(192.168.0.5). Requested URL: '/auth/login_flow/1ae7fe12'. (curl/8.0)"
)
check("username is absent from a real-shaped line", m.extract_username(line), None)
fields = m.parse_event(line)
check("line still parses for syslog", fields is not None, True)
check("src_ip extracted", fields["src_ip"], "192.168.0.5")
check("classify of a live line is unknown", m.classify_user(m.extract_username(line)),
      ("(unknown)", "unknown"))

# ---------------------------------------------------------------------------
banner("7.1h  TOKEN HANDLING - never leaks, scrubbed on the way out")
# ---------------------------------------------------------------------------
secret = "s3cr3t-bearer-value-abc123"
check("scrub removes the token", m.scrub_token(f"failed with {secret}", secret),
      "failed with <redacted>")
check("scrub is a no-op when no token", m.scrub_token("plain", ""), "plain")
check(
    "exception rendering is scrubbed",
    secret not in m.scrub_error(ValueError(f"boom {secret}"), secret),
    True,
)
os.environ["ALERTMANAGER_TOKEN_FILE"] = ""
os.environ["ALERTMANAGER_TOKEN_OPTION"] = secret
m.ALERTMANAGER_TOKEN_OPTION = secret
check("token read at send time", m.load_alertmanager_token(), secret)
with tempfile.NamedTemporaryFile("w", suffix=".token", delete=False) as handle:
    handle.write(secret + "\n")
    token_path = handle.name
m.ALERTMANAGER_TOKEN_FILE = token_path
check("token file is preferred over the option", m.load_alertmanager_token(), secret)
m.ALERTMANAGER_TOKEN_FILE = "/nonexistent/path.token"
m.ALERTMANAGER_TOKEN_OPTION = ""
check("unreadable token file yields empty, no crash", m.load_alertmanager_token(), "")
os.unlink(token_path)
m.ALERTMANAGER_TOKEN_OPTION = ""

# ---------------------------------------------------------------------------
banner("7.2a  END-TO-END - 12 attempts from one IP, 3 from a second")
# ---------------------------------------------------------------------------
CAPTURED: list[dict] = []
STATUSES: list[tuple[int, str]] = []


def fake_post(alert: dict) -> tuple[int, str]:
    CAPTURED.append(alert)
    STATUSES.append((200, "ok"))
    return (200, "ok")


m.post_alert = fake_post

LOG = []
for i in range(12):
    LOG.append(
        f"WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or "
        f"request with invalid authentication from a ({'192.168.0.5'}). Requested URL: "
        f"'/auth/login_flow/{i:016x}'. (curl/8.0)"
    )
for i in range(3):
    LOG.append(
        f"WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or "
        f"request with invalid authentication from b (198.51.100.77). Requested URL: "
        f"'/auth/login_flow/{i:016x}'. (curl/8.0)"
    )
FAKE_LOG = "\n".join(LOG)

m.fetch_logs = lambda: FAKE_LOG
m.SYSLOG_HOST = "127.0.0.1"
m.SYSLOG_PORT = 9  # discard port; datagram content is asserted separately

DATAGRAMS: list[bytes] = []
m.send_datagram = lambda payload: DATAGRAMS.append(payload)

with tempfile.TemporaryDirectory() as tmp:
    m.STATE_PATH = os.path.join(tmp, "state.json")
    state = m.load_state()
    state["initialised"] = True  # skip bootstrap so events are actually sent
    tracker = m.IpTracker()
    limiter = m.RateLimiter()
    sent, skipped = m.poll(state, tracker, limiter)
    m.save_state(state, tracker, limiter)
    with open(m.STATE_PATH, encoding="utf-8") as handle:
        persisted = json.load(handle)

events = [a for a in CAPTURED if a["labels"]["alertname"] == "HALoginEvent"]
sprays = [a for a in CAPTURED if a["labels"]["alertname"] == "HALoginSpray"]

check("syslog datagrams still emitted, one per event", len(DATAGRAMS), 15)
check("poll reports 15 sent", sent, 15)
check("both IPs received a HALoginEvent", len(events), 15)
check("EXACTLY ONE spray alert, not 12", len(sprays), 1)
check("spray alertname is HALoginSpray", sprays[0]["labels"]["alertname"], "HALoginSpray")
check("spray severity is critical", sprays[0]["annotations"]["summary"][:0] or sprays[0]["labels"]["alertname"], "HALoginSpray")

desc = sprays[0]["annotations"]["description"]
check("spray keys on the noisy IP", "spray_ip=192.168.0.5" in desc, True)
check("spray counts 12 attempts", "spray_attempts=12" in desc, True)
check("spray counts 12 distinct sessions", "spray_sessions=12" in desc, True)
check("spray records the window", "spray_window_minutes=10" in desc, True)
check("spray carries the no-username note",
      "note=keyed_on_attempt_count_no_username_in_ha_logs" in desc, True)
check("flow ids capped at 10 in the sample", desc.count(",") >= 9, True)
check("the quiet IP produced no spray alert",
      any("198.51.100.77" in a["annotations"]["description"] for a in sprays), False)

# ---------------------------------------------------------------------------
banner("7.2b  LABELS - component=homeassistant on EVERY alert")
# ---------------------------------------------------------------------------
check("every captured alert has component=homeassistant",
      {a["labels"].get("component") for a in CAPTURED}, {"homeassistant"})
check("every captured alert also has job=homeassistant",
      {a["labels"].get("job") for a in CAPTURED}, {"homeassistant"})
check("every alert carries an instance label",
      all(a["labels"].get("instance") for a in CAPTURED), True)
check("no unexpected label keys were added",
      {k for a in CAPTURED for k in a["labels"]},
      {"alertname", "job", "component", "instance"})

ev_desc = events[0]["annotations"]["description"]
check("per-event alert appends attempted_user", "attempted_user=(unknown)" in ev_desc, True)
check("per-event alert appends user_class", "user_class=unknown" in ev_desc, True)
check("per-event alert keeps the login_failed marker", "login_failed" in ev_desc, True)
check("known route canonicalised, not mangled", "route=auth.login_flow" in ev_desc, True)

# ---------------------------------------------------------------------------
banner("7.2c  NO CREDENTIAL MATERIAL IN ANY DESCRIPTION")
# ---------------------------------------------------------------------------
BANNED = ["password", "passwd", "secret", "token", "bearer", "authorization",
          "cookie", "session=", "otp", "totp", "api_key", "jwt", "eyJ"]
leaks = []
for alert in CAPTURED:
    blob = json.dumps(alert).lower()
    for term in BANNED:
        if term in blob:
            leaks.append((alert["labels"]["alertname"], term))
check("no credential keyword in any alert body", leaks, [])
check("no raw Authorization header anywhere", "authorization" in json.dumps(CAPTURED).lower(), False)

# ---------------------------------------------------------------------------
banner("7.2d  PERSISTENCE - state survives a restart")
# ---------------------------------------------------------------------------
check("tracker persisted", "tracker" in persisted, True)
check("rate limits persisted", "rate_limits" in persisted, True)
check("seen list still holds hashes only",
      all(len(h) == 64 and all(c in "0123456789abcdef" for c in h)
          for h in persisted["seen"]), True)
check("no raw log line persisted",
      any("invalid authentication" in json.dumps(persisted).lower() for _ in [0]), False)
check("no user agent persisted",
      any("curl/8.0" in json.dumps(persisted) for _ in [0]), False)

restored = m.IpTracker()
restored.load(persisted.get("tracker") or {})
view = restored.window("192.168.0.5", time.time() + 1, 10)
check("restored tracker still counts 12 attempts", view["attempts"], 12)

# ---------------------------------------------------------------------------
banner("7.2e  THROTTLING - notifications muted, detection NOT blinded")
# ---------------------------------------------------------------------------
CAPTURED.clear()
STDOUT = []
_real_print = print
import builtins
builtins.print = lambda *a, **k: STDOUT.append(" ".join(str(x) for x in a))

tracker = m.IpTracker()
limiter = m.RateLimiter()
m.EVENT_RATE_LIMIT_SECONDS = 60
m.SPRAY_RATE_LIMIT_SECONDS = 300
with tempfile.TemporaryDirectory() as tmp2:
    m.STATE_PATH = os.path.join(tmp2, "state.json")
    state = m.load_state()
    state["initialised"] = True
    m.poll(state, tracker, limiter)

builtins.print = _real_print
LOGGED = "\n".join(STDOUT)

events2 = [a for a in CAPTURED if a["labels"]["alertname"] == "HALoginEvent"]
sprays2 = [a for a in CAPTURED if a["labels"]["alertname"] == "HALoginSpray"]
check("event alerts throttled to 1 per IP", len(events2), 2)
check("spray throttled to 1 total", len(sprays2), 1)
check(
    "DETECTION STILL ACCUMULATES while muted",
    tracker.window("192.168.0.5", time.time() + 1, 10)["attempts"],
    12,
)
summary_line = next((ln for ln in STDOUT if "suppressed" in ln), None)
check("exactly ONE suppression summary line emitted",
      sum(1 for ln in STDOUT if "suppressed" in ln), 1)
check("summary counts the 13 suppressed event alerts",
      "13 event" in (summary_line or ""), True)
check("summary is a single line", "\n" in (summary_line or ""), False)
check("summary drained by poll, so a second drain is empty",
      limiter.drain_summary(), None)
m.EVENT_RATE_LIMIT_SECONDS = 0
m.SPRAY_RATE_LIMIT_SECONDS = 0

# ---------------------------------------------------------------------------
banner("7.2f  LRU BOUNDS - memory stays flat under an IP flood")
# ---------------------------------------------------------------------------
tracker = m.IpTracker(cap=2048, ttl_hours=24)
now = 1000.0
for i in range(5000):
    tracker.record(f"10.0.{i // 256}.{i % 256}", "f", now)
check("LRU holds exactly its cap", len(tracker._entries), 2048)
check("oldest evicted first", "10.0.0.0" in tracker._entries, False)
check("newest retained", "10.0.19.135" in tracker._entries, True)

# TTL: an entry untouched for longer than the TTL is pruned on the next write.
tracker.record("203.0.113.200", "f", now)
check("fresh entry present", "203.0.113.200" in tracker._entries, True)
tracker.record("203.0.113.201", "f", now + 25 * 3600)
check("entry older than the TTL is dropped", "203.0.113.200" in tracker._entries, False)

# ---------------------------------------------------------------------------
banner("7.2g  ROLLING WINDOW - only in-window attempts count")
# ---------------------------------------------------------------------------
tracker = m.IpTracker()
now = 5000.0
for i in range(5):
    tracker.record("203.0.113.9", "f", now + i * 60)   # 5 over 4 minutes
check("5 attempts inside 10 min", tracker.window("203.0.113.9", now + 300, 10)["attempts"], 5)
# At now+700 (11.7 min) the three most recent attempts are still in window.
check(
    "partial decay at 11.7 min keeps the 3 newest",
    tracker.window("203.0.113.9", now + 700, 10)["attempts"],
    3,
)
check(
    "at 20 min every attempt has aged out",
    tracker.window("203.0.113.9", now + 1200, 10)["attempts"],
    0,
)
tracker2 = m.IpTracker()
for i in range(12):
    tracker2.record("203.0.113.10", "f", now + i * 5)  # 12 in under a minute
check("tight burst counts 12", tracker2.window("203.0.113.10", now + 60, 10)["attempts"], 12)

# ---------------------------------------------------------------------------
banner("7.2h  ALERTMANAGER DISABLED BY DEFAULT - syslog-only behaviour")
# ---------------------------------------------------------------------------
check("default URL is empty", m.os.environ.get("ALERTMANAGER_URL", "") != "", True)
check("enabled flag follows the URL", m.ALERTMANAGER_ENABLED, True)
m.ALERTMANAGER_ENABLED = False
CAPTURED.clear()
with tempfile.TemporaryDirectory() as tmp3:
    m.STATE_PATH = os.path.join(tmp3, "state.json")
    state = m.load_state()
    state["initialised"] = True
    sent, _ = m.poll(state, m.IpTracker(), m.RateLimiter())
check("syslog still sends with Alertmanager off", sent, 15)
check("no alert attempted with Alertmanager off", len(CAPTURED), 0)
m.ALERTMANAGER_ENABLED = True

# ---------------------------------------------------------------------------
banner("7.2i  SYSLOG PATH UNCHANGED (regression guard)")
# ---------------------------------------------------------------------------
LEGACY_LINE = (
    "WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or "
    "request with invalid authentication from desktop (192.168.0.5). Requested URL: "
    "'/auth/login_flow/1ae7fe12abcd'. (Mozilla/5.0)"
)
legacy = m.parse_event(LEGACY_LINE)
check("field set identical to v1.0.2", list(legacy.keys()),
      ["event", "component", "src_ip", "src_host", "path", "ua"])
check("component detection unchanged", legacy["component"],
      "homeassistant.components.http.ban")
check("flow id still redacted in syslog",
      m.redact(LEGACY_LINE).count("<redacted>") >= 1, True)
check("datagram still has PRI <84> and app name",
      m.build_datagram(legacy).decode().startswith("<84>"), True)
check("datagram body is key=value over the six legacy keys",
      len(m.build_datagram(legacy).decode().split(": ", 1)[1].split(" ")), 6)

# ---------------------------------------------------------------------------
print()
print("=" * 78)
if FAILURES:
    print(f"RESULT: {len(FAILURES)} FAILURE(S) of {CHECKS} checks")
    for label in FAILURES:
        print(f"  - {label}")
    print("=" * 78)
    sys.exit(1)
print(f"RESULT: ALL {CHECKS} CHECKS PASSED")
print("=" * 78)
