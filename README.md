# HA Auth Sender

A supervised Home Assistant add-on that forwards authentication events to a
remote syslog receiver over **RFC3164/UDP**, so failed logins show up in your
central monitoring stack in near real time.

## What it does

- Polls the Supervisor Core log tail (`/core/logs`) every 20s (5-30s).
- Matches `homeassistant.components.http.ban` and `homeassistant.components.auth`
  warnings and errors.
- Redacts credentials before anything leaves the container.
- Deduplicates by SHA-256 content hash, persisted in `/data`, so events are
  never sent twice across restarts.
- Emits one datagram per event, priority `<84>` (authpriv.warning).
- Optionally posts Alertmanager alerts and detects per-IP login bursts
  (`alertmanager_url` empty = disabled, which is the default).

Sample message body:

```
event=login_failed component=homeassistant.components.http.ban src_ip=203.0.113.9 src_host=host.example.lan path=/auth/login_flow/<redacted> ua=curl/8.14.1
```

### Why there is no username in the alerts

Home Assistant does not log the attempted username on a failed login.
`process_wrong_login` composes its line from the peer address, the requested URL
and the user agent only — the request body is never read — and
`Data.validate_login` is a constant-time scan so it cannot reveal whether a
username exists. Verified on a live instance with a canary username: absent
from `/core/logs` and from `/config`.

So `attempted_user` is `(unknown)` and `user_class` is `unknown` on all live
data. Burst detection is therefore keyed on **per-IP attempt count**, not on
distinct usernames, which would be permanently 1 and could never fire.

Flow identifiers are reported only as a *distinct sessions* statistic. A
`flow_id` keys a login **session**, not an attempt, so bursts reuse a handful of
them and it cannot substitute for username identity.

## Install

**Settings -> Add-ons -> Add-on Store -> menu -> Repositories**, add:

```
https://github.com/desivi/ha-auth-sender
```

Then install **HA Auth Sender**, set the destination host in Configuration, start.

## Options

| Option | Default | Notes |
|---|---|---|
| `syslog_host` | `192.168.0.20` | Receiver address |
| `syslog_port` | `1514` | UDP port |
| `poll_interval` | `20` | Seconds, 5-30 |
| `app_name` | `ha-auth` | RFC3164 app-name field |
| `log_host` | `homeassistant` | RFC3164 hostname field |
| `bootstrap` | `skip` | `skip` adopts existing events silently on first run; `send` backfills |
| `alertmanager_url` | `""` (disabled) | POST endpoint. Empty leaves the add-on syslog-only |
| `alertmanager_token_file` | `""` | **Preferred.** Path to a file holding the bearer token |
| `alertmanager_token` | `""` | Fallback. Stored in `.storage`, visible in the options UI |
| `instance` | `homeassistant` | `instance` label value |
| `spray_threshold` | `10` | Attempts per IP per window before `HALoginSpray` |
| `spray_window_minutes` | `10` | Rolling window |
| `event_rate_limit_seconds` | `60` | Per-IP `HALoginEvent` throttle |
| `spray_rate_limit_seconds` | `300` | Per-IP `HALoginSpray` throttle |
| `max_tracked_ips` | `2048` | LRU cap on tracked source IPs |
| `ip_ttl_hours` | `24` | Idle lifetime for a tracked IP |

### Token handling

Use `alertmanager_token_file`. Add-on options are stored in `.storage`, shown in
the add-on options UI and included in diagnostics dumps, so a token placed in
`alertmanager_token` is readable by anything that can read the Supervisor API.
A file keeps it out of that path. Place it under `/data` (for example
`/data/alertmanager.token`, mode `0600`) and point the option at it;
`alertmanager_token` remains as a convenience fallback and is declared
`password` in the schema so it is masked in the UI.

The token is read at send time only, held in a local for the duration of one
request, never logged, and stripped from response bodies and exception messages
before anything is printed. TLS verification is on and cannot be disabled.

### Rate limiting and detection state

Throttling applies only to **notifications**. Attempt recording is
unconditional, so a muted or throttled channel never blinds detection, and the
suppressed count is reported as a single summary line per poll. Detection and
throttle state are persisted, so both survive a restart.

## Permissions and networking

- `hassio_api: true` only. No `homeassistant_api`, no host network, no privileged
  mode, no host ports, no `map` mounts.
- Outbound UDP only.
- Port `8099` is an internal watchdog health check and is **not** published.

## Privacy

Deduplication state in `/data/state.json` is a bounded list of SHA-256 hashes.
Raw log lines, user agents and paths are never persisted.

Burst detection (1.1.0 and later) additionally persists bounded per-IP state:
attempt timestamps and login-flow session identifiers, capped at
`max_tracked_ips` and expired after `ip_ttl_hours`. This is a deliberate change
from 1.0.2, which stored nothing but hashes — rate limits and burst windows
cannot survive a restart otherwise. It stores no usernames, passwords, cookies
or tokens. Set `max_tracked_ips` low if you want the footprint smaller, or leave
`alertmanager_url` empty to keep the old behaviour exactly.

No credentials are stored or logged; redaction covers JWTs,
`Authorization`/`Bearer`, cookies, passwords, `api_password`, MFA/OTP, API keys,
tokens and login-flow identifiers.

## Known limitations

**Successful logins are not forwarded.** Home Assistant's
`process_success_login` fires no event and logs only at `DEBUG`, and only when
the IP already has failed attempts to clear. A clean successful login produces
no output at all, so there is nothing reliable to capture.

**The log tail is lossy.** `/core/logs` is a rotating tail of roughly 100 lines.
If more than ~100 lines are written between two polls, the oldest auth events are
dropped without notice. A single multi-line Core traceback can displace them.
This is a property of the source, not something faster polling can fix.

**A Core restart rotates the tail**, discarding events not yet polled.

## Rollback

To return to 1.0.2 after installing 1.1.0:

```bash
# 1. Stop the add-on.
ha addon stop 34f93bf8_ha_auth_sender

# 2. Check out the 1.0.2 source. HEAD is 463102b ("fix: make add-on options
#    actually reach the script"), which is the 1.0.2 release. Only v1.0.0 is
#    tagged so far, so use the commit until a v1.0.2 tag is pushed:
cd /path/to/ha-auth-sender
git checkout 463102b        # or: git checkout v1.0.2   once tagged

# 3. Rebuild from that checkout.
cd ha_auth_sender
docker build --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.24 -t local/ha-auth-sender:1.0.2 .

# 4. Clear the 1.1.0-only options (Supervisor keeps unknown keys, but 1.0.2
#    rejects them on schema validation):
#    Settings -> Add-ons -> HA Auth Sender -> Configuration
#    clear alertmanager_url, alertmanager_token_file, alertmanager_token,
#    instance, spray_threshold, spray_window_minutes,
#    event_rate_limit_seconds, spray_rate_limit_seconds, max_tracked_ips, ip_ttl_hours

ha addon start 34f93bf8_ha_auth_sender
```

Simply uninstalling, or deleting `/addon_configs/ha_auth_sender` to drop the
stored watermark, also works. No Home Assistant configuration is modified by
this add-on.

## Tests

Offline validation, no network and no credentials:

```bash
python3 tests/test_alertmanager.py
```

It covers the sanitiser, route canonicalisation, the LRU and rolling-window
bounds, throttling, persistence round-trip, and an end-to-end synthetic burst.
`post_alert` is stubbed so alerts can be inspected; the live webhook is
deliberately **not** exercised by this suite.

## Local build

```bash
cd ha_auth_sender
docker build --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.24 -t ha-auth-sender:local .
```
