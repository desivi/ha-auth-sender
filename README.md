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

Sample message body:

```
event=login_failed component=homeassistant.components.http.ban src_ip=203.0.113.9 src_host=host.example.lan path=/auth/login_flow/<redacted> ua=curl/8.14.1
```

## Install

**Settings -> Add-ons -> Add-on Store -> menu -> Repositories**, add:

```
https://github.com/desivi/ha-auth-sender-addon
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

## Permissions and networking

- `hassio_api: true` only. No `homeassistant_api`, no host network, no privileged
  mode, no host ports, no `map` mounts.
- Outbound UDP only.
- Port `8099` is an internal watchdog health check and is **not** published.

## Privacy

The only thing written to `/data/state.json` is a bounded list of SHA-256
hashes. Raw log lines, client IPs, user agents and paths are never persisted.
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

Uninstall the add-on, or delete `/addon_configs/ha_auth_sender` to drop the
stored watermark. No Home Assistant configuration is modified by this add-on.

## Local build

```bash
cd ha_auth_sender
docker build --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.24 -t ha-auth-sender:local .
```
