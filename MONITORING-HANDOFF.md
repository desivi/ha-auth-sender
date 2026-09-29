# TASK: support HA Auth Sender 1.1.0 alerts and resolve the component-label question

You own the notifier receiving Alertmanager posts from the `ha-auth-sender`
Home Assistant add-on. That add-on was just updated from 1.0.2 to **1.1.0** and
now posts to you. Your job is the receiving side.

Do NOT modify the add-on repository or push to
`github.com/desivi/ha-auth-sender`. That work is merged and tagged `v1.1.0`.
If you believe the add-on is wrong, report it — do not patch it.

---

## 1. What changed on the sender side

`v1.0.2` emitted RFC3164/UDP syslog only and never posted to you. `v1.1.0` adds
a second sink posting to `/v1/alertmanager`, gated on an `alertmanager_url`
option. The syslog path is byte-identical to before.

**The feature is still off by default.** If you have received nothing yet, the
`alertmanager_url` option is still empty. Set it and restart the add-on before
concluding anything is broken.

Two alert shapes now exist. All detail travels in `annotations.description`
because the sender assumes your whitelist discards anything else.

### HALoginEvent — one per failed login, per-IP throttled to 1/60s

```json
{
  "labels": {
    "alertname": "HALoginEvent",
    "job": "homeassistant",
    "component": "homeassistant",
    "instance": "homeassistant"
  },
  "annotations": {
    "summary": "Failed login from 192.168.0.5",
    "description": "login_failed from=192.168.0.5 route=auth.login_flow ua=curl/8.0 attempted_user=(unknown) user_class=unknown"
  }
}
```

### HALoginSpray — a NEW alertname, 1 per IP per 5 min

```json
{
  "labels": {
    "alertname": "HALoginSpray",
    "job": "homeassistant",
    "component": "homeassistant",
    "instance": "homeassistant"
  },
  "annotations": {
    "summary": "Login burst from 192.168.0.5",
    "description": "spray_ip=192.168.0.5 spray_window_minutes=10 spray_attempts=12 spray_sessions=12 spray_sample_flow_ids=0000000000000004,0000000000000005 note=keyed_on_attempt_count_no_username_in_ha_logs"
  }
}
```

Fields are space-separated `key=value`. `route` is a short canonical token, not a
raw path — `/auth/login_flow/<id>` is reported as `route=auth.login_flow` and
unrecognised routes are sanitised and truncated. `ua` is the raw user agent,
sanitised, so treat it as untrusted text.

---

## 2. THE DECISIVE OPEN QUESTION — resolve this first

The sender sets **both** `job: homeassistant` and `component: homeassistant` on
every alert, and we do not know which one your routing logic actually reads.

The task author described your whitelist as mapping your output field
`component` from `labels.job`. If that is right, the `component` **label** is
never read and `HALoginSpray` will land in the **monitoring** room, not the
Home Assistant room. If your routing keys on a label literally named
`component`, it will land correctly.

Nobody has observed either outcome. Please determine which, from your own
routing code, and state it plainly with the file and line.

**Do not guess and do not accept the sender's assumption.** If your whitelist
genuinely maps `component` from `labels.job`, then the correct fix is on **your**
side: key HA routing off `labels.component` (or accept either), because
`job` is not a field HA controls — it can be absent or arbitrary on a
third-party alert, whereas `component` is set deliberately.

---

## 3. Required changes on your side

### Before you edit anything

**Back up every file you intend to touch, timestamped, before modifying it.**
A previous round established `/root/secure-backup/` for exactly this, and the
rollback procedure depends on those copies existing. For each file:

```bash
ts=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /root/secure-backup/"$ts"
cp -a /path/to/notifier/config.yaml /root/secure-backup/"$ts"/
```

Use a fresh timestamped directory per task, not one flat directory. **Report the
backup path in your §7 writeup** — it is the only thing the rollback plan can
point at. Do not report the contents of any backed-up file if it contains a
token; report the path and a checksum instead.

**Check your self-alert thresholds before you change anything.** If the notifier
alerts on its own restart, connection loss, or queue depth, your edits will
generate alerts that muddy the room counters someone else is watching. Note the
current thresholds first so you can distinguish your own noise from a real
regression.

### The changes

1. **Route `HALoginSpray` to the Home Assistant room.** It is a new alertname.
   If your HA routing is keyed on a hardcoded `alertname: HALoginEvent`, every
   burst alert currently misroutes to monitoring. Fix this — it is the whole
   reason the sender added the `component` label.
2. **Confirm your whitelist.** Verify it really is only `source`, `event_type`,
   `severity`, `status`, `host`, `component`, `summary`, `reason`, and
   `details{alertname, instance, service}`. If it copies more than that, say so:
   the sender is packing everything into `description` on the assumption it does.
3. **Parse the new description fields** into whatever structured view you
   render, so a burst reads as `12 attempts from 192.168.0.5` rather than a
   string blob. Fields: `spray_ip`, `spray_attempts`, `spray_sessions`,
   `spray_window_minutes`, `spray_sample_flow_ids`, `attempted_user`,
   `user_class`, `from`, `route`, `ua`.
4. **Handle `attempted_user=(unknown)` gracefully.** It is **always** `(unknown)`
   on live data. Home Assistant does not log the attempted username —
   `process_wrong_login` composes its line from peer address, requested URL and
   user agent only, and the request body is never read. Verified with a canary
   username on a live instance. `user_class` is therefore always `unknown` too.
   **Do not build a username-based rule, filter, or dedupe key** — every value
   is identical, so it would collapse all logins into one.
5. **Do not double-throttle.** The sender already limits to 1 event per IP per
   60s and 1 spray per IP per 5 min. If you have your own dedupe or rate limit,
   make sure it does not suppress a burst alert the sender deliberately sent.
6. **Ignore `note=keyed_on_attempt_count_no_username_in_ha_logs`** or surface it
   as context. It explains why the alert counts attempts, not usernames.

### Restart planning — the notifier has `CanReload=no`

There is no hot reload. **Every config change costs a full restart (~3s), and a
restart drops the queue.** Plan for this:

- **Make all edits first, then restart ONCE.** Do not restart per change. A
  restart-per-edit loop multiplies the window in which delivery is down and
  will double-count your own self-alerts.
- **Check your self-alert thresholds before the restart** (see above) so a
  planned bounce is not mistaken for an incident by whoever is watching room
  counters and Matrix delivery on the other side.
- **After the single restart, confirm recovery before sending the test
  alerts:** `matrix_connected` is true, the queue has fully drained rather than
  sitting at a growing depth, and the notifier is logging healthy.
- Only then run §5. If Matrix is not connected when you send, the three results
  are meaningless — the alert was accepted but never delivered, and you will
  misreport it as a routing failure.

---

## 4. Two sender-side limitations that will look like your bugs

- **The sender's log tail is lossy.** It reads `/core/logs`, a rotating tail of
  roughly 100 lines. Bursts faster than polling can be partially missed, and a
  Core traceback or restart can discard events. Gaps in what you receive are
  expected, not a delivery failure.
- **Only failed logins are forwarded.** Successful logins produce no output at
  all. You will never see a success event from this add-on.
- **Suppression counts go to the add-on's stdout, not to you.** When the sender
  throttles, it logs a single `suppressed N event` line to the add-on log. You
  will see silence, not a notice.

---

## 5. Validation — send these three, report real results

Use RFC 5737 documentation IPs (`198.51.100.0/24`) so test traffic is never
mistaken for a real attacker. Mark every one clearly.

```bash
# Read the token from your own credential store at send time. Do NOT echo it,
# do NOT paste it into a file, and do NOT include it in your report.

curl -sS -o /dev/null -w 'HTTP %{http_code}\n' -X POST \
  https://192.168.0.40:18128/v1/alertmanager \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"labels":{"alertname":"HALoginEvent","job":"homeassistant","component":"homeassistant","instance":"homeassistant"},"annotations":{"summary":"POLLER TEST DICT","description":"login_failed from=198.51.100.10 route=auth.login_flow ua=curl/8.0 attempted_user=admin user_class=dictionary"}}'

curl -sS -o /dev/null -w 'HTTP %{http_code}\n' -X POST \
  https://192.168.0.40:18128/v1/alertmanager \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"labels":{"alertname":"HALoginSpray","job":"homeassistant","component":"homeassistant","instance":"homeassistant"},"annotations":{"summary":"POLLER TEST SPRAY","description":"spray_ip=198.51.100.11 spray_window_minutes=10 spray_attempts=7 spray_sessions=4 spray_sample_flow_ids=1144ed2a,95e5531b note=keyed_on_attempt_count_no_username_in_ha_logs"}}'

curl -sS -o /dev/null -w 'HTTP %{http_code}\n' -X POST \
  https://192.168.0.40:18128/v1/alertmanager \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"labels":{"alertname":"SomeOtherThing","job":"homeassistant","component":"homeassistant","instance":"homeassistant"},"annotations":{"summary":"POLLER TEST CONTROL","description":"attempted_user=alice user_class=unknown"}}'
```

Drop `-o /dev/null` on at least one to capture the **response body**, and report
it. The third alert is the routing probe: an unrecognised alertname carrying
`component: homeassistant`.

Report for **each** of the three:
- HTTP status
- response body
- **which room or chat it landed in**

The third one is the real test. It belongs in the Home Assistant room. If it
lands in monitoring, the `component` label is not reaching your routing and
Required Change 1 has failed.

Also confirm the add-on is actually sending: check its log for lines beginning
`alertmanager: HALoginEvent status=` and `alertmanager: HALoginSpray status=`.
If `alertmanager_url` is unset you will see
`alertmanager: enabled url=unset` and nothing else.

---

## 6. Security

- Never print, log, echo or commit the bearer token. Read it at send time from
  your credential store. If you must show a command, use `$TOKEN` as above.
- Report statuses and bodies. Never report the token.
- `ua` and any unrecognised `route` in a description are **attacker-controlled**.
  Render them escaped. Do not render any description field as HTML or markdown,
  and do not build clickable links from them.
- `spray_sample_flow_ids` are login session identifiers, not credentials, but
  they are still session-scoped data. Do not log them beyond the alert body.
- Do not enable TLS verification bypass to make a send work.

---

## 7. Report back

- **The §2 answer: which field does your routing read, `labels.job` or
  `labels.component`? File and line.** This is the most important thing you
  report and it must be evidence, not inference.
- What you changed, file by file.
- **The backup directory path you created, and a checksum per backed-up file.**
- Full validation output: all three HTTP statuses, all three response bodies,
  all three room destinations.
- **How many restarts you performed.** It should be one. If more, say what
  forced the extra.
- **Post-restart recovery evidence:** `matrix_connected` value, queue depth
  before and after it drained, and the log line showing healthy startup.
- Whether your whitelist matched the description in §1, field by field.
- Whether the add-on is confirmed sending, with the log line you saw.
- Anything you could not determine.
- If you could not complete a step, say so plainly. Do not report a simulated
  or mock result as real.
