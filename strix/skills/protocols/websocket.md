---
name: websocket
description: WebSocket security testing covering CSWSH, origin enforcement, auth-on-connect vs per-message, cross-tenant frame leakage, and message tampering
---

# WebSocket

WebSocket upgrades a normal HTTP request into a long-lived, bidirectional channel. The common failure is that developers authorize the *handshake* once and then trust every frame after it. Treat the handshake and every subsequent message as separate authorization boundaries.

## Attack Surface

**Handshake (HTTP upgrade)**
- `GET` with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`
- `Origin` header — the browser sets it; the server is responsible for validating it
- Auth material: cookies (sent automatically cross-site), `Authorization` header, token in query string or subprotocol (`Sec-WebSocket-Protocol`)

**Post-handshake frames**
- Text/binary application messages (often JSON-RPC-ish: `{"action":..., "id":...}`)
- Control frames: ping/pong, close
- Subprotocols: `graphql-ws`, `graphql-transport-ws`, STOMP, MQTT-over-WS, SignalR, socket.io

**Architecture**
- Direct app WS server vs reverse-proxied (nginx/ALB) — proxies may strip/forward `Origin` inconsistently
- Pub/sub backends (Redis, NATS) where channel/topic names are the real authz key

## Reconnaissance

Find endpoints in JS bundles and network traffic:
```
grep -rEi "wss?://|new WebSocket|io\(|graphql-ws|/socket.io/|/hubs/|/cable" bundle.js
```
Common paths: `/ws`, `/socket`, `/socket.io/`, `/cable` (Rails ActionCable), `/hubs/*` (SignalR), `/graphql` (subscriptions).

Establish a baseline connection and record: does it require auth to connect? What frames does the client send on open (subscribe/auth messages)? What channel/topic identifiers appear?

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

The flagship WebSocket bug. If the server authenticates the handshake with **cookies** and does **not** validate `Origin`, any attacker page can open a WS to the target in the victim's authenticated session and read/write their data.

Test:
1. Capture a working authenticated handshake.
2. Replay it with a foreign/absent `Origin` header (e.g. `Origin: https://evil.example`).
3. If the connection still upgrades and returns the victim's data, it's vulnerable.

```
GET /ws HTTP/1.1
Host: target
Origin: https://evil.example
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Cookie: session=<victim-style cookie is sent automatically by the browser>
```

PoC for a report: an HTML page hosted off-origin that opens `new WebSocket("wss://target/ws")` and exfiltrates the first messages. Confirms the browser attaches cookies and the server accepted the foreign origin.

### Auth on Connect vs Per-Message

Servers frequently check authorization only at connect (or only on the first `subscribe`) and then serve any subsequent frame.

- Connect as user A, then send frames referencing user B's resource IDs / channels.
- Subscribe to a channel you shouldn't own: `{"action":"subscribe","channel":"user:OTHER_ID"}`.
- After a privileged action is denied at connect, retry the *same* action as a later frame — the per-message path may skip the check.

### Cross-Tenant / Broadcast Frame Leakage

Pub/sub servers that broadcast on a shared topic may deliver other tenants' events.

- Subscribe with a wildcard or a foreign tenant identifier: `topic:*`, `org:OTHER`, `room:GUESSABLE`.
- Sit on a broadly-scoped subscription and watch for messages containing other users' PII, IDs, or tokens.
- Test predictable channel names (sequential room IDs, email-derived channels).

### Message Tampering / Injection

Frames often reach the same backend logic as REST but skip its middleware (validation, rate limits, WAF).

- Replay a low-privilege frame with elevated fields (`"role":"admin"`, `"amount":-1`) — mass-assignment over WS.
- Inject SQLi/XSS/command payloads through WS message fields; the delivered messages may be rendered by other clients without encoding (stored XSS via WS).
- Send malformed/oversized frames and out-of-order control frames to probe for DoS or state confusion.

### Rate-Limit & WAF Bypass

WS frames commonly bypass per-request rate limiting and WAF rules that only inspect the initial handshake. Use a single connection to blast enumeration/brute-force actions that would be throttled over REST.

### graphql-ws / Subscriptions

- Authorization enforced only at `connection_init`, not per `subscribe` — subscribe to foreign IDs after a valid init.
- `connection_init` payload may accept a token that the server never re-validates on token expiry.
- See `[[graphql]]` for schema-level testing; this covers the transport.

## WAF / Proxy Notes

- Some reverse proxies overwrite or drop `Origin` on upgrade — test both directly against the app server and through the proxy.
- `Sec-WebSocket-Protocol` is sometimes used to smuggle a bearer token; check whether the server validates it or just echoes it.

## Testing Methodology

1. **Discover** — grep bundles/traffic for WS endpoints and the client's open/subscribe frames.
2. **Baseline** — connect as an authenticated user; catalog channels, actions, and ID shapes.
3. **CSWSH** — replay the handshake with a foreign `Origin`; build an off-origin HTML PoC if it upgrades.
4. **Per-message authz** — reference foreign IDs/channels in frames after a valid connect.
5. **Broadcast leakage** — subscribe broadly/cross-tenant and watch for other users' data.
6. **Tampering** — mass-assignment, injection, and stored-XSS-via-WS in message fields.
7. **Limits** — confirm rate-limit/WAF bypass through frames.

## Validation Requirements

- CSWSH: an off-origin PoC page that connects and returns the victim-scoped data, proving cookies attach and `Origin` was not enforced.
- Per-message authz: two connections (user A, user B) where A's frame reads/writes B's resource.
- Broadcast leakage: captured frames containing another tenant's data on a subscription you should not have.
- Minimal frames: exact JSON messages sent and the server's response frames.
