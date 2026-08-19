---
name: api_security_top10
description: "OWASP API Security Top 10 methodology: an attack-surface-first workflow that sequences BOLA/IDOR, broken auth, BOPLA/mass-assignment, BFLA, and the rest into one API test plan"
---

# API Security Top 10 (Methodology)

APIs fail differently from web pages: no rendered UI to constrain input, authorization enforced per-object and per-function, and lots of hidden endpoints. Strix already has deep skills for the individual bugs — this skill is the *methodology* that ties them into one systematic pass so nothing gets skipped. Load the linked skills for payload-level depth.

## Step 0 — Build the API Attack Surface

Before testing, enumerate and record (use the attack-surface map):

- **Spec import:** OpenAPI/Swagger, Postman collections, GraphQL schema — import all endpoints, params, and schemas.
- **Discovery:** crawl JS bundles/mobile apps for endpoints; brute-force versions (`/v1`, `/v2`, `/internal`, `/admin`), formats (`.json`), and hidden methods.
- **Principal matrix:** obtain tokens for anonymous, low-priv user A, second user B (same tenant), second tenant, and admin — with at least one owned object ID per principal. This matrix is what makes the authorization tests below possible.

## The Top 10 — What To Test

### API1: Broken Object-Level Authorization (BOLA/IDOR)

The #1 API bug. For every endpoint taking an object ID, swap A's ID for B's. Test numeric, UUID, slug, and nested IDs; GET/PUT/PATCH/DELETE, not just GET. Full playbook: `[[idor]]`.

### API2: Broken Authentication

Weak/So absent token validation, JWT flaws, credential stuffing, no lockout, guessable reset tokens. Cross-link `[[authentication-jwt]]`, `[[weak-password-detection]]`, `[[cryptographic-failures]]`.

### API3: Broken Object Property-Level Authorization (BOPLA)

Two halves:
- **Excessive data exposure:** the response returns more fields than the UI shows (read `password_hash`, `internal_notes`, other users' PII in list endpoints). Inspect raw JSON, not the app.
- **Mass assignment:** the request accepts fields it shouldn't (`role`, `is_admin`, `balance`, `verified`). Full playbook: `[[mass-assignment]]`.

### API4: Unrestricted Resource Consumption

No rate limits / pagination caps / size limits → brute force, scraping, denial-of-wallet. Test large `limit`/`page_size`, bulk operations, expensive queries, and unthrottled auth endpoints.

### API5: Broken Function-Level Authorization (BFLA)

Call admin/privileged *functions* as a low-priv user (not object access — function access). Swap HTTP methods, hit admin routes directly, guess management endpoints. Full playbook: `[[broken-function-level-authorization]]`.

### API6: Unrestricted Access to Sensitive Business Flows

Automate a flow the business assumes is human-paced: bulk-buy limited stock, spam invites, farm referrals/discounts, scrape all listings. Cross-link `[[business-logic]]`, `[[race-conditions]]`.

### API7: Server-Side Request Forgery

Any param taking a URL/hostname (webhooks, imports, image fetch, PDF render). Cross-link `[[ssrf]]`.

### API8: Security Misconfiguration

Verbose errors/stack traces, permissive CORS, missing security headers, debug endpoints, default creds, unnecessary HTTP methods (TRACE), unpatched components. Cross-link `[[information-disclosure]]`, `[[csrf]]`.

### API9: Improper Inventory Management

Shadow/zombie APIs: old versions (`/v1` still live and unpatched), staging/internal hosts, undocumented endpoints, deprecated params. These often lack the newer version's authz. Enumerate hosts/versions deliberately.

### API10: Unsafe Consumption of Third-Party APIs

The target trusts data from an upstream API/webhook without validation → injection via that channel. Test data the app ingests from integrations (webhooks, OAuth userinfo, imported feeds) for the same injection classes as user input.

## Cross-Cutting

- **Injection everywhere:** every param is an injection point — `[[sql-injection]]`, `[[nosql-injection]]`, `[[ssti]]`, `[[rce]]`, `[[xxe]]`.
- **GraphQL:** if present, use `[[graphql]]` — BOLA/BFLA/batching map directly onto resolvers.
- **Transport parity:** REST, GraphQL, gRPC-web, and WebSocket (`[[websocket]]`) for the same operation may enforce different authz — test each.

## Testing Methodology

1. **Enumerate** — import specs, crawl, brute versions/hosts; record every endpoint + params.
2. **Principal matrix** — tokens + owned IDs for each role/tenant.
3. **Authorization sweep** — BOLA (API1), BFLA (API5), BOPLA (API3) across the matrix; this is where most findings are.
4. **Auth & crypto** — token/session/reset weaknesses (API2).
5. **Abuse & limits** — resource consumption (API4), business flows (API6).
6. **Injection & SSRF** — every param (API7 + cross-cutting).
7. **Config & inventory** — misconfig (API8), shadow APIs (API9), third-party ingestion (API10).

## Validation Requirements

- Authorization findings: paired requests (principal A accessing B's object/function) with the unauthorized data returned.
- Excessive exposure: the raw response showing fields beyond authorization.
- Mass assignment: request adding a privileged field + confirmation it took effect.
- Shadow API: the old-version/undocumented endpoint responding with data the current version protects.
