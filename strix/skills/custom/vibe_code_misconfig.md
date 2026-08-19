---
name: vibe_code_misconfig
description: "AI-generated / 'vibe-coded' app misconfig playbook: the config and deployment bugs LLM codegen ships by default — broken Supabase RLS, client-leaked secrets, permissive CORS, missing rate limits, weak JWT, exposed .env/debug, GraphQL introspection — each mapped to the deterministic Strix probe that proves it"
---

# Vibe-Code Misconfig (Methodology)

AI code assistants generate functional happy-path code and skip the security defaults. Research (Veracode, Escape.tech, GitGuardian, 2025-2026) shows ~45% of AI-generated code ships with a flaw, and the recurring failures are **config/deployment misconfigs**, not exotic logic bugs. Strix has knowledge packs for each class — this playbook sequences them and points at the one-call probe that proves each, so nothing gets skipped just because the agent forgot to look.

Run this pass early against any app that looks AI-built (Next.js/Vite front end, Supabase/Firebase backend, Tailwind, generated CRUD). Every probe below returns a `possible_*` flag with a concrete oracle — confirm, then `validate_finding` before filing.

## 1. Client-leaked secrets — run first, it feeds everything else
`frontend_secret_scan(url, validate=True)` fetches the page + served JS bundles and regexes key shapes (AWS, Stripe `sk_live`, OpenAI, Google, GitHub, Slack, private keys, Supabase JWTs graded by role). A `service_role` JWT or a live-validated `sk_live` key is an instant critical. Capture any Supabase URL + `anon` key here — the next step needs them.

## 2. Broken Supabase RLS / open Firebase rules
`backend_rules_probe(base_url, provider, anon_key)` reads `/rest/v1/<table>?select=*` with the public anon key (Supabase) or `/<path>.json` unauthenticated (Firebase). Rows returned = broken RLS = confirmed cross-tenant data leak — the single most common critical in the Supabase vibe stack (~60% of apps). Test `users`, `profiles`, `orders`, `payments`, and any table names you saw in the bundle. Also test write (PATCH/DELETE / POST) for policies missing `WITH CHECK`.

## 3. Permissive CORS
`cors_probe(url)` sends attacker `Origin`s and grades the `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials` combo. Reflected Origin + credentials = critical cross-origin credentialed read. Point it at a credentialed API endpoint.

## 4. Weak / misconfigured JWT
Capture a session token, then `jwt_audit(token)`: it flags `alg=none` / missing-exp / expired and cracks weak HS256 secrets against a wordlist, emitting an `alg=none` token and a resigned admin token. Replay the forged tokens with `http_replay` (`Authorization: Bearer <token>`) — acceptance = critical auth bypass.

## 5. Missing rate limiting
`rate_limit_probe(url, method="POST", count=50)` bursts a sensitive endpoint (login, OTP, password-reset, expensive search/export) and flags the absence of `429` / `RateLimit-*`. Enables credential stuffing and billing abuse.

## 6. GraphQL introspection in prod
If a `/graphql` endpoint exists, `graphql_introspection(url)` fires an `__schema` query; a returned type map = introspection left on, the map for every deeper GraphQL attack.

## 7. Exposed .env / debug / admin + verbose errors
Request `/.env`, `/.git/HEAD`, `/config.json`, `/debug`, `/actuator`, sourcemap `.map` files directly (use `run_scanner` with `ffuf`/`nikto`, or `http_replay`). Trigger errors (malformed JSON, wrong-type params) and grep responses for stack frames, file paths, and framework banners. `load_skill information_disclosure` for the full list.

## 8. Access control on generated CRUD (IDOR/BOLA)
The #1 AI bug. Store two identities' credentials, then `authz_probe(method, url, identities)` replays the same object request across them and diffs status/length/body-digest — shared bodies or an unexpected 2xx = broken access control. Also POST extra fields (`role`, `is_admin`, `owner_id`) to test mass assignment. `load_skill idor` and `broken_function_level_authorization`.

## Wrap up
`dedupe_reports` to merge duplicates, then after any fix cycle `retest_findings` to prove what's actually closed. Don't declare done until every probe above has run against the relevant surface.
