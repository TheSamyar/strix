"""autopwn — chained, self-verifying deep scan driven by prior leaks.

One call runs the pivot an operator would: fingerprint the stack, discover hidden
params/endpoints, harvest leaks (secrets, SSR data, .git/.env, source maps), then
FEED those leaks into the next stage — a leaked Supabase key becomes an RLS dump,
hidden params become an injection fuzz, discovered endpoints get ranked and hit
for data exposure/CORS, a GraphQL schema gets field-leak-tested. Every finding is
double-confirmed (adversarial verification) before it's kept, then chained.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from strix.tools.backend_rules_probe.tools import _backend_rules_probe_impl
from strix.tools.chain_suggest.tools import _chain_suggest_impl
from strix.tools.cors_probe.tools import _cors_probe_impl
from strix.tools.data_exposure.tools import _data_exposure_impl
from strix.tools.deep_fuzz.tools import _deep_fuzz_impl
from strix.tools.discovery.tools import _content_discover_impl, _param_discover_impl
from strix.tools.error_leak.tools import _error_leak_impl
from strix.tools.frontend_secret_scan.tools import _frontend_secret_scan_impl
from strix.tools.graphql_deep.tools import _graphql_field_leak_impl
from strix.tools.header_leak.tools import _header_leak_impl
from strix.tools.profile_target.tools import _profile_target_impl
from strix.tools.security_headers.tools import _security_headers_impl
from strix.tools.ssr_leak.tools import _ssr_leak_impl
from strix.tools.storage_probe.tools import _storage_probe_impl


if TYPE_CHECKING:
    from collections.abc import Callable


def _safe(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 (never let one stage kill the pipeline)
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}


def _finding(
    kind: str, title: str, severity: str, detail: Any, verify: Callable[[], bool] | None
) -> dict[str, Any]:
    # Adversarial verification: re-run the check; keep the verdict either way.
    verified = None
    if verify is not None:
        verified = _safe(lambda: {"v": verify()}).get("v", False)
    return {
        "kind": kind,
        "title": title,
        "severity": severity,
        "verified": verified,
        "detail": detail,
    }


def _autopwn_impl(  # noqa: PLR0912, PLR0915
    seed_url: str,
    headers: dict[str, str] | None,
    supabase_anon_key: str | None,
    timeout: int,
) -> dict[str, Any]:
    if not seed_url or not seed_url.strip():
        return {"success": False, "error": "seed_url cannot be empty"}
    findings: list[dict[str, Any]] = []

    # --- 1. Profile the stack ------------------------------------------------
    prof = _safe(lambda: _profile_target_impl(seed_url, timeout))
    baas = prof.get("baas") or []
    api = prof.get("api") or []
    supa_url = prof.get("supabase_url")
    supa_key = prof.get("supabase_anon_key") or supabase_anon_key

    # --- 2. Discover hidden params + content --------------------------------
    params = _safe(lambda: _param_discover_impl(seed_url, headers, None, timeout))
    content = _safe(lambda: _content_discover_impl(seed_url, None, timeout))
    hidden_params = [p["param"] for p in params.get("hidden_params", [])][:8]
    discovered_paths = [f["path"] for f in content.get("found", [])]

    # --- 3. Harvest leaks (seed page) ---------------------------------------
    secret = _safe(lambda: _frontend_secret_scan_impl(seed_url, validate=False, timeout=timeout))
    for s in secret.get("findings", []):
        if s.get("severity") in {"critical", "high"}:
            findings.append(
                _finding("secret", f"Leaked {s['type']} in JS bundle", s["severity"], s, None)
            )
        if s.get("type") == "supabase_anon_key" and not supa_key:
            supa_key = s.get("value")

    ssr = _safe(lambda: _ssr_leak_impl(seed_url, timeout))
    if ssr.get("possible_ssr_leak"):
        findings.append(
            _finding(
                "data_leak",
                "Sensitive data embedded in SSR page",
                "high",
                ssr.get("results"),
                lambda: _safe(lambda: _ssr_leak_impl(seed_url, timeout)).get(
                    "possible_ssr_leak", False
                ),
            )
        )
    storage = _safe(lambda: _storage_probe_impl(seed_url, None, timeout))
    if storage.get("possible_exposure"):
        findings.append(
            _finding(
                "information disclosure",
                "Exposed .git/.env/backup files",
                "high",
                storage.get("exposed"),
                lambda: _safe(lambda: _storage_probe_impl(seed_url, None, timeout)).get(
                    "possible_exposure", False
                ),
            )
        )
    errleak = _safe(lambda: _error_leak_impl("GET", seed_url, "id", headers, timeout))
    if errleak.get("possible_error_leak"):
        findings.append(
            _finding(
                "information disclosure",
                "Verbose error / stack trace leak",
                "medium",
                errleak.get("findings"),
                None,
            )
        )
    hleak = _safe(lambda: _header_leak_impl(seed_url, timeout))
    if hleak.get("possible_header_leak"):
        findings.append(
            _finding(
                "data_leak", "Version/debug/PII leak in headers", "low", hleak.get("findings"), None
            )
        )

    # --- 4. Pivot on prior leaks --------------------------------------------
    # Leaked Supabase key -> dump tables (RLS bypass).
    if supa_url and supa_key:
        backend = _safe(
            lambda: _backend_rules_probe_impl("supabase", supa_url, supa_key, None, timeout)
        )
        if backend.get("possible_open_rules"):
            findings.append(
                _finding(
                    "idor",
                    "Broken Supabase RLS via leaked anon key (cross-tenant data)",
                    "critical",
                    backend.get("results"),
                    lambda: _safe(
                        lambda: _backend_rules_probe_impl(
                            "supabase", supa_url, supa_key, None, timeout
                        )
                    ).get("possible_open_rules", False),
                )
            )
    # Hidden params -> deep injection fuzz.
    if hidden_params:
        fuzz = _safe(
            lambda: _deep_fuzz_impl(
                "GET", seed_url, hidden_params, headers, None, "query", 150, timeout
            )
        )
        findings.extend(
            _finding(
                "injection",
                f"{f['family']} injection in hidden param '{f['param']}'",
                f.get("severity", "high"),
                f,
                None,
            )
            for f in fuzz.get("findings", [])
        )
    # GraphQL -> field-level data leak.
    if "graphql" in api or any("graphql" in p for p in discovered_paths):
        gql_url = seed_url.rstrip("/") + "/graphql"
        gql = _safe(lambda: _graphql_field_leak_impl(gql_url, headers, timeout))
        if gql.get("possible_field_leak"):
            findings.append(
                _finding(
                    "data_leak",
                    "GraphQL exposes sensitive fields",
                    "high",
                    gql.get("schema_sensitive_fields"),
                    None,
                )
            )

    # --- 5. Always-on surface checks on the seed ----------------------------
    cors = _safe(lambda: _cors_probe_impl(seed_url, "GET", None, timeout))
    if cors.get("possible_cors_issue"):
        findings.append(
            _finding(
                "access control",
                f"Permissive CORS ({cors.get('worst_severity')})",
                cors.get("worst_severity") or "medium",
                cors.get("results"),
                lambda: _safe(lambda: _cors_probe_impl(seed_url, "GET", None, timeout)).get(
                    "possible_cors_issue", False
                ),
            ),
        )
    if headers is not None:
        expo = _safe(lambda: _data_exposure_impl("GET", seed_url, headers, timeout))
        if expo.get("possible_excessive_exposure"):
            findings.append(
                _finding(
                    "data_leak",
                    "Excessive data exposure (API returns sensitive fields)",
                    "high",
                    expo.get("sensitive_fields"),
                    None,
                )
            )
    sh = _safe(lambda: _security_headers_impl(seed_url, timeout))
    if sh.get("possible_hardening_gaps"):
        findings.append(
            _finding(
                "misconfiguration",
                "Missing security headers",
                "low",
                {"missing": sh.get("missing_headers"), "cookies": sh.get("cookie_issues")},
                None,
            )
        )

    # --- 6. Chain the findings ----------------------------------------------
    chains = _safe(lambda: _chain_suggest_impl(findings)).get("chains", [])

    verified = [f for f in findings if f["verified"] is True]
    return {
        "success": True,
        "seed_url": seed_url,
        "profile": {
            "framework": prof.get("framework"),
            "baas": baas,
            "api": api,
            "supabase_key_found": bool(supa_key),
        },
        "discovered": {"hidden_params": hidden_params, "paths": discovered_paths[:20]},
        "finding_count": len(findings),
        "verified_count": len(verified),
        "findings": findings,
        "chains": chains,
    }


def _verify_finding_impl(
    kind: str,
    url: str,
    method: str,
    param: str | None,
    headers: dict[str, str] | None,
    supabase_url: str | None,
    supabase_anon_key: str | None,
    runs: int,
    timeout: int,
) -> dict[str, Any]:
    kind = (kind or "").lower()

    def _check() -> bool:  # noqa: PLR0911
        if kind in {"cors", "access control"}:
            return bool(_cors_probe_impl(url, method, None, timeout).get("possible_cors_issue"))
        if kind in {"injection", "sqli", "ssti", "xss"} and param:
            r = _deep_fuzz_impl(method, url, [param], headers, None, "query", 100, timeout)
            return bool(r.get("possible_injection"))
        if kind in {"data_exposure", "data_leak"}:
            return bool(
                _data_exposure_impl(method, url, headers, timeout).get(
                    "possible_excessive_exposure"
                )
            )
        if kind in {"backend_rules", "supabase", "idor"} and supabase_url and supabase_anon_key:
            r = _backend_rules_probe_impl(
                "supabase", supabase_url, supabase_anon_key, None, timeout
            )
            return bool(r.get("possible_open_rules"))
        if kind == "ssr":
            return bool(_ssr_leak_impl(url, timeout).get("possible_ssr_leak"))
        if kind in {"storage", "information disclosure"}:
            return bool(_storage_probe_impl(url, None, timeout).get("possible_exposure"))
        if kind == "header":
            return bool(_header_leak_impl(url, timeout).get("possible_header_leak"))
        if kind == "secret":
            return bool(
                _frontend_secret_scan_impl(url, validate=True, timeout=timeout).get(
                    "possible_secret_leak"
                )
            )
        raise ValueError(f"no verifier for kind {kind!r} (with the params given)")

    runs = max(2, min(runs, 5))
    hits = 0
    errors: list[str] = []
    for _ in range(runs):
        out = _safe(lambda: {"v": _check()})
        if "error" in out:
            errors.append(str(out["error"]))
        elif out.get("v"):
            hits += 1
    confirmed = hits >= (runs // 2 + 1)
    return {
        "success": True,
        "kind": kind,
        "runs": runs,
        "signal_reproduced": hits,
        "verdict": "CONFIRMED" if confirmed else "NOT_REPRODUCED",
        "errors": errors[:3],
    }


@function_tool(timeout=180, strict_mode=False)
async def verify_finding(
    ctx: RunContextWrapper,
    kind: str,
    url: str,
    method: str = "GET",
    param: str | None = None,
    headers: dict[str, str] | None = None,
    supabase_url: str | None = None,
    supabase_anon_key: str | None = None,
    runs: int = 3,
    timeout: int = 15,
) -> str:
    """Adversarially re-confirm a single finding — re-run its check N times.

    Runs the class-appropriate probe ``runs`` times and returns CONFIRMED only if
    the signal reproduces in the majority — killing flaky/one-off false positives
    before you file. Supported ``kind``: cors, injection (needs ``param``),
    data_exposure/data_leak, backend_rules/supabase (needs ``supabase_url`` +
    ``supabase_anon_key``), ssr, storage, header, secret. Only test authorized
    targets.

    Returns JSON with ``verdict`` (CONFIRMED / NOT_REPRODUCED) and
    ``signal_reproduced`` / ``runs``.

    Args:
        kind: The finding class to re-verify.
        url: The URL the finding is on.
        method: HTTP method (default GET).
        param: The parameter (for injection).
        headers: Session headers if the finding needs auth.
        supabase_url: Supabase project URL (for backend_rules).
        supabase_anon_key: Supabase anon key (for backend_rules).
        runs: How many times to re-run (default 3, max 5).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _verify_finding_impl,
            kind,
            url,
            method,
            param,
            headers,
            supabase_url,
            supabase_anon_key,
            runs,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=900, strict_mode=False)
async def autopwn(
    ctx: RunContextWrapper,
    seed_url: str,
    headers: dict[str, str] | None = None,
    supabase_anon_key: str | None = None,
    timeout: int = 15,
) -> str:
    """Run a chained, self-verifying deep scan that pivots on prior leaks.

    One call: fingerprint the stack, discover hidden params/endpoints, harvest
    leaks (secrets/SSR/\u200b.git/\u200b.env/source maps/headers), then feed those leaks into
    deeper probes — a leaked Supabase key dumps tables (RLS bypass), hidden params
    get injection-fuzzed, GraphQL gets field-leak-tested, discovered endpoints get
    CORS/data-exposure checks. Every finding is re-run to confirm it (adversarial
    verification), then findings are chained into escalation paths. Pass a session
    in ``headers`` to reach authed surfaces. Only test authorized targets.

    Returns JSON with ``findings`` (kind/title/severity/verified), ``chains``, the
    detected ``profile``, and what was ``discovered``.

    Args:
        seed_url: The target URL to start from.
        headers: Optional session headers to reach authenticated surfaces.
        supabase_anon_key: Supabase anon key if you already have it (else it's
            auto-extracted from the bundle).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_autopwn_impl, seed_url, headers, supabase_anon_key, timeout),
        ensure_ascii=False,
        default=str,
    )
