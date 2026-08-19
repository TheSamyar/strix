"""OAST MCP tools — hand out payload domains and poll for blind callbacks."""

from __future__ import annotations

import asyncio
import json

from agents import RunContextWrapper, function_tool

from strix.tools.oast.client import get_domain, poll


@function_tool(timeout=30)
async def oast_get_domain(ctx: RunContextWrapper, server: str | None = None) -> str:
    """Get an out-of-band (OAST) payload domain to catch blind callbacks.

    Registers an interactsh listener and returns a unique ``<token>.<server>``
    domain. Plant it in payloads for blind bugs — SSRF (``http://<domain>``),
    blind XSS, DNS exfil, RCE (``curl <domain>``), indirect prompt-injection —
    then call ``oast_poll`` to see if the target called back. A callback proves
    the vulnerability. Set ``STRIX_INTERACTSH_SERVER`` to use a self-hosted
    server instead of the public default.

    Returns JSON with ``domain``, ``url``, ``correlation_id``, and ``server``.

    Args:
        server: interactsh server host (default ``oast.pro`` or the env override).
    """
    del ctx
    return json.dumps(await asyncio.to_thread(get_domain, server), ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def oast_poll(ctx: RunContextWrapper, correlation_id: str | None = None) -> str:
    """Poll the OAST listener for interactions (proof of a blind callback).

    Fetches and decrypts any DNS/HTTP interactions the target made to a domain
    from ``oast_get_domain``. Each interaction (``protocol``, ``remote_address``,
    ``timestamp``, ``raw_request``) proves the target reached the payload host —
    e.g. a DNS lookup of your token confirms blind SSRF. ``got_callback: true``
    means the vuln fired.

    Returns JSON with ``new_interactions``, ``total_interactions``,
    ``got_callback``, and the decrypted ``interactions``.

    Args:
        correlation_id: The id from ``oast_get_domain`` (defaults to the active
            session).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(poll, correlation_id), ensure_ascii=False, default=str
    )
