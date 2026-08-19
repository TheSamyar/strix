"""Shared helper for batching a single-URL probe over a list of URLs.

Lets a passive per-URL probe accept an optional ``urls`` list and run its
existing impl once per URL in a single tool call — same per-URL analysis, far
fewer round-trips for the driving model. Zero capability change: the single-URL
path is untouched; batch mode just loops it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable


def url_batch(
    impl: Callable[[str, int], dict[str, Any]],
    urls: list[str],
    timeout: int,
    *,
    cap: int = 25,
) -> dict[str, Any]:
    """Run ``impl(url, timeout)`` for each URL (capped) and collect the results.

    Each result is the impl's own dict with the ``url`` echoed in. Anything over
    ``cap`` is reported in ``dropped`` rather than silently skipped.
    """
    trimmed = [u for u in urls if u and u.strip()][:cap]
    results = [{"url": u, **impl(u, timeout)} for u in trimmed]
    out: dict[str, Any] = {"success": True, "results": results, "count": len(results)}
    over = len([u for u in urls if u and u.strip()]) - len(trimmed)
    if over > 0:
        out["dropped"] = over
    return out
