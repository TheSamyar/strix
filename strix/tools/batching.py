"""Shared helper for batching a single-URL probe over a list of URLs.

Lets a passive per-URL probe accept an optional ``urls`` list and run its
existing impl once per URL in a single tool call — same per-URL analysis, far
fewer round-trips for the driving model. Zero capability change: the single-URL
path is untouched; batch mode just loops it.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from strix.config.settings import depth_cap


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
    cap = depth_cap(cap, cap * 10)  # STRIX_MAX_DEPTH: process 10x more URLs per call
    trimmed = [u for u in urls if u and u.strip()][:cap]
    # These are independent passive per-URL probes (no timing oracle), so run them
    # concurrently over a bounded pool — I/O-bound, so wall-clock drops ~Nx.
    if len(trimmed) > 1:
        workers = min(len(trimmed), depth_cap(8, 24))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda u: {"url": u, **impl(u, timeout)}, trimmed))
    else:
        results = [{"url": u, **impl(u, timeout)} for u in trimmed]
    out: dict[str, Any] = {"success": True, "results": results, "count": len(results)}
    over = len([u for u in urls if u and u.strip()]) - len(trimmed)
    if over > 0:
        out["dropped"] = over
    return out
