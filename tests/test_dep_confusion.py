"""Dependency-confusion / typosquat detection — pure-function tests (no network)."""

from __future__ import annotations

import json

from strix.tools.dep_confusion.tools import (
    _edit_distance_le1,
    check_names,
    parse_manifest,
    typosquat_of,
)


def test_parse_package_json() -> None:
    content = json.dumps(
        {"dependencies": {"react": "^18", "@acme/utils": "1.0"}, "devDependencies": {"jest": "29"}}
    )
    assert set(parse_manifest(content, "npm")) == {"react", "@acme/utils", "jest"}


def test_parse_requirements_txt() -> None:
    content = "requests==2.32.0\n# comment\nflask>=3\n-e .\nacme-internal\n"
    assert set(parse_manifest(content, "pypi")) == {"requests", "flask", "acme-internal"}


def test_parse_pyproject_toml() -> None:
    content = (
        '[project]\nname="x"\ndependencies=["requests>=2","fastapi"]\n'
        '[project.optional-dependencies]\ndev=["pytest"]\n'
    )
    assert set(parse_manifest(content, "pypi")) == {"requests", "fastapi", "pytest"}


def test_parse_go_mod() -> None:
    content = "module x\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n\tgolang.org/x/net v0.1.0\n)\n"
    assert set(parse_manifest(content, "go")) == {"github.com/foo/bar", "golang.org/x/net"}


def test_edit_distance() -> None:
    assert _edit_distance_le1("requestz", "requests")  # 1 substitution
    assert _edit_distance_le1("reqeusts", "requests")  # adjacent transposition
    assert _edit_distance_le1("loadsh", "lodash")  # adjacent transposition
    assert _edit_distance_le1("axioss", "axios")  # insertion
    assert _edit_distance_le1("react", "reactt")  # insertion
    assert not _edit_distance_le1("react", "react")  # identical is not a squat
    assert not _edit_distance_le1("react", "angular")


def test_typosquat_detection() -> None:
    assert typosquat_of("reqeusts", "pypi") == "requests"  # transposition
    assert typosquat_of("djngo", "pypi") == "django"  # 1 deletion
    assert typosquat_of("loadsh", "npm") == "lodash"  # transposition
    assert typosquat_of("cross_env", "npm") == "cross-env"  # separator swap
    assert typosquat_of("react", "npm") is None  # it IS the popular package
    assert typosquat_of("totally-unrelated-pkg", "npm") is None


def test_check_names_flags_unclaimed_internal() -> None:
    def fetcher(url: str) -> int:
        return 404 if "acme-secret" in url else 200

    findings = check_names(
        ["acme-secret-lib", "requests"], "pypi", fetcher=fetcher, internal_prefixes=("acme-",)
    )
    by_name = {f["name"]: f for f in findings}
    assert by_name["acme-secret-lib"]["risk"] == "dependency_confusion"
    assert "requests" not in by_name  # claimed + canonical => no finding


def test_check_names_flags_typosquat_even_when_published() -> None:
    def fetcher(url: str) -> int:
        return 200  # squat is actually published on the registry

    findings = check_names(["reqeusts"], "pypi", fetcher=fetcher)
    assert findings[0]["risk"] == "typosquat"
    assert findings[0]["typosquat_of"] == "requests"


def test_network_error_is_not_treated_as_unclaimed() -> None:
    findings = check_names(["some-random-name"], "pypi", fetcher=lambda _url: 0)
    assert findings == []  # status 0 (network error) must not be a confusion finding
