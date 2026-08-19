"""Gap Kali tools must be in the image, allowlist, and tooling skills."""

from pathlib import Path

from strix.skills import get_available_skills
from strix.tools.run_scanner.tools import _ALLOWLIST


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "containers" / "Dockerfile").read_text(encoding="utf-8")
SKILL_DIR = ROOT / "strix" / "skills" / "tooling"

# Packages (or go-module path fragments) the sandbox image must ship.
_IMAGE_PACKAGES = (
    "seclists",
    "exploitdb",
    "sslscan",
    "sstimap",
    "commix",
    "wpscan",
    "whatweb",
    "nikto",
    "hashid",
    "crlfuzz",
)

# MCP/CLI run_scanner names. seclists is wordlists, not a scanner binary.
_SCANNER_TOOLS = (
    "sslscan",
    "sstimap",
    "commix",
    "whatweb",
    "crlfuzz",
    "searchsploit",
    "hashid",
    "wpscan",
    "nikto",
)

_SKILL_PLAYBOOKS = _SCANNER_TOOLS


def test_dockerfile_installs_gap_packages() -> None:
    missing = [pkg for pkg in _IMAGE_PACKAGES if pkg not in DOCKERFILE]
    assert missing == []


def test_run_scanner_allowlists_gap_tools() -> None:
    missing = [name for name in _SCANNER_TOOLS if name not in _ALLOWLIST]
    assert missing == []


def test_tooling_skills_cover_gap_tools() -> None:
    names = {skill["name"] for skill in get_available_skills()["tooling"]}
    missing = [name for name in _SKILL_PLAYBOOKS if name not in names]
    assert missing == []
    for name in _SKILL_PLAYBOOKS:
        assert (SKILL_DIR / f"{name}.md").is_file()
