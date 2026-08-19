---
name: supply_chain_dependency_confusion
description: "Supply-chain testing: dependency confusion, typosquatting, malicious install scripts, lockfile integrity, and registry-scope misconfig — complements known-CVE SCA"
---

# Supply Chain: Dependency Confusion & Typosquatting

Known-CVE scanning (`[[dependency-cve-scanning]]`, osv/npm audit) finds *vulnerable* published packages. This skill finds the other class: packages an attacker can *publish or has published* to hijack a build — dependency confusion, typosquats, and malicious install hooks. Pair with the `dep_confusion` tool for the automated registry checks.

## What To Collect First

Enumerate every manifest and lockfile in the target (source repo, container images, client bundles):

- npm/yarn/pnpm: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `.npmrc`
- Python: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `setup.py`, `poetry.lock`
- Go: `go.mod`, `go.sum`
- Others: `Gemfile`, `composer.json`, `pom.xml`, `build.gradle`, `Cargo.toml`

From these, build the dependency list plus: declared registries/scopes, whether lockfiles are committed, and whether any package name *looks internal* (company prefix, scoped `@org/`, private-sounding names not on the public registry).

## Key Attacks

### Dependency Confusion (substitution)

If a build resolves an internal package name from a **public** registry when the private one is missing or lower-versioned, an attacker publishes a same-named public package (with a higher version) and gets code execution in the build.

Signals to flag:
- An internal-looking dependency name that is **unclaimed** on the public registry (npmjs/PyPI) — an attacker can register it.
- A scoped/prefixed name (`@acme/utils`, `acme-internal-...`) with **no scope-to-registry mapping** in `.npmrc`/`pip.conf` (no `@acme:registry=...`).
- Public and private registries both configured with public-first resolution or no `--index-url` pinning.
- Missing/uncommitted lockfile → resolution happens fresh at build time (confusion window open).

Exploit direction (report as risk, PoC only in an authorized/isolated context): publish a benign-versioned placeholder to the public registry and observe a build phone-home from a non-collecting canary. Never publish live malware.

### Typosquatting

An attacker publishes a package one keystroke from a popular one (`reqeusts`, `loadsh`, `crossenv`, `python-dateutil` vs `python3-dateutil`).

Flag dependencies that are ≤1 edit-distance (or common transposition/homoglyph) from a well-known package but are **not** the canonical one. Also flag names that differ only by hyphen/underscore/scope from a popular package.

### Malicious Install Scripts

- npm: `preinstall`/`install`/`postinstall` scripts in `package.json` or in a transitive dep — arbitrary code at `npm install`.
- Python: `setup.py` executing code at install; `pyproject.toml` build backends.
- Look for install-time network calls, base64 blobs, `curl|bash`, env-var exfil (`process.env`, `os.environ`) in dependency source.

### Lockfile & Integrity Weaknesses

- No committed lockfile, or lockfile without integrity hashes (`integrity`/`resolved` fields, `go.sum`).
- Integrity hashes pointing at a mutable/non-canonical registry.
- `resolved` URLs pointing at a private or attacker-controllable host.

### Registry & Scope Misconfig

- `.npmrc`/`pip.conf`/`.yarnrc` with credentials committed, `always-auth=false`, or a public registry aliased over a private scope.
- Git/HTTP dependency URLs (`git+http`, tarball URLs) on hosts the org doesn't control.
- CI configured to fall back to the public registry on private-registry failure.

## Testing Methodology

1. **Inventory** every manifest/lockfile across repo, images, and bundles.
2. **Classify** each dependency: public / private-mapped / internal-unmapped.
3. **Registry check** (use the `dep_confusion` tool): for internal-unmapped names, query the public registry — unclaimed ⇒ confusion risk; near-miss of a popular name ⇒ typosquat.
4. **Install-script audit** — grep manifests + top transitive deps for install hooks and network/exfil patterns.
5. **Lockfile/registry review** — presence, integrity hashes, scope mappings, committed creds.
6. **Report** with claimability status and remediation (claim the name, pin the scope registry, commit lockfiles, disable install scripts in CI).

## Validation Requirements

- Dependency confusion: the exact internal package name, proof it is unclaimed on the public registry, and the missing scope-to-registry mapping that allows public resolution.
- Typosquat: the suspect name, the canonical package it mimics, and the edit distance/transformation.
- Malicious script: the manifest/file and the offending install hook with its network/exfil behavior.
- Never publish live malicious packages; demonstrate risk with claimability + resolution config, or a benign canary in an isolated build only with explicit authorization.
