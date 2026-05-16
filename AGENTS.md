# AGENTS.md — safeguard-ansible

Ansible plugins for integrating with One Identity Safeguard for Privileged
Passwords (SPP). Depends on the
[PySafeguard](https://github.com/OneIdentity/PySafeguard) Python SDK (v8+).

Requires Python ≥ 3.10. Requires Ansible ≥ 2.14.

## Project structure

```
safeguard-ansible/
├── AGENTS.md
├── README.md
├── LICENSE
├── versionnumber.ps1                    # Version stamping script (dual-component)
├── pipeline-templates/                  # Shared pipeline step templates
├── collection/                          # Ansible Galaxy collection
│   ├── azure-pipelines.yml
│   ├── tests/                           # pytest: 32 unit + 21 integration
│   │   ├── conftest.py                  # Session fixtures, playbook runner, auto-skip
│   │   ├── helpers/                     # certificates.py, provisioning.py
│   │   └── playbooks/                   # Ansible playbooks run by pytest
│   └── oneidentity/safeguard/
│       ├── galaxy.yml                   # Collection metadata (version source of truth)
│       └── plugins/lookup/
│           ├── safeguardcredentials.py   # A2A credential retrieval
│           └── safeguardaccessrequest.py # Access Request credential retrieval
└── credential_type_plugin/              # AWX/AAP credential type plugin
    ├── azure-pipelines.yml
    ├── pyproject.toml                   # PyPI packaging (version source of truth)
    ├── tests/                           # pytest: 15 unit + 4 integration
    └── safeguardcredentialtype/
        └── __init__.py                  # AWX credential plugin implementation
```

## Components

### Ansible Collection (`oneidentity.safeguardcollection`)

Two **lookup plugins** for retrieving credentials from SPP:

- **safeguardcredentials** — A2A credential retrieval via client certificate.
  Uses `pysafeguard.A2AContext`.
- **safeguardaccessrequest** — Access Request workflow via username/password
  (PKCE auth). Uses `pysafeguard.SafeguardClient` with `PkceAuth`.

### Credential Type Plugin (`safeguardcredentialtype`)

A Python package that integrates with AWX / Ansible Automation Platform as a
managed credential type. Entry point: `awx.credential_plugins` → `spp_plugin`.
Published to PyPI.

## Build commands

### Collection

```bash
cd collection/oneidentity/safeguard
ansible-galaxy collection build
ansible-galaxy collection install oneidentity-safeguardcollection-<version>.tar.gz
```

### Credential Type Plugin

```bash
cd credential_type_plugin
python3 -m build
```

## Code conventions

- Python ≥ 3.10 (no Python 2 compatibility shims)
- Use explicit imports — no wildcard imports
- 4-space indentation throughout
- Ansible plugin conventions: `DOCUMENTATION`, `EXAMPLES`, `RETURN` module-level strings
- reStructuredText-style docstrings (`:arg name:`, `:returns:`)
- Copyright headers on all source files
- `no_log: True` on options that contain secrets
- Use `PkceAuth` for user authentication (not `PasswordAuth` — ROPC is disabled by default)
- All test objects use `SgAns_` prefix with UUID suffix for identification and cleanup

## Versioning

Both components use semantic versioning. The version in `galaxy.yml` and
`pyproject.toml` is the source of truth. Component-prefixed git tags trigger
official releases:

- `collection-v<X.Y.Z>` → Ansible Galaxy
- `credplugin-v<X.Y.Z>` → PyPI

Do not manually edit version strings during builds — `versionnumber.ps1`
handles dev suffixes for non-tag builds automatically.

## On-demand skills

The following skills contain reference material loaded only when relevant.
Read the `SKILL.md` when your current task matches the trigger.

| Skill | When to read | File |
|-------|-------------|------|
| Testing Guide | Running tests, writing tests, investigating test failures, test environment setup | `.agents/skills/testing-guide/SKILL.md` |
| PySafeguard API | Working on plugin source code, debugging credential retrieval, PySafeguard SDK usage | `.agents/skills/pysafeguard-api/SKILL.md` |
| Build & Release | Preparing releases, modifying CI/CD pipelines, version management | `.agents/skills/build-and-release/SKILL.md` |
