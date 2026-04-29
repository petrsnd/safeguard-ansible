# AGENTS.md -- safeguard-ansible

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
├── collection/                          # Ansible Galaxy collection
│   ├── azure-pipelines.yml              # CI/CD: build & publish collection
│   ├── tests/                           # Integration test playbooks & inventory
│   │   └── Ansible/
│   │       ├── inventory.yaml
│   │       └── playbooks/playbook.yaml
│   └── oneidentity/safeguard/           # The collection itself
│       ├── galaxy.yml                   # Collection metadata (namespace, version, deps)
│       ├── meta/runtime.yml             # Ansible version requirement
│       ├── changelogs/config.yaml       # antsibull-changelog config
│       ├── README.md
│       ├── LICENSE
│       └── plugins/
│           ├── README.md                # Plugin usage documentation with examples
│           └── lookup/
│               ├── safeguardaccessrequest.py # Lookup plugin — retrieves credentials via Access Requests
│               └── safeguardcredentials.py   # Lookup plugin — retrieves A2A credentials
│
└── credential_type_plugin/              # AWX/AAP credential type plugin
    ├── azure-pipelines.yml              # CI/CD: build & publish to PyPI
    ├── pyproject.toml                   # PyPI packaging (safeguardcredentialtype)
    ├── README.md                        # Installation & configuration docs
    ├── Images/                          # Screenshots for docs
    ├── tests/                           # Manual test steps & playbooks
    │   ├── steps.txt
    │   └── playbook.yaml
    └── safeguardcredentialtype/
        └── __init__.py                  # AWX credential plugin implementation
```

## Components

### Ansible Collection (`collection/oneidentity/safeguard/`)

An Ansible Galaxy collection providing a **lookup plugin** that retrieves
credentials from SPP via the Application-to-Application (A2A) API.

- **Plugin**: `oneidentity.safeguardcollection.safeguardcredentials`
- **Type**: Lookup plugin
- **Dependency**: `pysafeguard>=8,<9`
- **Usage**: `{{ lookup('oneidentity.safeguardcollection.safeguardcredentials', api_key, a2aconnection=conn) }}`

The lookup plugin uses `pysafeguard.A2AContext` to authenticate with a client
certificate and retrieve credentials (passwords or SSH private keys) by API key.

### Credential Type Plugin (`credential_type_plugin/`)

A Python package (`safeguardcredentialtype`) that integrates with
AWX / Ansible Automation Platform as a managed credential type. Installed via
pip into the AAP environment.

- **Entry point**: `awx.credential_plugins` → `spp_plugin`
- **Dependency**: `pysafeguard>=8,<9`
- **Published to**: PyPI as `safeguardcredentialtype`

## Build commands

### Collection

```bash
cd collection/oneidentity/safeguard
ansible-galaxy collection build
```

The resulting `.tar.gz` can be installed with:

```bash
ansible-galaxy collection install oneidentity-safeguardcollection-<version>.tar.gz
```

### Credential Type Plugin

```bash
cd credential_type_plugin
python3 -m build
```

## Testing

There are no automated unit tests. Testing is done manually against a live SPP
appliance. See `collection/tests/` for sample playbooks and inventory, and
`credential_type_plugin/tests/steps.txt` for AWX testing instructions.

### Integration testing (lookup plugin)

1. Configure `collection/tests/Ansible/inventory.yaml` with appliance details
2. Run:
   ```bash
   cd collection/tests/Ansible
   ansible-playbook -i inventory.yaml playbooks/playbook.yaml
   ```

### Integration testing (credential type plugin)

Follow the step-by-step instructions in `credential_type_plugin/tests/steps.txt`
for AWX/AAP deployment and verification.

## PySafeguard API usage

Both plugins use `pysafeguard.A2AContext` for A2A credential retrieval:

```python
from pysafeguard import A2AContext, A2AType

# One-shot retrieval
password = A2AContext.quick_retrieve_password(
    host, api_key, cert_file, key_file, verify=tls_cert_path_or_false
)
credential = password.value  # HiddenString → str

# Context manager for multiple retrievals
with A2AContext(host, cert_file, key_file, verify=verify) as a2a:
    pw = a2a.retrieve_password(api_key)
    key = a2a.retrieve_private_key(api_key)
```

The `verify` parameter maps from the user-facing `spp_tls_cert` config:
- String path → passed as `verify=path` (CA bundle for TLS verification)
- `True` → passed as `verify=True` (use system CA store)
- `False` / omitted → passed as `verify=False` (disable TLS verification)

Credentials are returned as `HiddenString` objects. Use `.value` to extract
the plaintext string.

## CI/CD

Both components use Azure Pipelines (`azure-pipelines.yml`) for building and
publishing. The pipelines:

1. Use Python 3.12
2. Replace the placeholder version in `galaxy.yml` / `setup.py` with the build version
3. Build the artifact (collection tarball or Python wheel)
4. Publish to GitHub Releases (all release branches)
5. Publish to Ansible Galaxy / PyPI (non-prerelease only)

**Do not change the version in `galaxy.yml` or `setup.py` manually for
releases.** The CI pipeline stamps the version from the build ID.

## Code conventions

- Python ≥ 3.10 (no Python 2 compatibility shims)
- Use explicit imports (`from pysafeguard import A2AContext, A2AType`) — no wildcard imports
- 4-space indentation throughout
- Ansible plugin conventions: `DOCUMENTATION`, `EXAMPLES`, `RETURN` module-level strings
- reStructuredText-style docstrings (`:arg name:`, `:returns:`)

## Versioning

The version placeholder in `galaxy.yml` and `pyproject.toml` is `1.0.0`. The Azure
Pipeline replaces this at build time with the actual release version
(`1.2.<BuildId>`).
