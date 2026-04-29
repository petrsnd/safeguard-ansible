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
│   ├── tests/                           # Automated integration test suite
│   │   ├── pytest.ini                   # Pytest config & markers
│   │   ├── requirements.txt             # Test dependencies
│   │   ├── conftest.py                  # Session fixtures, playbook runner, auto-skip
│   │   ├── test_safeguardcredentials.py # A2A lookup plugin tests (7 tests)
│   │   ├── test_safeguardaccessrequest.py # Access request plugin tests (11 tests)
│   │   ├── helpers/
│   │   │   ├── __init__.py
│   │   │   ├── certificates.py          # Self-signed cert & SSH key generation
│   │   │   └── provisioning.py          # SPP object CRUD (SgAns_ prefix)
│   │   ├── playbooks/                   # Test playbooks run by pytest via subprocess
│   │   │   ├── a2a_password.yml
│   │   │   ├── a2a_privatekey.yml
│   │   │   ├── a2a_known_password.yml
│   │   │   ├── a2a_multi_key.yml
│   │   │   ├── a2a_missing_appliance.yml
│   │   │   ├── a2a_missing_cert.yml
│   │   │   ├── a2a_invalid_credtype.yml
│   │   │   ├── accessrequest_password.yml
│   │   │   ├── accessrequest_privatekey.yml
│   │   │   ├── accessrequest_account.yml
│   │   │   ├── accessrequest_sshkey_account.yml
│   │   │   ├── accessrequest_known_password.yml
│   │   │   ├── accessrequest_envvars.yml
│   │   │   ├── accessrequest_invalid_credtype.yml
│   │   │   └── accessrequest_bad_credentials.yml
│   │   └── Ansible/                     # Legacy manual test inventory
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
│               ├── safeguardcredentials.py   # Lookup plugin — A2A credential retrieval
│               └── safeguardaccessrequest.py # Lookup plugin — Access Request credential retrieval
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

An Ansible Galaxy collection providing two **lookup plugins** for retrieving
credentials from SPP.

#### safeguardcredentials (A2A)

- **Plugin**: `oneidentity.safeguardcollection.safeguardcredentials`
- **Auth**: Client certificate via A2A registration
- **Dependency**: `pysafeguard>=8,<9`
- **Usage**: `{{ lookup('oneidentity.safeguardcollection.safeguardcredentials', api_key, a2aconnection=conn) }}`

Uses `pysafeguard.A2AContext` to authenticate with a client certificate and
retrieve credentials (passwords or SSH private keys) by API key. Supports
multiple API keys in a single lookup call.

#### safeguardaccessrequest

- **Plugin**: `oneidentity.safeguardcollection.safeguardaccessrequest`
- **Auth**: Username/password via PKCE (PkceAuth)
- **Dependency**: `pysafeguard>=8,<9`
- **Usage**: `{{ lookup('oneidentity.safeguardcollection.safeguardaccessrequest', 'asset', spp_appliance=host, ...) }}`

Uses `pysafeguard.SafeguardClient` with `PkceAuth` to authenticate a user and
retrieve credentials through the Access Request workflow. Supports password and
SSH key retrieval. All connection options support environment variable and
ansible.cfg ini fallbacks.

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

### Automated integration tests (lookup plugins)

The collection has a pytest-based integration test suite that runs against a
live SPP appliance. Tests are in `collection/tests/`.

**Prerequisites**: Python ≥ 3.10, `pip install -r collection/tests/requirements.txt`

**Running**:

```bash
cd collection/tests
SPP_HOST=<appliance-ip> SPP_ADMIN_PASSWORD=<admin-pw> python3 -m pytest -v
```

**Environment variables**:

| Variable             | Required | Description |
|----------------------|----------|-------------|
| `SPP_HOST`           | Yes      | Appliance IP or hostname |
| `SPP_ADMIN_PASSWORD` | No       | Bootstrap admin password (default: `Admin123`) |
| `SPP_CA_FILE`        | No       | TLS CA bundle path (disables TLS verify if unset) |

All 18 tests skip automatically when `SPP_HOST` is not set.

**What the tests do**:

1. Create a fully-privileged test admin using the bootstrap admin (PKCE auth)
2. Provision test objects (asset, accounts, cert user, A2A registration, access
   policies) — all with `SgAns_` prefix for easy identification
3. Build and install the collection into a temp directory
4. Run Ansible playbooks via subprocess against the live appliance
5. Verify credentials are retrieved correctly (including value-match checks)
6. Clean up all provisioned objects in reverse order

**Test coverage** (18 tests):

- **A2A plugin** (7 tests): password retrieval, password value correctness,
  private key retrieval, multi-key retrieval, invalid API key, missing
  appliance, missing certificate, invalid credential type
- **Access request plugin** (11 tests): password retrieval, explicit account
  name, password value correctness, private key retrieval, SSH key with
  account name, env var configuration, invalid asset, invalid account,
  invalid credential type, bad user credentials

### Manual integration testing (credential type plugin)

Follow the step-by-step instructions in `credential_type_plugin/tests/steps.txt`
for AWX/AAP deployment and verification.

## PySafeguard API usage

### A2A credential retrieval

The safeguardcredentials plugin and credential type plugin use
`pysafeguard.A2AContext`:

```python
from pysafeguard import A2AContext, A2AType

# Context manager for multiple retrievals
with A2AContext(host, cert_file, key_file, verify=verify) as a2a:
    pw = a2a.retrieve_password(api_key)
    key = a2a.retrieve_private_key(api_key)
```

Credentials are returned as `HiddenString` objects. Use `.value` to extract
the plaintext string.

### Access request credential retrieval

The safeguardaccessrequest plugin uses `pysafeguard.SafeguardClient` with
`PkceAuth` (PKCE authentication — does not require a browser):

```python
from pysafeguard import SafeguardClient, PkceAuth, Service

with SafeguardClient(host, auth=PkceAuth(provider, user, pw), verify=verify) as client:
    client.login()
    resp = client.get(Service.CORE, "Me/RequestEntitlements", params={...})
    resp = client.post(Service.CORE, "AccessRequests", json={...})
    resp = client.post(Service.CORE, f"AccessRequests/{id}/CheckOutPassword")
```

**Important**: `CheckOutPassword` returns a plain JSON string, but
`CheckOutSshKey` returns a JSON object with keys `PrivateKey`, `Passphrase`,
`PublicKey`, etc. The plugin extracts the `PrivateKey` field.

**Note**: `PasswordAuth` (ROPC) is disabled by default on SPP appliances.
Always use `PkceAuth` instead — it has an identical constructor signature.

### The `verify` parameter

The `verify` parameter maps from the user-facing `spp_tls_cert` config:
- String path → passed as `verify=path` (CA bundle for TLS verification)
- `True` → passed as `verify=True` (use system CA store)
- `False` / omitted → passed as `verify=False` (disable TLS verification)

## CI/CD

Both components use Azure Pipelines (`azure-pipelines.yml`) for building and
publishing. The pipelines:

1. Use Python 3.12
2. Replace the placeholder version in `galaxy.yml` / `pyproject.toml` with the
   build version
3. Build the artifact (collection tarball or Python wheel)
4. Publish to GitHub Releases (all release branches)
5. Publish to Ansible Galaxy / PyPI (non-prerelease only)

**Do not change the version in `galaxy.yml` or `pyproject.toml` manually for
releases.** The CI pipeline stamps the version from the build ID.

## Code conventions

- Python ≥ 3.10 (no Python 2 compatibility shims)
- Use explicit imports (`from pysafeguard import A2AContext, A2AType`) — no wildcard imports
- 4-space indentation throughout
- Ansible plugin conventions: `DOCUMENTATION`, `EXAMPLES`, `RETURN` module-level strings
- reStructuredText-style docstrings (`:arg name:`, `:returns:`)
- Copyright headers on all source files
- `no_log: True` on options that contain secrets
- Use `PkceAuth` for user authentication (not `PasswordAuth` — ROPC is disabled by default)
- All test objects use `SgAns_` prefix with uuid suffix for identification and cleanup

## Versioning

The version placeholder in `galaxy.yml` and `pyproject.toml` is `1.0.0`. The Azure
Pipeline replaces this at build time with the actual release version
(`1.2.<BuildId>`).
