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
├── versionnumber.ps1                    # Version stamping script (dual-component)
├── pipeline-templates/                  # Shared pipeline step templates
│   ├── global-variables.yml             # isTagBuild, isCollectionTag, isCredPluginTag
│   ├── build-collection-steps.yml       # Collection build steps
│   └── build-credplugin-steps.yml       # Credential plugin build steps
├── collection/                          # Ansible Galaxy collection
│   ├── azure-pipelines.yml              # Collection CI/CD pipeline
│   ├── tests/                           # Automated integration test suite
│   │   ├── pytest.ini                   # Pytest config & markers
│   │   ├── requirements.txt             # Test dependencies
│   │   ├── conftest.py                  # Session fixtures, playbook runner, auto-skip
│   │   ├── test_safeguardcredentials.py # A2A lookup plugin tests (8 tests)
│   │   ├── test_safeguardaccessrequest.py # Access request plugin tests (10 tests)
│   │   ├── test_tls_verification.py    # TLS certificate verification tests (3 tests)
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
│   │   │   ├── a2a_tls_verified.yml
│   │   │   ├── accessrequest_password.yml
│   │   │   ├── accessrequest_privatekey.yml
│   │   │   ├── accessrequest_account.yml
│   │   │   ├── accessrequest_sshkey_account.yml
│   │   │   ├── accessrequest_known_password.yml
│   │   │   ├── accessrequest_envvars.yml
│   │   │   ├── accessrequest_invalid_credtype.yml
│   │   │   ├── accessrequest_tls_verified.yml
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
    ├── azure-pipelines.yml              # Credential plugin CI/CD pipeline
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

**Design note — no check-in after checkout**: The plugin intentionally does not
call `CheckInPassword` / `CheckInSshKey` after retrieving the credential.
Checking in triggers credential rotation on the appliance, which would change
the password/key immediately after retrieval — making the returned value useless.
Instead, access requests are left to expire naturally per the access policy's
session duration settings.

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
| `SPP_CA_FILE`        | No       | TLS CA bundle path (uses system CA store if unset) |

All 21 tests skip automatically when `SPP_HOST` is not set.

**CI limitation**: These tests cannot run in CI/CD pipelines because they
require a live SPP appliance. The pipeline's PR validation stage only builds
the artifacts (collection tarball and wheel) to verify packaging. Behavioral
correctness must be validated manually against a test appliance before release.

**What the tests do**:

1. Create a fully-privileged test admin using the bootstrap admin (PKCE auth)
2. Provision test objects (asset, accounts, cert user, A2A registration, access
   policies) — all with `SgAns_` prefix for easy identification
3. Build and install the collection into a temp directory
4. Run Ansible playbooks via subprocess against the live appliance
5. Verify credentials are retrieved correctly (including value-match checks)
6. Clean up all provisioned objects in reverse order

**Test coverage** (21 tests):

- **A2A plugin** (8 tests): password retrieval, password value correctness,
  private key retrieval, multi-key retrieval, invalid API key, missing
  appliance, missing certificate, invalid credential type
- **Access request plugin** (10 tests): password retrieval, explicit account
  name, password value correctness, private key retrieval, SSH key with
  account name, env var configuration, invalid asset, invalid account,
  invalid credential type, bad user credentials
- **TLS verification** (3 tests): A2A with CA bundle, access request with
  CA bundle, A2A fails without valid CA bundle

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

The `verify` parameter maps from the user-facing TLS options:
- `spp_ca_cert` is a path → passed as `verify=path` (CA bundle for TLS verification)
- `spp_validate_certs=True` (default) with no path → passed as `verify=True` (use system CA store)
- `spp_validate_certs=False` → passed as `verify=False` (disable TLS verification)

## CI/CD

The repository uses two separate Azure Pipelines (one per component), modeled
after PySafeguard's release semantics. Each pipeline only triggers when its
own component's files change.

### Pipeline structure

```
collection/azure-pipelines.yml
├── PRValidation          # Builds collection, no publishing
└── BuildCollection       # Builds + publishes collection to Galaxy

credential_type_plugin/azure-pipelines.yml
├── PRValidation          # Builds credential plugin, no publishing
└── BuildCredPlugin       # Builds + publishes credential plugin to PyPI
```

Shared build logic lives in `pipeline-templates/`:
- `global-variables.yml` — `isTagBuild`, `isCollectionTag`, `isCredPluginTag`
- `build-collection-steps.yml` — install ansible-core, version stamp, build collection
- `build-credplugin-steps.yml` — install build tools, version stamp, build wheel

### Version management

`versionnumber.ps1` reads the version from each component's metadata file
(`galaxy.yml` or `pyproject.toml`) and produces the package version:

- **Tag builds** (e.g. `collection-v2.0.0`): uses the tag as the version →
  publishes to Galaxy/PyPI as a full release
- **Dev builds** (merge to main/release-*): appends a dev suffix →
  `2.0.0-dev.N` for collection (SemVer), `2.0.0.devN` for credential plugin
  (PEP 440) → GitHub prerelease only

### Release workflow

To release the collection:
```bash
git tag collection-v2.0.0
git push origin collection-v2.0.0
```

To release the credential type plugin:
```bash
git tag credplugin-v2.0.0
git push origin credplugin-v2.0.0
```

Dev builds use `dev/` prefix tags (e.g. `dev/collection-v2.0.0-dev.123`) to
avoid re-triggering the pipeline's tag-based release triggers.

### Service connections

- **GitHub**: `PangaeaBuild-GitHub` (same as PySafeguard)
- **Galaxy API key**: Azure Key Vault `SafeguardBuildSecrets` → `AnsibleGalaxyApiKey1`
- **PyPI**: `pypiOneIdentity` via Twine

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

Both components use semantic versioning. The version in `galaxy.yml` and
`pyproject.toml` is the source of truth (currently `2.0.0`). The pipeline
reads this and either uses it as-is (tag builds) or appends a dev suffix.

Component-prefixed git tags trigger official releases:
- `collection-v<X.Y.Z>` → Ansible Galaxy
- `credplugin-v<X.Y.Z>` → PyPI

The version in the metadata files should be bumped when preparing a new
release. It does not need a placeholder — `versionnumber.ps1` handles
the dev suffix for non-tag builds automatically.
