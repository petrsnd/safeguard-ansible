---
name: testing-guide
description: >-
  Use when running tests, writing tests, investigating test failures, or
  setting up a test environment. Covers both the Ansible collection tests
  (32 unit + 21 integration) and the credential type plugin tests
  (15 unit + 4 integration), including live appliance setup with SPP_HOST.
---

# Testing Guide

## Quick Reference

### Collection — unit tests only (no appliance needed)

```bash
cd collection/tests
pip install -r requirements.txt
python3 -m pytest test_unit.py -v
```

### Collection — all tests (requires live SPP appliance)

```bash
cd collection/tests
SPP_HOST=<appliance-ip> SPP_ADMIN_PASSWORD=<admin-pw> python3 -m pytest -v
```

### Credential type plugin — unit tests only

```bash
cd credential_type_plugin
pip install -r tests/requirements.txt
python3 -m pytest tests/test_unit.py -v
```

### Credential type plugin — all tests

```bash
cd credential_type_plugin
SPP_HOST=<appliance-ip> SPP_ADMIN_PASSWORD=<admin-pw> python3 -m pytest tests/ -v
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SPP_HOST` | Yes (integration) | — | Appliance IP or hostname |
| `SPP_ADMIN_PASSWORD` | No | `Admin123` | Bootstrap admin password |
| `SPP_CA_FILE` | No | — | TLS CA bundle path; disables TLS verification if unset |

Integration tests skip automatically when `SPP_HOST` is not set. Unit tests
always run regardless of environment.

---

## Test File Map

### Collection (`collection/tests/`)

| File | Type | Count | What it tests |
|------|------|-------|---------------|
| `test_unit.py` | Unit | 32 | `_resolve_verify` mapping, `_find_entitlement` matching/filtering/error handling, `_find_existing_request` state logic, `_checkout_with_retry` retry/timeout, `_create_or_reuse_request` success/reuse/error, `validate_certs` string normalization |
| `test_safeguardcredentials.py` | Integration | 8 | A2A password retrieval, value correctness, private key, multi-key, invalid API key, missing appliance, missing cert, invalid credential type |
| `test_safeguardaccessrequest.py` | Integration | 10 | Password retrieval, explicit account name, value correctness, private key, SSH key with account, env var config, invalid asset, invalid account, invalid credential type, bad credentials |
| `test_tls_verification.py` | Integration | 3 | A2A with CA bundle, access request with CA bundle, A2A fails without valid CA bundle |

### Credential type plugin (`credential_type_plugin/tests/`)

| File | Type | Count | What it tests |
|------|------|-------|---------------|
| `test_unit.py` | Unit | 15 | Plugin metadata, input/injector field definitions, `backend` function logic |
| `test_integration.py` | Integration | 4 | End-to-end A2A credential retrieval via the plugin's `backend` function |

---

## How Integration Tests Work

Both test suites follow the same pattern:

### 1. Bootstrap admin creates a test admin

The factory-default `Admin` user (authenticated via PKCE) creates a
fully-privileged test admin with all admin roles (`GlobalAdmin`, `AssetAdmin`,
`PolicyAdmin`, `UserAdmin`, `ApplianceAdmin`, `HelpdeskAdmin`,
`OperationsAdmin`, `Auditor`, `ApplicationAuditor`, `SystemAuditor`). All
subsequent provisioning uses this test admin.

### 2. Provision test objects

All test objects use the `SgAns_` prefix with a UUID suffix for easy
identification and cleanup. The provisioning chain:

- **Asset** — a test managed system
- **Accounts** — separate accounts for password and SSH key tests
- **Client certificate** — generated via `helpers/certificates.py`
- **Certificate user** — SPP user linked to the client cert thumbprint
- **A2A registration** — links cert user to retrievable accounts
- **Requester user, role, access policy** — for access request tests

### 3. Run tests

- **Collection tests** run Ansible playbooks via `subprocess` against the live
  appliance. The collection is built and installed into a temp directory first
  (the `installed_collection` fixture handles this).
- **Credential plugin tests** call the plugin's `backend` function directly.

### 4. Clean up

Fixtures clean up all provisioned objects in reverse order via `yield` in
session-scoped fixtures. Partial setup failures also trigger best-effort
cleanup.

---

## Test Helpers

### `helpers/certificates.py`

- `generate_client_cert(tmpdir)` → `(cert_path, key_path, thumbprint)`
- `generate_ssh_keypair(tmpdir)` → `(public_key, private_key)`
- `read_cert_base64(cert_path)` → base64-encoded certificate string
- `build_ca_bundle(client, tmpdir)` → path to CA bundle built from appliance
  trusted certs

### `helpers/provisioning.py`

CRUD operations against the SPP API. All `create_*` functions accept a
`label` parameter and prepend `SgAns_` with a UUID suffix. Key functions:

- `create_local_user`, `create_cert_user`, `set_user_password`
- `create_asset`, `create_account`, `set_account_password`, `set_account_ssh_key`
- `create_a2a_registration`, `add_retrievable_account`
- `create_role`, `create_access_policy`
- `upload_trusted_cert`, `delete_trusted_cert`
- Matching `delete_*` functions for cleanup

---

## Playbook-Based Testing (Collection)

Integration tests for the collection run actual Ansible playbooks in
`collection/tests/playbooks/`. The `run_playbook()` helper in `conftest.py`:

1. Accepts a playbook filename, extra vars, and environment
2. Runs `ansible-playbook` via subprocess with `-i localhost,`
3. Passes non-secret variables via `-e` (JSON) and secrets via env vars
4. Asserts `returncode == 0` unless `expect_failure=True`

The `ansible_env` fixture sets `ANSIBLE_COLLECTIONS_PATH` to the temp install
directory and configures TLS settings.

### Playbook naming convention

- `a2a_*.yml` — A2A credential plugin tests
- `accessrequest_*.yml` — Access request plugin tests

---

## CI Usage

Unit tests run in every PR validation pipeline. Integration tests require a
live SPP appliance and are skipped in CI unless `SPP_HOST` is configured.
The pipeline's PR validation stage runs unit tests and builds artifacts
(collection tarball and credential plugin wheel) to verify packaging.

---

## Manual AWX Testing (Credential Type Plugin)

For end-to-end testing in AWX/AAP, follow the step-by-step instructions in
`credential_type_plugin/tests/steps.txt`. This covers deploying the plugin
into a running AAP instance and verifying credential retrieval through the
AWX UI.
