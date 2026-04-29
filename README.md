# Ansible Resources for Safeguard Integration

## What is Ansible?

Ansible is an automation platform for handling the deployment and maintenance of devices. For more information, see <https://www.ansible.com>

## What are the Ansible resources for Safeguard integration?

This repository provides Ansible plugins for integrating with One Identity Safeguard for Privileged Passwords (SPP). These plugins allow Ansible playbooks and the Ansible Automation Platform environment to pull credentials directly from SPP so that they can be used to perform tasks securely — without storing passwords in playbooks, inventory files, or version control.

All plugins depend on the [PySafeguard](https://github.com/OneIdentity/PySafeguard) Python SDK (v8+) and require Python ≥ 3.10 and Ansible ≥ 2.14.

## Contents

### Safeguard Lookup Plugins for Ansible

The collection provides two lookup plugins:

- **Safeguard Credentials (A2A)** — Retrieves credentials using a client certificate through the Application to Application (A2A) API. Best for automated, non-interactive workflows where a pre-registered certificate identifies the caller.
- **Safeguard Access Request** — Retrieves credentials using username/password authentication (PKCE) through the Access Request workflow. Best for user-driven automation where credentials are checked out on behalf of a named user.

For installation, configuration, and usage examples, see the [plugins documentation](https://github.com/OneIdentity/safeguard-ansible/tree/main/collection/oneidentity/safeguard/plugins).

### Safeguard Credential Type Plugin for Ansible Automation Platform

The Safeguard Credential Type plugin is configured using the AWX / Ansible Automation Platform web interface and allows Ansible to define an SPP credential that is automatically fetched at runtime. For more information, see the [credential type plugin documentation](https://github.com/OneIdentity/safeguard-ansible/tree/main/credential_type_plugin).

## Integration Testing

The collection includes an automated pytest-based integration test suite (18 tests) that runs against a live SPP appliance. Tests automatically provision and clean up all required SPP objects. See `collection/tests/` for details.

```bash
cd collection/tests
pip install -r requirements.txt
SPP_HOST=<appliance-ip> python3 -m pytest -v
```

Tests skip automatically when `SPP_HOST` is not set.

## Breaking Changes in v2.0.0

- Requires PySafeguard ≥ 8.0 (completely new API)
- Requires Python ≥ 3.10, Ansible ≥ 2.14
- **TLS verification is now enabled by default.** Connections to SPP use the system CA store unless overridden. To disable verification (e.g. for self-signed certs in lab environments), set `spp_validate_certs: false`.
- **`spp_tls_cert` renamed to `spp_ca_cert`** across both lookup plugins. Update your `a2aconnection` dicts and keyword arguments accordingly.
- The environment variable `SPP_TLS_CERT` is now `SPP_CA_CERT`.
- `setup.py` removed in favor of `pyproject.toml` for the credential type plugin.
- Release tags changed from `release-*` to `collection-v*` / `credplugin-v*`.

## Contributing to the Ansible Resources for Safeguard

Is something broken or something that should be added to the Ansible resources for Safeguard integration? [Log an issue](https://github.com/OneIdentity/safeguard-ansible/issues).
