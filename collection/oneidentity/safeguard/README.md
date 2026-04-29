# Safeguard Collection for Ansible

The Safeguard collection provides lookup plugins for retrieving credentials from One Identity Safeguard for Privileged Passwords (SPP). Two plugins are included:

- **safeguardcredentials** — Retrieves credentials via A2A registration using client certificate authentication. Supports password and SSH private key retrieval by API key.
- **safeguardaccessrequest** — Retrieves credentials via the Access Request workflow using username/password (PKCE) authentication. Supports password and SSH private key checkout by asset/account name.

These plugins allow Ansible playbooks, inventory files, and templates to pull credentials directly from SPP at runtime without storing secrets in version control.

## Requirements

- Python ≥ 3.10
- Ansible ≥ 2.14
- [PySafeguard](https://github.com/OneIdentity/PySafeguard) ≥ 8.0

## Installation and usage

For installation instructions, configuration reference, and usage examples, see the [plugins documentation](https://github.com/OneIdentity/safeguard-ansible/tree/main/collection/oneidentity/safeguard/plugins).
