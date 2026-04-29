# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Shared fixtures for safeguard-ansible integration tests.

Environment variables:
    SPP_HOST            Appliance address (required — tests skip if unset)
    SPP_ADMIN_PASSWORD  Bootstrap admin password (required)
    SPP_CA_FILE         TLS CA bundle path (optional; disables TLS if unset)
"""

import json
import logging
import os
import subprocess

import pytest

from pysafeguard import SafeguardClient, PkceAuth

log = logging.getLogger("sgans_tests")

from helpers.certificates import generate_client_cert, generate_ssh_keypair, read_cert_base64, build_ca_bundle
from helpers.provisioning import (
    create_access_policy,
    create_account,
    create_a2a_registration,
    create_asset,
    create_cert_user,
    create_local_user,
    create_role,
    add_retrievable_account,
    delete_access_policy,
    delete_account,
    delete_a2a_registration,
    delete_asset,
    delete_role,
    delete_trusted_cert,
    delete_user,
    set_account_password,
    set_account_ssh_key,
    set_user_password,
    upload_trusted_cert,
)


# ---------------------------------------------------------------------------
# Auto-skip when SPP_HOST is not set
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(config, items):
    if not os.environ.get("SPP_HOST"):
        skip = pytest.mark.skip(reason="SPP_HOST not set — skipping integration tests")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip)


# ---------------------------------------------------------------------------
# Environment fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def spp_host():
    return os.environ["SPP_HOST"]


@pytest.fixture(scope="session")
def spp_admin_password():
    return os.environ.get("SPP_ADMIN_PASSWORD", "Admin123")


@pytest.fixture(scope="session")
def spp_verify():
    ca = os.environ.get("SPP_CA_FILE")
    return ca if ca else False


# ---------------------------------------------------------------------------
# Admin client — bootstrap admin creates a test admin with full privileges
# ---------------------------------------------------------------------------

ALL_ADMIN_ROLES = [
    "GlobalAdmin", "AssetAdmin", "PolicyAdmin", "UserAdmin",
    "ApplianceAdmin", "HelpdeskAdmin", "OperationsAdmin",
    "Auditor", "ApplicationAuditor", "SystemAuditor",
]

TEST_ADMIN_PASSWORD = "SgAns_Adm1n_P@ss9"


@pytest.fixture(scope="session")
def admin_client(spp_host, spp_admin_password, spp_verify):
    """Create a fully-privileged test admin and return a logged-in client."""
    bootstrap = SafeguardClient(
        spp_host, auth=PkceAuth("local", "Admin", spp_admin_password), verify=spp_verify
    )
    bootstrap.login()

    user = create_local_user(bootstrap, label="TestAdmin", admin_roles=ALL_ADMIN_ROLES)
    user_id = user["Id"]
    set_user_password(bootstrap, user_id, TEST_ADMIN_PASSWORD)
    bootstrap.logout()

    client = SafeguardClient(
        spp_host,
        auth=PkceAuth("local", user["Name"], TEST_ADMIN_PASSWORD),
        verify=spp_verify,
    )
    client.login()

    yield client

    client.logout()

    # Cleanup: delete test admin via bootstrap
    bootstrap2 = SafeguardClient(
        spp_host, auth=PkceAuth("local", "Admin", spp_admin_password), verify=spp_verify
    )
    bootstrap2.login()
    delete_user(bootstrap2, user_id)
    bootstrap2.logout()


# ---------------------------------------------------------------------------
# TLS CA bundle — built from the appliance's trusted certificates
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ca_bundle_path(admin_client, tmp_path_factory):
    """Build a CA bundle from the appliance's trusted CA certificates."""
    tmpdir = str(tmp_path_factory.mktemp("tls"))
    return build_ca_bundle(admin_client, tmpdir)


# ---------------------------------------------------------------------------
# Asset + accounts (separate accounts for password and SSH key)
# ---------------------------------------------------------------------------

KNOWN_PASSWORD = "SgAns_TestP@ss_42!"


@pytest.fixture(scope="session")
def test_asset(admin_client):
    asset = create_asset(admin_client)
    yield asset
    delete_asset(admin_client, asset["Id"])


@pytest.fixture(scope="session")
def test_pw_account(admin_client, test_asset):
    """Account with a known password — used for password retrieval tests."""
    account = create_account(admin_client, test_asset["Id"], label="PwAcct")
    set_account_password(admin_client, account["Id"], KNOWN_PASSWORD)
    yield account
    delete_account(admin_client, account["Id"])


@pytest.fixture(scope="session")
def test_sshkey_account(admin_client, test_asset, tmp_path_factory):
    """Separate account with an SSH key — used for private key retrieval tests."""
    account = create_account(admin_client, test_asset["Id"], label="SshKeyAcct")
    # Set a password too — needed for multi-key A2A test (password type)
    set_account_password(admin_client, account["Id"], KNOWN_PASSWORD)
    tmpdir = str(tmp_path_factory.mktemp("sshkey"))
    _, private_key = generate_ssh_keypair(tmpdir)
    set_account_ssh_key(admin_client, account["Id"], private_key)
    yield account
    delete_account(admin_client, account["Id"])


# ---------------------------------------------------------------------------
# A2A: cert, cert user, registration, API key
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def client_cert(tmp_path_factory):
    tmpdir = str(tmp_path_factory.mktemp("cert"))
    cert_path, key_path, thumbprint = generate_client_cert(tmpdir)
    return cert_path, key_path, thumbprint


@pytest.fixture(scope="session")
def a2a_setup(admin_client, test_pw_account, test_sshkey_account, client_cert):
    """Provision the full A2A chain with retrievable accounts for both types."""
    cert_path, key_path, thumbprint = client_cert
    cert_b64 = read_cert_base64(cert_path)

    upload_trusted_cert(admin_client, cert_b64)
    cert_user = create_cert_user(admin_client, thumbprint)
    a2a_reg = create_a2a_registration(admin_client, cert_user["Id"])
    ra_pw = add_retrievable_account(admin_client, a2a_reg["Id"], test_pw_account["Id"])
    ra_key = add_retrievable_account(admin_client, a2a_reg["Id"], test_sshkey_account["Id"])

    yield {
        "pw_api_key": ra_pw["ApiKey"],
        "sshkey_api_key": ra_key["ApiKey"],
        "cert_path": cert_path,
        "key_path": key_path,
    }

    delete_a2a_registration(admin_client, a2a_reg["Id"])
    delete_user(admin_client, cert_user["Id"])
    delete_trusted_cert(admin_client, thumbprint)


# ---------------------------------------------------------------------------
# Access Request: requester user, role, policy
# ---------------------------------------------------------------------------

REQUESTER_PASSWORD = "SgAns_Req_P@ss_42!"


@pytest.fixture(scope="session")
def ar_setup(admin_client, spp_host, test_asset, test_pw_account, test_sshkey_account, spp_verify):
    """Provision the access request chain with separate accounts per credential type."""
    user = create_local_user(admin_client, label="Requester")
    set_user_password(admin_client, user["Id"], REQUESTER_PASSWORD)

    role = create_role(admin_client, user["Id"])
    pw_policy = create_access_policy(
        admin_client, role["Id"], test_pw_account["Id"],
        request_type="Password", label="PwPolicy",
    )
    sshkey_policy = create_access_policy(
        admin_client, role["Id"], test_sshkey_account["Id"],
        request_type="SshKey", label="SshKeyPolicy",
    )

    yield {
        "spp_appliance": spp_host,
        "spp_provider": "local",
        "spp_user": user["Name"],
        "spp_password": REQUESTER_PASSWORD,
        "asset_name": test_asset["Name"],
        "pw_account_name": test_pw_account["Name"],
        "sshkey_account_name": test_sshkey_account["Name"],
    }

    delete_access_policy(admin_client, sshkey_policy["Id"])
    delete_access_policy(admin_client, pw_policy["Id"])
    delete_role(admin_client, role["Id"])
    delete_user(admin_client, user["Id"])


# ---------------------------------------------------------------------------
# Collection install
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def installed_collection(tmp_path_factory):
    """Build and install the collection into a temporary path."""
    collection_src = os.path.join(
        os.path.dirname(__file__), "..", "oneidentity", "safeguard"
    )
    collection_src = os.path.abspath(collection_src)

    build_dir = str(tmp_path_factory.mktemp("build"))
    subprocess.run(
        ["ansible-galaxy", "collection", "build", "--output-path", build_dir],
        cwd=collection_src,
        capture_output=True,
        check=True,
    )

    # Find the built tarball
    tarball = [f for f in os.listdir(build_dir) if f.endswith(".tar.gz")][0]
    tarball_path = os.path.join(build_dir, tarball)

    install_dir = str(tmp_path_factory.mktemp("collections"))
    subprocess.run(
        ["ansible-galaxy", "collection", "install", tarball_path, "-p", install_dir],
        capture_output=True,
        check=True,
    )

    return install_dir


@pytest.fixture(scope="session")
def ansible_env(installed_collection, spp_verify):
    """Return an env dict for subprocess calls that points Ansible at the test collection."""
    env = os.environ.copy()
    env["ANSIBLE_COLLECTIONS_PATH"] = installed_collection
    # Suppress warnings about localhost
    env["ANSIBLE_LOCALHOST_WARNING"] = "false"
    if spp_verify and isinstance(spp_verify, str):
        env["SPP_CA_CERT"] = spp_verify
    else:
        # No CA file — disable TLS validation for test appliances with self-signed certs
        env["SPP_VALIDATE_CERTS"] = "false"
    return env


# ---------------------------------------------------------------------------
# Playbook runner helper
# ---------------------------------------------------------------------------

def run_playbook(playbook_name, extra_vars, ansible_env, secret_env=None,
                 expect_failure=False):
    """Run a test playbook and return the CompletedProcess.

    :arg playbook_name: Filename in the playbooks/ directory
    :arg extra_vars: Dict of extra variables (non-secret, passed via -e)
    :arg ansible_env: Base environment dict from the ansible_env fixture
    :arg secret_env: Dict of secret env vars (passed in subprocess env only,
        never on the command line). Playbooks read these via lookup('env', ...).
    :arg expect_failure: If True, don't assert rc==0
    :returns: subprocess.CompletedProcess
    """
    playbook_dir = os.path.join(os.path.dirname(__file__), "playbooks")
    playbook_path = os.path.join(playbook_dir, playbook_name)

    env = ansible_env.copy()
    if secret_env:
        env.update(secret_env)

    # Inject spp_validate_certs so A2A playbooks can pick it up as an Ansible var
    merged_vars = dict(extra_vars)
    if "SPP_VALIDATE_CERTS" in env and "spp_validate_certs" not in merged_vars:
        merged_vars["spp_validate_certs"] = env["SPP_VALIDATE_CERTS"].lower() in ("true", "1", "yes")

    cmd = [
        "ansible-playbook", playbook_path,
        "-i", "localhost,",
        "-e", json.dumps(merged_vars),
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, env=env
    )

    if not expect_failure:
        assert result.returncode == 0, (
            f"Playbook {playbook_name} failed (rc={result.returncode}):\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    return result
