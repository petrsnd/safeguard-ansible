# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Shared fixtures for credential type plugin tests.

Environment variables:
    SPP_HOST            Appliance address (required — integration tests skip if unset)
    SPP_ADMIN_PASSWORD  Bootstrap admin password (default: Admin123)
    SPP_CA_FILE         TLS CA bundle path (optional; disables TLS verification if unset)
"""

import logging
import os
import sys

import pytest

# Make the credential plugin package importable regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Make collection test helpers importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "collection", "tests"))

log = logging.getLogger("sgans_credplugin_tests")


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
# Admin client
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
    from pysafeguard import SafeguardClient, PkceAuth
    from helpers.provisioning import create_local_user, set_user_password, delete_user

    bootstrap = SafeguardClient(
        spp_host, auth=PkceAuth("local", "Admin", spp_admin_password), verify=spp_verify
    )
    bootstrap.login()

    user = create_local_user(bootstrap, label="CredPlugAdmin", admin_roles=ALL_ADMIN_ROLES)
    user_id = user["Id"]
    set_user_password(bootstrap, user_id, TEST_ADMIN_PASSWORD)
    bootstrap.logout()

    client = SafeguardClient(
        spp_host,
        auth=PkceAuth("local", user["Name"], TEST_ADMIN_PASSWORD),
        verify=spp_verify,
    )
    try:
        client.login()
        yield client
        client.logout()
    finally:
        bootstrap2 = SafeguardClient(
            spp_host, auth=PkceAuth("local", "Admin", spp_admin_password), verify=spp_verify
        )
        bootstrap2.login()
        delete_user(bootstrap2, user_id)
        bootstrap2.logout()


# ---------------------------------------------------------------------------
# A2A setup: cert, cert user, asset, account, registration, API key
# ---------------------------------------------------------------------------

KNOWN_PASSWORD = "SgAns_CredPlug_P@ss42!"


@pytest.fixture(scope="session")
def a2a_setup(admin_client, spp_verify, tmp_path_factory):
    """Provision a full A2A chain and yield connection details for tests."""
    from helpers.certificates import generate_client_cert, read_cert_base64
    from helpers.provisioning import (
        create_asset, create_account, set_account_password,
        create_cert_user, create_a2a_registration, add_retrievable_account,
        upload_trusted_cert,
        delete_asset, delete_account, delete_user,
        delete_a2a_registration, delete_trusted_cert,
    )

    tmpdir = str(tmp_path_factory.mktemp("credplugin_cert"))
    cert_path, key_path, thumbprint = generate_client_cert(tmpdir)
    cert_b64 = read_cert_base64(cert_path)

    # Track for cleanup
    created_cert = False
    cert_user = None
    asset = None
    account = None
    a2a_reg = None

    try:
        upload_trusted_cert(admin_client, cert_b64)
        created_cert = True
        cert_user = create_cert_user(admin_client, thumbprint, label="CredPlugCert")
        asset = create_asset(admin_client, label="CredPlugAsset")
        account = create_account(admin_client, asset["Id"], label="CredPlugAcct")
        set_account_password(admin_client, account["Id"], KNOWN_PASSWORD)
        a2a_reg = create_a2a_registration(admin_client, cert_user["Id"], label="CredPlugA2A")
        ra = add_retrievable_account(admin_client, a2a_reg["Id"], account["Id"])
    except Exception:
        # Best-effort cleanup on partial failure
        if a2a_reg:
            delete_a2a_registration(admin_client, a2a_reg["Id"])
        if account:
            delete_account(admin_client, account["Id"])
        if asset:
            delete_asset(admin_client, asset["Id"])
        if cert_user:
            delete_user(admin_client, cert_user["Id"])
        if created_cert:
            delete_trusted_cert(admin_client, thumbprint)
        raise

    yield {
        "api_key": ra["ApiKey"],
        "cert_path": cert_path,
        "key_path": key_path,
        "known_password": KNOWN_PASSWORD,
    }

    # Cleanup
    delete_a2a_registration(admin_client, a2a_reg["Id"])
    delete_account(admin_client, account["Id"])
    delete_asset(admin_client, asset["Id"])
    delete_user(admin_client, cert_user["Id"])
    delete_trusted_cert(admin_client, thumbprint)
