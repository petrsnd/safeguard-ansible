# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""SPP object provisioning helpers for integration testing.

All created objects use a ``SgAns_`` prefix so they are easily identifiable
if cleanup fails.
"""

import logging
import uuid

from pysafeguard import Service


PREFIX = "SgAns_"
log = logging.getLogger("sgans_tests")


def _name(label):
    """Generate a prefixed, unique object name."""
    return f"{PREFIX}{label}_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

def create_asset(client, label="TestAsset", address="10.255.255.99"):
    """Create an asset in the default partition.

    :returns: Asset dict (contains 'Id', 'Name')
    """
    resp = client.post(Service.CORE, "Assets", json={
        "Name": _name(label),
        "NetworkAddress": address,
        "PlatformId": 188,  # Other Linux
        "AssetPartitionId": -1,
    })
    resp.raise_for_status()
    return resp.json()


def delete_asset(client, asset_id):
    """Best-effort asset deletion."""
    try:
        client.delete(Service.CORE, f"Assets/{asset_id}")
    except Exception as e:
        log.warning("Failed to delete asset %s: %s", asset_id, e)


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

def create_account(client, asset_id, label="TestAcct"):
    """Create an account on an asset.

    :returns: Account dict (contains 'Id', 'Name')
    """
    resp = client.post(Service.CORE, "AssetAccounts", json={
        "Asset": {"Id": asset_id},
        "Name": _name(label),
    })
    resp.raise_for_status()
    return resp.json()


def set_account_password(client, account_id, password):
    """Set a static password on an account."""
    resp = client.put(
        Service.CORE, f"AssetAccounts/{account_id}/Password", json=password
    )
    resp.raise_for_status()


def set_account_ssh_key(client, account_id, private_key):
    """Set an SSH key on an account."""
    resp = client.put(
        Service.CORE,
        f"AssetAccounts/{account_id}/SshKey",
        json={"Passphrase": "", "PrivateKey": private_key},
    )
    resp.raise_for_status()


def delete_account(client, account_id):
    """Best-effort account deletion."""
    try:
        client.delete(Service.CORE, f"AssetAccounts/{account_id}")
    except Exception as e:
        log.warning("Failed to delete account %s: %s", account_id, e)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def create_local_user(client, label="TestUser", admin_roles=None):
    """Create a local user.

    :returns: User dict (contains 'Id', 'Name')
    """
    body = {
        "PrimaryAuthenticationProvider": {"Id": -1},
        "Name": _name(label),
    }
    if admin_roles:
        body["AdminRoles"] = admin_roles
    resp = client.post(Service.CORE, "Users", json=body)
    resp.raise_for_status()
    return resp.json()


def set_user_password(client, user_id, password):
    """Set a local user's password."""
    resp = client.put(Service.CORE, f"Users/{user_id}/Password", json=password)
    resp.raise_for_status()


def create_cert_user(client, thumbprint, label="CertUser"):
    """Create a certificate-authenticated user.

    Both ``PrimaryAuthenticationProvider`` (cert, Id=-2) and
    ``IdentityProvider`` (local, Id=-1) must carry the thumbprint.

    :returns: User dict
    """
    resp = client.post(Service.CORE, "Users", json={
        "Name": _name(label),
        "PrimaryAuthenticationProvider": {"Id": -2, "Identity": thumbprint},
        "IdentityProvider": {"Id": -1, "IdentityId": thumbprint},
    })
    resp.raise_for_status()
    return resp.json()


def delete_user(client, user_id):
    """Best-effort user deletion."""
    try:
        client.delete(Service.CORE, f"Users/{user_id}")
    except Exception as e:
        log.warning("Failed to delete user %s: %s", user_id, e)


# ---------------------------------------------------------------------------
# Trusted Certificates
# ---------------------------------------------------------------------------

def upload_trusted_cert(client, cert_base64):
    """Upload a trusted certificate.

    :returns: Response dict (contains 'Thumbprint')
    """
    resp = client.post(
        Service.CORE, "TrustedCertificates", json={"Base64CertificateData": cert_base64}
    )
    resp.raise_for_status()
    return resp.json()


def delete_trusted_cert(client, thumbprint):
    """Best-effort trusted certificate deletion."""
    try:
        client.delete(Service.CORE, f"TrustedCertificates/{thumbprint}")
    except Exception as e:
        log.warning("Failed to delete trusted cert %s: %s", thumbprint, e)


# ---------------------------------------------------------------------------
# A2A Registrations
# ---------------------------------------------------------------------------

def create_a2a_registration(client, cert_user_id, label="A2AReg"):
    """Create an A2A registration.

    :returns: A2A registration dict (contains 'Id')
    """
    resp = client.post(Service.CORE, "A2ARegistrations", json={
        "AppName": _name(label),
        "CertificateUserId": cert_user_id,
    })
    resp.raise_for_status()
    return resp.json()


def add_retrievable_account(client, a2a_id, account_id):
    """Add a retrievable account to an A2A registration.

    :returns: Dict containing 'ApiKey'
    """
    resp = client.post(
        Service.CORE,
        f"A2ARegistrations/{a2a_id}/RetrievableAccounts",
        json={"AccountId": account_id},
    )
    resp.raise_for_status()
    return resp.json()


def delete_a2a_registration(client, a2a_id):
    """Best-effort A2A registration deletion."""
    try:
        client.delete(Service.CORE, f"A2ARegistrations/{a2a_id}")
    except Exception as e:
        log.warning("Failed to delete A2A registration %s: %s", a2a_id, e)


# ---------------------------------------------------------------------------
# Roles & Access Policies
# ---------------------------------------------------------------------------

def create_role(client, user_id, label="TestRole"):
    """Create a role with a single member.

    :returns: Role dict (contains 'Id')
    """
    resp = client.post(Service.CORE, "Roles", json={
        "Name": _name(label),
        "Members": [{"Id": user_id, "PrimaryAuthenticationProviderId": -1}],
    })
    resp.raise_for_status()
    return resp.json()


def delete_role(client, role_id):
    """Best-effort role deletion."""
    try:
        client.delete(Service.CORE, f"Roles/{role_id}")
    except Exception as e:
        log.warning("Failed to delete role %s: %s", role_id, e)


def create_access_policy(client, role_id, account_id, request_type="Password",
                         label="TestPolicy"):
    """Create an auto-approved access policy.

    :arg request_type: 'Password' or 'SshKey'
    :returns: AccessPolicy dict (contains 'Id')
    """
    resp = client.post(Service.CORE, "AccessPolicies", json={
        "Name": _name(label),
        "RoleId": role_id,
        "ApproverProperties": {"RequireApproval": False},
        "AccessRequestProperties": {"AccessRequestType": request_type},
        "ScopeItems": [{"ScopeItemType": "Account", "Id": account_id}],
    })
    resp.raise_for_status()
    return resp.json()


def delete_access_policy(client, policy_id):
    """Best-effort access policy deletion."""
    try:
        client.delete(Service.CORE, f"AccessPolicies/{policy_id}")
    except Exception as e:
        log.warning("Failed to delete access policy %s: %s", policy_id, e)
