# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.
# Adapted for PySafeguard v8 from original code by Adrian Lopez <adrian.lopez@datadope.io>.

import time

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from pysafeguard import SafeguardClient, PkceAuth, Service

DOCUMENTATION = """
    name: safeguardaccessrequest
    version_added: "1.0"
    author:
      - Adrian Lopez (Datadope) <adrian.lopez@datadope.io>
    short_description: retrieve credentials from Safeguard for Privileged Passwords via Access Requests
    description:
      - Retrieve credentials (passwords or SSH keys) from the Safeguard for Privileged Passwords vault
        using username/password authentication and the Access Request workflow.
      - This plugin queries entitlements for the specified asset, creates an access request, and checks out the credential.
    options:
      _terms:
        description:
          - First term is the asset name or IP. Optional second term is the account name on the asset.
        type: str
        required: True
      spp_appliance:
        description: Safeguard for Privileged Passwords appliance IP address or host name
        type: str
        required: True
        env:
          - name: SPP_APPLIANCE
        ini:
          - section: safeguard
            key: spp_appliance
      spp_provider:
        description: Authentication provider name (e.g. 'local', your AD/LDAP provider name)
        type: str
        required: True
        env:
          - name: SPP_PROVIDER
        ini:
          - section: safeguard
            key: spp_provider
      spp_user:
        description: Authentication user name
        type: str
        required: True
        env:
          - name: SPP_USER
        ini:
          - section: safeguard
            key: spp_user
      spp_password:
        description: Authentication password
        type: str
        required: True
        no_log: True
        env:
          - name: SPP_PASSWORD
      spp_credential_type:
        description: >-
          Type of credential to retrieve.
        type: str
        choices: ['password', 'privatekey']
        default: password
        required: False
        env:
          - name: SPP_CREDENTIAL_TYPE
        ini:
          - section: safeguard
            key: spp_credential_type
      spp_ca_cert:
        description: >-
          Full path to a CA certificate bundle for TLS verification of the SPP appliance.
          When provided, overrides the system CA store.
        type: str
        required: False
        env:
          - name: SPP_CA_CERT
        ini:
          - section: safeguard
            key: spp_ca_cert
      spp_validate_certs:
        description: >-
          Whether to validate TLS certificates when connecting to the SPP appliance.
          Set to false only for testing with self-signed certificates.
        type: bool
        default: true
        required: False
        env:
          - name: SPP_VALIDATE_CERTS
        ini:
          - section: safeguard
            key: spp_validate_certs
    notes:
      - The safeguardaccessrequest lookup plugin requires OneIdentity PySafeguard module (>=8.0).
      - See https://github.com/OneIdentity/PySafeguard
    seealso:
      - plugin: oneidentity.safeguardcollection.safeguardcredentials
        plugin_type: lookup
        description: Retrieve credentials via A2A registration using client certificate authentication.
"""

EXAMPLES = """
  vars:
    spp_appliance: 192.168.0.1
    spp_provider: local
    spp_user: foo
    spp_password: mysecret
  tasks:
    - name: retrieve a password (single account on asset)
      ansible.builtin.set_fact:
        credential: "{{ lookup('oneidentity.safeguardcollection.safeguardaccessrequest', 'myasset', spp_appliance=spp_appliance, spp_provider=spp_provider, spp_user=spp_user, spp_password=spp_password) }}"

    - name: retrieve a password for a specific account
      ansible.builtin.set_fact:
        credential: "{{ lookup('oneidentity.safeguardcollection.safeguardaccessrequest', 'myasset', 'root', spp_appliance=spp_appliance, spp_provider=spp_provider, spp_user=spp_user, spp_password=spp_password) }}"

    - name: retrieve an SSH key for a specific account
      ansible.builtin.set_fact:
        sshkey: "{{ lookup('oneidentity.safeguardcollection.safeguardaccessrequest', 'myasset', 'root', spp_appliance=spp_appliance, spp_provider=spp_provider, spp_user=spp_user, spp_password=spp_password, spp_credential_type='privatekey') }}"
"""

RETURN = """
_raw:
  description:
    - A single-element list containing the retrieved credential.
    - For password lookups, the element is the plaintext password.
    - For privatekey lookups, the element is the PEM-formatted SSH private key.
  type: list
  elements: str
"""


display = Display()

CHECKOUT_MAX_RETRIES = 4
CHECKOUT_RETRY_BASE_SECONDS = 3
CHECKOUT_RETRY_MAX_SECONDS = 30

REQUEST_TYPES = {
    "password": "Password",
    "privatekey": "SshKey",
}

CHECKOUT_ENDPOINTS = {
    "password": "AccessRequests/%s/CheckOutPassword",
    "privatekey": "AccessRequests/%s/CheckOutSshKey",
}


def _resolve_verify(tls_cert, validate_certs=True):
    """Map user-facing TLS options to a PySafeguard verify parameter.

    :arg tls_cert: A CA bundle file path (str) or None
    :arg validate_certs: Whether to validate TLS (bool, default True)
    :returns: A CA bundle path, True (system CA), or False (no verification)
    """
    if isinstance(tls_cert, str) and tls_cert:
        return tls_cert
    if validate_certs:
        return True
    return False


def _find_entitlement(client, asset_name, credential_type, account_name=None):
    """Find the entitlement matching the given asset name or IP.

    :arg client: An authenticated SafeguardClient
    :arg asset_name: Asset name or IP address to look up
    :arg credential_type: The credential type key ('password' or 'privatekey')
    :arg account_name: Optional account name to filter by
    :returns: A dict with AccountId and AssetId
    :raises AnsibleError: If no match or multiple matches are found
    """
    resp = client.get(
        Service.CORE,
        "Me/RequestEntitlements",
        params={"q": asset_name, "accessRequestType": REQUEST_TYPES[credential_type]},
    )
    if resp.status_code != 200:
        raise AnsibleError(
            'Error obtaining entitlements: %s - %s' % (resp.status_code, resp.text)
        )

    entitlements = resp.json()
    matches = [
        e for e in entitlements
        if (e.get("Account", {}).get("AssetName", "").lower() == asset_name.lower()
            or e.get("Account", {}).get("AssetNetworkAddress") == asset_name)
    ]

    if account_name:
        matches = [
            e for e in matches
            if e.get("Account", {}).get("Name", "").lower() == account_name.lower()
        ]

    if not matches:
        if account_name:
            raise AnsibleError(
                "No entitlement found for account '%s' on asset '%s'" % (account_name, asset_name)
            )
        raise AnsibleError("Asset with name '%s' not found in entitlements" % asset_name)
    if len(matches) > 1:
        account_names = [e.get("Account", {}).get("Name", "?") for e in matches]
        raise AnsibleError(
            "Multiple entitlements found for '%s' (accounts: %s). Specify the account name as the second lookup term."
            % (asset_name, ", ".join(account_names))
        )

    account = matches[0]["Account"]
    return {"AccountId": account["Id"], "AssetId": account["AssetId"]}


def _find_existing_request(client, account_id, asset_id, access_request_type):
    """Find an existing active access request for the given account/asset/type.

    :arg access_request_type: The SPP AccessRequestType value (e.g. "Password", "SshKey")
    :returns: The request ID string, or None if no matching request exists
    """
    resp = client.get(Service.CORE, "AccessRequests")
    if resp.status_code != 200:
        return None

    active_states = (
        "RequestAvailable",
        "PasswordCheckedOut",
        "SshKeyCheckedOut",
        "FileCheckedOut",
        "RdpInitialized",
        "SshInitialized",
    )
    for req in resp.json():
        if (req.get("AccountId") == account_id
                and req.get("AssetId") == asset_id
                and req.get("AccessRequestType") == access_request_type
                and not req.get("WasExpired", False)
                and req.get("State") in active_states):
            return req["Id"]

    return None


def _create_or_reuse_request(client, account_id, asset_id, asset_name, credential_type):
    """Create a new access request or find an existing one.

    :returns: The access request ID
    """
    resp = client.post(
        Service.CORE,
        "AccessRequests",
        json={
            "AccountId": account_id,
            "AssetId": asset_id,
            "AccessRequestType": REQUEST_TYPES[credential_type],
            "ReasonComment": "Ansible lookup plugin request for asset '%s'" % asset_name,
        },
    )

    if resp.status_code == 201:
        return resp.json()["Id"]

    # Error code 90001 means a request already exists for this account/asset
    if resp.status_code == 400:
        try:
            error_body = resp.json()
            error_code = error_body.get("Code")
        except Exception:
            error_code = None

        if error_code == 90001:
            display.vvvv("Access request already exists for '%s' (error code 90001)" % asset_name)
            request_id = _find_existing_request(client, account_id, asset_id,
                                                    REQUEST_TYPES[credential_type])
            if request_id is not None:
                return request_id

    raise AnsibleError(
        'Error creating access request: %s - %s' % (resp.status_code, resp.text)
    )


def _checkout_with_retry(client, request_id, credential_type):
    """Check out the credential, retrying on transient failures.

    :returns: The checked-out credential
    """
    endpoint = CHECKOUT_ENDPOINTS[credential_type] % request_id
    last_error = None
    for attempt in range(CHECKOUT_MAX_RETRIES):
        resp = client.post(Service.CORE, endpoint)
        if resp.status_code == 200:
            return resp.json()

        last_error = 'Error checking out credential: %s - %s' % (resp.status_code, resp.text)
        if attempt < CHECKOUT_MAX_RETRIES - 1:
            wait = min(CHECKOUT_RETRY_BASE_SECONDS * (2 ** attempt), CHECKOUT_RETRY_MAX_SECONDS)
            display.vvvv("Checkout attempt %d failed, retrying in %ds..." % (attempt + 1, wait))
            time.sleep(wait)

    raise AnsibleError(last_error)


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        ret = []

        self.set_options(var_options=variables, direct=kwargs)

        appliance = self.get_option("spp_appliance")
        provider = self.get_option("spp_provider")
        username = self.get_option("spp_user")
        password = self.get_option("spp_password")
        credential_type = self.get_option("spp_credential_type")
        tls_cert = self.get_option("spp_ca_cert")
        validate_certs = self.get_option("spp_validate_certs")
        verify = _resolve_verify(tls_cert, validate_certs)

        if credential_type not in REQUEST_TYPES:
            raise AnsibleError("Invalid spp_credential_type '%s'. Must be one of: %s"
                               % (credential_type, ", ".join(REQUEST_TYPES.keys())))

        if not terms:
            raise AnsibleError('Missing asset name (first lookup term).')
        if len(terms) > 2:
            raise AnsibleError('Expected 1 or 2 terms (asset name, optional account name), got %d.' % len(terms))

        asset_name = terms[0]
        account_name = terms[1] if len(terms) > 1 else None

        if not appliance:
            raise AnsibleError('Missing appliance IP address or host name.')
        if not provider:
            raise AnsibleError('Missing authentication provider.')
        if not username:
            raise AnsibleError('Missing authentication username.')
        if not password:
            raise AnsibleError('Missing authentication password.')

        try:
            with SafeguardClient(
                appliance,
                auth=PkceAuth(provider, username, password),
                verify=verify,
            ) as client:
                client.login()
                display.vvvv(
                    "Requesting %s for asset '%s'%s from '%s' as '%s'"
                    % (credential_type, asset_name,
                       (" account '%s'" % account_name if account_name else ""),
                       appliance, username)
                )
                entitlement = _find_entitlement(client, asset_name, credential_type, account_name=account_name)
                request_id = _create_or_reuse_request(
                    client, entitlement["AccountId"], entitlement["AssetId"],
                    asset_name, credential_type
                )
                credential = _checkout_with_retry(client, request_id, credential_type)
                if credential_type == "privatekey" and isinstance(credential, dict):
                    credential = credential.get("PrivateKey", credential)
                ret.append(credential)
        except AnsibleError:
            raise
        except Exception as e:
            raise AnsibleError('Failed to retrieve the credential: %s' % to_native(e)) from e

        return ret
