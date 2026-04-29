# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

import collections

from pysafeguard import A2AContext, A2AType

CredentialPlugin = collections.namedtuple('CredentialPlugin', ['name', 'inputs', 'backend'])


def _resolve_verify(tls_path, validate_certs=True):
    """Map user-facing TLS options to a PySafeguard verify parameter.

    :arg tls_path: A CA bundle file path (str) or None/False
    :arg validate_certs: Whether to validate TLS (bool, default True)
    :returns: A CA bundle path, True (system CA), or False (no verification)
    """
    if isinstance(tls_path, str) and tls_path:
        return tls_path
    if validate_certs:
        return True
    return False


def _get_spp_credential(**kwargs):
    """Retrieve the credential that corresponds to the API key.

    :arg spp_api_key: API key that corresponds to a credential
    :arg spp_appliance: SPP appliance to connect to
    :arg spp_certificate_path: Client authentication certificate
    :arg spp_key_path: Client authentication key
    :arg spp_tls_path: TLS certificate path or False
    :arg spp_credential_type: Credential type (password or privatekey)
    :returns: a text string containing the credential
    """
    api_key = kwargs.get('spp_api_key', None)
    appliance = kwargs.get('spp_appliance', None)
    cert = kwargs.get('spp_certificate_path', None)
    key = kwargs.get('spp_key_path', None)
    tls_path = kwargs.get('spp_tls_path', None)
    validate_certs = kwargs.get('spp_validate_certs', True)
    # AWX passes string 'false'/'true' from UI — normalize to bool
    if isinstance(validate_certs, str):
        validate_certs = validate_certs.lower() not in ('false', '0', 'no')
    credential_type = kwargs.get('spp_credential_type', A2AType.PASSWORD)
    if credential_type.lower() == A2AType.PASSWORD:
        credential_type = A2AType.PASSWORD
    elif credential_type.lower() == A2AType.PRIVATEKEY:
        credential_type = A2AType.PRIVATEKEY
    else:
        raise ValueError('Invalid credential type: ' + credential_type)

    if not api_key:
        raise ValueError('Missing credential API key.')
    if not appliance:
        raise ValueError('Missing appliance IP address or host name.')
    if not cert:
        raise ValueError('Missing client authentication certificate path.')
    if not key:
        raise ValueError('Missing client authentication key path.')

    verify = _resolve_verify(tls_path, validate_certs)

    try:
        if credential_type == A2AType.PRIVATEKEY:
            credential = A2AContext.quick_retrieve_private_key(
                appliance, api_key, cert, key, verify=verify
            )
        else:
            credential = A2AContext.quick_retrieve_password(
                appliance, api_key, cert, key, verify=verify
            )
        return credential.value
    except Exception as e:
        raise ValueError('Failed to retrieve the credential: %s' % e) from e


spp_plugin = CredentialPlugin(
    'Safeguard Credential',
    inputs={
        'fields': [{
            'id': 'spp_api_key',
            'label': 'Safeguard Credential API key',
            'type': 'string',
            'secret': True,
        }, {
            'id': 'spp_appliance',
            'label': 'Safeguard Appliance IP or Host name',
            'type': 'string',
        }, {
            'id': 'spp_certificate_path',
            'label': 'Safeguard client certificate file path',
            'type': 'string',
        }, {
            'id': 'spp_key_path',
            'label': 'Safeguard client key file path',
            'type': 'string',
            'help_text': 'Full path to the client authentication private key (PEM). Ensure the private key is stored securely and readable only by Ansible.',
        }, {
            'id': 'spp_tls_path',
            'label': 'Safeguard CA certificate file path',
            'type': 'string',
            'help_text': 'Optional CA bundle path. If empty, the system CA store is used for TLS verification.',
        }, {
            'id': 'spp_validate_certs',
            'label': 'Validate TLS certificates',
            'type': 'string',
            'choices': ['true', 'false'],
            'default': 'true',
            'help_text': 'Set to false only for testing with self-signed certificates.',
        }, {
            'id': 'spp_credential_type',
            'label': 'Safeguard credential type to retrieve',
            'type': 'string',
            'choices': ['password', 'privatekey'],
            'default': 'password',
        }],
        'metadata': [],
        'required': ['spp_api_key', 'spp_appliance', 'spp_certificate_path', 'spp_key_path'],
    },
    backend=_get_spp_credential,
)
