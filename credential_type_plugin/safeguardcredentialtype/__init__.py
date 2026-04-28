import collections

from pysafeguard import A2AContext, A2AType

CredentialPlugin = collections.namedtuple('CredentialPlugin', ['name', 'inputs', 'backend'])


def _resolve_verify(tls_path):
    """Map the user-facing TLS path value to a PySafeguard verify parameter.

    :arg tls_path: A file path (str), True, False, or None
    :returns: True, False, or a CA bundle path string
    """
    if isinstance(tls_path, str) and tls_path:
        return tls_path
    if tls_path is True:
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
    tls_path = kwargs.get('spp_tls_path', False)
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

    verify = _resolve_verify(tls_path)

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
        raise ValueError('Failed to retrieve the credential.') from e


spp_plugin = CredentialPlugin(
    'Safeguard Credential',
    inputs={
        'fields': [{
            'id': 'spp_api_key',
            'label': 'Safeguard Credential API key',
            'type': 'string',
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
        }, {
            'id': 'spp_tls_path',
            'label': 'Safeguard TLS certificate file path',
            'type': 'string',
        }, {
            'id': 'spp_credential_type',
            'label': 'Safeguard credential type to retrieve',
            'type': 'string',
            'choices': ['password', 'privatekey']
        }],
        'metadata': [],
        'required': ['spp_api_key', 'spp_appliance', 'spp_certificate_path', 'spp_key_path'],
    },
    backend=_get_spp_credential,
)
