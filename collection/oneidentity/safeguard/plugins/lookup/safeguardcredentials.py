# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from pysafeguard import A2AContext, A2AType

DOCUMENTATION = """
    name: safeguardcredentials
    version_added: "0.9"
    author:
      - Brad Nicholes (!UNKNOWN) <brad.nicholes@oneidentity.com>
    short_description: retrieve credentials from Safeguard for Privileged Passwords vault
    description:
      - Retrieve credentials from the Safeguard for Privileged Passwords vault given a user certificate and API key that
        corresponds to a specific credential.
    options:
      _terms:
        description:
          - List of API keys that correspond to retrievable credentials
        required: True
      a2aconnection:
        description:
          - Safeguard for Privileged Passwords appliance connection information
          - The a2aconnection must contain the following properties
            - spp_appliance - IP address or host name of the Safeguard for Privileged Passwords appliance
            - spp_certificate_file - Full path to the A2A client authentication certificate
            - spp_certificate_key - Full path to the A2A client authentication private key
            - spp_ca_cert(optional) - Full path to a CA certificate bundle for TLS verification
            - spp_validate_certs(optional) - Whether to validate TLS certificates (default true)
            - spp_credential_type(optional) - Credential type to retrieve. Must be 'password' or 'privatekey'
        required: True
        no_log: True
    notes:
      - Please see the configuration for the Safeguard for Privileged Passwords Application to Application registration.
      - Each credential that is retrieved from Safeguard for Privileged Passwords will have an identifying API key.
      - The safeguardcredentials lookup plugin requires OneIdentity PySafeguard module (>=8.0).
      - See https://github.com/OneIdentity/PySafeguard
    seealso:
      - plugin: oneidentity.safeguardcollection.safeguardaccessrequest
        plugin_type: lookup
        description: Retrieve credentials via the Access Request workflow using username/password authentication.
"""

EXAMPLES = """
- name: Retrieve a password credential
  hosts: localhost
  vars:
    spp_credential_apikey: safyBECB8SW5g0Udk7GRFh6LaQ/KoI0eNOW4JK8Cqeo=
    a2aconnection:
      spp_appliance: 192.168.0.1
      spp_certificate_file: /etc/ansible/certs/CN=a2ausercert.pem
      spp_certificate_key: /etc/ansible/certs/CN=a2ausercert.key
      spp_ca_cert: /etc/ansible/certs/spp-ca-bundle.pem
      spp_credential_type: password
  tasks:
    - name: Retrieve a credential by API key
      ansible.builtin.set_fact:
        password: "{{ lookup('oneidentity.safeguardcollection.safeguardcredentials', spp_credential_apikey, a2aconnection=a2aconnection) }}"

    - name: Retrieve an SSH private key by API key
      ansible.builtin.set_fact:
        sshkey: "{{ lookup('oneidentity.safeguardcollection.safeguardcredentials', spp_credential_apikey, a2aconnection=a2aconnection | combine({'spp_credential_type': 'privatekey'})) }}"
"""

RETURN = """
_raw:
  description:
    - One credential string per API key provided.
    - For password lookups, each element is the plaintext password.
    - For privatekey lookups, each element is the PEM-formatted SSH private key.
  type: list
  elements: str
"""


def _resolve_verify(tls_cert, validate_certs=True):
    """Map user-facing TLS options to a PySafeguard verify parameter.

    :arg tls_cert: A CA bundle file path (str) or None/False
    :arg validate_certs: Whether to validate TLS (bool, default True)
    :returns: A CA bundle path, True (system CA), or False (no verification)
    """
    if isinstance(tls_cert, str) and tls_cert:
        return tls_cert
    if validate_certs:
        return True
    return False


display = Display()


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        ret = []

        self.set_options(var_options=variables, direct=kwargs)

        a2aconnection = self.get_option('a2aconnection')

        appliance = a2aconnection.get('spp_appliance', None)
        cert = a2aconnection.get('spp_certificate_file', None)
        key = a2aconnection.get('spp_certificate_key', None)
        tls_cert = a2aconnection.get('spp_ca_cert', None)
        validate_certs = a2aconnection.get('spp_validate_certs', True)
        credential_type = a2aconnection.get('spp_credential_type', A2AType.PASSWORD)
        if credential_type.lower() == A2AType.PASSWORD:
            credential_type = A2AType.PASSWORD
        elif credential_type.lower() == A2AType.PRIVATEKEY:
            credential_type = A2AType.PRIVATEKEY
        else:
            raise AnsibleError('Invalid credential type: ' + credential_type)

        if not appliance:
            raise AnsibleError('Missing appliance IP address or host name.')
        if not cert:
            raise AnsibleError('Missing client authentication certificate path.')
        if not key:
            raise AnsibleError('Missing client authentication key path.')

        verify = _resolve_verify(tls_cert, validate_certs)

        try:
            display.vvvv("Connecting to '%s' via A2A with cert '%s'" % (appliance, cert))
            with A2AContext(appliance, cert, key, verify=verify) as a2a:
                for term in terms:
                    display.vvvv("Retrieving %s credential for API key '%s...'" % (credential_type, term[:8]))
                    if credential_type == A2AType.PRIVATEKEY:
                        credential = a2a.retrieve_private_key(term)
                    else:
                        credential = a2a.retrieve_password(term)
                    ret.append(credential.value)
        except AnsibleError:
            raise
        except Exception as e:
            raise AnsibleError('Failed to retrieve the credential: %s' % to_native(e)) from e

        return ret
