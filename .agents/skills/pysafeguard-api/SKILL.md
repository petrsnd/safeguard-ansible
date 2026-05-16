---
name: pysafeguard-api
description: >-
  Use when working on plugin source code, understanding PySafeguard SDK
  usage, or debugging credential retrieval. Covers A2AContext, SafeguardClient,
  PkceAuth, the verify parameter, HiddenString, and CheckOut response formats.
---

# PySafeguard API Patterns

All three plugins in this repository depend on `pysafeguard>=8,<9`. This
skill documents how they use the SDK so agents working on plugin code have
the full picture.

## A2A Credential Retrieval

Used by `safeguardcredentials` (lookup plugin) and `safeguardcredentialtype`
(AWX credential plugin).

### Context manager pattern (collection lookup plugin)

```python
from pysafeguard import A2AContext, A2AType

with A2AContext(host, cert_file, key_file, verify=verify) as a2a:
    pw = a2a.retrieve_password(api_key)       # Returns HiddenString
    key = a2a.retrieve_private_key(api_key)   # Returns HiddenString
```

The collection plugin iterates over multiple API keys in a single context:

```python
with A2AContext(appliance, cert, key, verify=verify) as a2a:
    for term in terms:
        credential = a2a.retrieve_password(term)
        ret.append(credential.value)
```

### Quick retrieval pattern (credential type plugin)

The AWX credential plugin uses static convenience methods instead of a
context manager, since it retrieves a single credential per call:

```python
credential = A2AContext.quick_retrieve_password(
    appliance, api_key, cert, key, verify=verify
)
credential = A2AContext.quick_retrieve_private_key(
    appliance, api_key, cert, key, verify=verify
)
return credential.value
```

### `HiddenString`

All PySafeguard credential retrieval methods return `HiddenString` objects,
not plain strings. Use `.value` to extract the plaintext:

```python
credential = a2a.retrieve_password(api_key)
plaintext = credential.value  # str
```

### `A2AType` enum

```python
from pysafeguard import A2AType

A2AType.PASSWORD    == "password"
A2AType.PRIVATEKEY  == "privatekey"
```

Both plugins normalize user input via `.lower()` comparison against these
values. Invalid types raise an error.

---

## Access Request Credential Retrieval

Used by `safeguardaccessrequest` (lookup plugin only).

### Authentication

```python
from pysafeguard import SafeguardClient, PkceAuth, Service

with SafeguardClient(host, auth=PkceAuth(provider, user, pw), verify=verify) as client:
    client.login()
    # ... make API calls ...
```

**Always use `PkceAuth`**, not `PasswordAuth`. ROPC (Resource Owner Password
Credentials) is disabled by default on SPP appliances. `PkceAuth` has an
identical constructor signature and works without a browser.

### Workflow steps

The access request plugin follows this sequence:

1. **Find entitlement** — query `Me/RequestEntitlements` for the asset:

   ```python
   resp = client.get(Service.CORE, "Me/RequestEntitlements",
       params={"q": asset_name, "accessRequestType": "Password"})
   ```

   Matches by `AssetName` or `AssetNetworkAddress` (case-insensitive).
   Optionally filters by account name. Raises an error if zero or multiple
   matches are found.

2. **Create or reuse request** — POST to `AccessRequests`:

   ```python
   resp = client.post(Service.CORE, "AccessRequests", json={
       "AccountId": account_id,
       "AssetId": asset_id,
       "AccessRequestType": "Password",  # or "SshKey"
       "ReasonComment": "Ansible lookup plugin request...",
   })
   ```

   If error code `90001` is returned (request already exists), the plugin
   searches for an existing active request to reuse.

3. **Check out credential** — POST with retry:

   ```python
   resp = client.post(Service.CORE, f"AccessRequests/{id}/CheckOutPassword")
   resp = client.post(Service.CORE, f"AccessRequests/{id}/CheckOutSshKey")
   ```

   Retries every 5 seconds until success or timeout (default 90 seconds).

### CheckOut response formats

- **`CheckOutPassword`** returns a plain JSON string (the password).
- **`CheckOutSshKey`** returns a JSON object:
  ```json
  {"PrivateKey": "...", "Passphrase": "...", "PublicKey": "..."}
  ```
  The plugin extracts the `PrivateKey` field:
  ```python
  if credential_type == "privatekey" and isinstance(credential, dict):
      credential = credential.get("PrivateKey", credential)
  ```

### Active request states

When searching for an existing request to reuse, the plugin considers these
states as "active" (not expired, eligible for checkout):

```python
("RequestAvailable", "PasswordCheckedOut", "SshKeyCheckedOut",
 "FileCheckedOut", "RdpInitialized", "SshInitialized")
```

### Error code 90001 — request overlap

SPP returns error code `90001` when an access request already exists for the
same account/asset/type combination. The plugin handles this by finding the
existing active request and reusing it rather than failing.

---

## Design Decision: No Check-In After Checkout

The access request plugin intentionally does **not** call `CheckInPassword` /
`CheckInSshKey` after retrieving the credential. Checking in triggers
credential rotation on the appliance, which would change the password/key
immediately after retrieval — making the returned value useless. Instead,
access requests expire naturally per the access policy's session duration.

---

## The `verify` Parameter

All three plugins use the same `_resolve_verify()` function to map
user-facing TLS options to PySafeguard's `verify` parameter:

```python
def _resolve_verify(tls_cert, validate_certs=True):
    if isinstance(tls_cert, str) and tls_cert:
        return tls_cert          # CA bundle path
    if validate_certs:
        return True              # System CA store
    return False                 # No TLS verification
```

**Mapping:**

| User input | `verify` value | Behavior |
|-----------|---------------|----------|
| `spp_ca_cert="/path/to/ca.pem"` | `"/path/to/ca.pem"` | Use specified CA bundle |
| `spp_validate_certs=True` (default), no CA path | `True` | Use system CA store |
| `spp_validate_certs=False` | `False` | Disable TLS verification |

### `validate_certs` string normalization

Both the A2A and credential type plugins normalize string values from
user input (e.g., AWX UI passes `"false"` as a string):

```python
if isinstance(validate_certs, str):
    validate_certs = validate_certs.lower() not in ('false', '0', 'no')
```

---

## Credential Type Plugin (AWX/AAP)

The credential type plugin has a different structure from the collection
lookup plugins:

### Entry point

Registered as `awx.credential_plugins` → `spp_plugin` via `pyproject.toml`:

```python
spp_plugin = CredentialPlugin(
    'Safeguard Credential',
    inputs={...},
    backend=_get_spp_credential,
)
```

### `CredentialPlugin` namedtuple

```python
CredentialPlugin = collections.namedtuple(
    'CredentialPlugin', ['name', 'inputs', 'backend']
)
```

- **`name`** — Display name in the AWX UI
- **`inputs`** — Dict with `fields` (UI form definition), `metadata`, `required`
- **`backend`** — Callable that receives `**kwargs` from the UI fields

### Lazy import

The credential type plugin imports `pysafeguard` lazily inside `_get_spp_credential()`,
not at module level. This allows the plugin to be discovered by AWX even when
`pysafeguard` isn't installed — the import error surfaces only when the
backend is actually called.

### Input fields

| Field ID | Type | Secret | Required |
|----------|------|--------|----------|
| `spp_api_key` | string | Yes | Yes |
| `spp_appliance` | string | No | Yes |
| `spp_certificate_path` | string | No | Yes |
| `spp_key_path` | string | No | Yes |
| `spp_tls_path` | string | No | No |
| `spp_validate_certs` | string (choices: true/false) | No | No |
| `spp_credential_type` | string (choices: password/privatekey) | No | No |

---

## Connection Options (Access Request Plugin)

The access request plugin supports three configuration sources per option,
with this precedence: direct keyword argument > environment variable >
`ansible.cfg` ini setting.

| Option | Env var | ini section/key |
|--------|---------|----------------|
| `spp_appliance` | `SPP_APPLIANCE` | `[safeguard] spp_appliance` |
| `spp_provider` | `SPP_PROVIDER` | `[safeguard] spp_provider` |
| `spp_user` | `SPP_USER` | `[safeguard] spp_user` |
| `spp_password` | `SPP_PASSWORD` | — (no ini, secrets shouldn't be in files) |
| `spp_credential_type` | `SPP_CREDENTIAL_TYPE` | `[safeguard] spp_credential_type` |
| `spp_ca_cert` | `SPP_CA_CERT` | `[safeguard] spp_ca_cert` |
| `spp_validate_certs` | `SPP_VALIDATE_CERTS` | `[safeguard] spp_validate_certs` |
| `spp_checkout_timeout` | `SPP_CHECKOUT_TIMEOUT` | `[safeguard] spp_checkout_timeout` |
