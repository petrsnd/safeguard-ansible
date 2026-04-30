# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Unit tests for the collection lookup plugins.

These tests do NOT require a live SPP appliance or Ansible. They verify
the pure-logic helper functions and input validation in isolation.
"""

import sys
import os
from unittest.mock import MagicMock, patch

import pytest

# Add the plugins directory to the path so we can import directly
PLUGINS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "oneidentity", "safeguard", "plugins", "lookup"
)
sys.path.insert(0, os.path.abspath(PLUGINS_DIR))


# ---------------------------------------------------------------------------
# safeguardcredentials — _resolve_verify
# ---------------------------------------------------------------------------

class TestCredentialsResolveVerify:
    """Test _resolve_verify in safeguardcredentials plugin."""

    def test_path_string_returns_path(self):
        from safeguardcredentials import _resolve_verify

        assert _resolve_verify("/path/to/ca.pem") == "/path/to/ca.pem"

    def test_empty_string_with_validate_true_returns_true(self):
        from safeguardcredentials import _resolve_verify

        assert _resolve_verify("", validate_certs=True) is True

    def test_none_with_validate_true_returns_true(self):
        from safeguardcredentials import _resolve_verify

        assert _resolve_verify(None, validate_certs=True) is True

    def test_none_with_validate_false_returns_false(self):
        from safeguardcredentials import _resolve_verify

        assert _resolve_verify(None, validate_certs=False) is False

    def test_path_overrides_validate_false(self):
        from safeguardcredentials import _resolve_verify

        assert _resolve_verify("/ca.pem", validate_certs=False) == "/ca.pem"

    def test_false_with_validate_false_returns_false(self):
        from safeguardcredentials import _resolve_verify

        assert _resolve_verify(False, validate_certs=False) is False


# ---------------------------------------------------------------------------
# safeguardaccessrequest — _resolve_verify
# ---------------------------------------------------------------------------

class TestAccessRequestResolveVerify:
    """Test _resolve_verify in safeguardaccessrequest plugin."""

    def test_path_string_returns_path(self):
        from safeguardaccessrequest import _resolve_verify

        assert _resolve_verify("/path/to/ca.pem") == "/path/to/ca.pem"

    def test_none_with_validate_true_returns_true(self):
        from safeguardaccessrequest import _resolve_verify

        assert _resolve_verify(None, validate_certs=True) is True

    def test_none_with_validate_false_returns_false(self):
        from safeguardaccessrequest import _resolve_verify

        assert _resolve_verify(None, validate_certs=False) is False

    def test_path_overrides_validate_false(self):
        from safeguardaccessrequest import _resolve_verify

        assert _resolve_verify("/ca.pem", validate_certs=False) == "/ca.pem"


# ---------------------------------------------------------------------------
# safeguardaccessrequest — _find_entitlement
# ---------------------------------------------------------------------------

class TestFindEntitlement:
    """Test _find_entitlement logic with mocked client."""

    def _mock_client_with_entitlements(self, entitlements):
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = entitlements
        client.get.return_value = resp
        return client

    def test_matches_by_asset_name(self):
        from safeguardaccessrequest import _find_entitlement

        client = self._mock_client_with_entitlements([
            {"Account": {"Id": 1, "AssetId": 10, "AssetName": "myserver",
                         "AssetNetworkAddress": "10.0.0.1", "Name": "root"}},
        ])
        result = _find_entitlement(client, "myserver", "password")
        assert result == {"AccountId": 1, "AssetId": 10}

    def test_matches_by_network_address(self):
        from safeguardaccessrequest import _find_entitlement

        client = self._mock_client_with_entitlements([
            {"Account": {"Id": 2, "AssetId": 20, "AssetName": "dbserver",
                         "AssetNetworkAddress": "10.0.0.5", "Name": "admin"}},
        ])
        result = _find_entitlement(client, "10.0.0.5", "password")
        assert result == {"AccountId": 2, "AssetId": 20}

    def test_case_insensitive_match(self):
        from safeguardaccessrequest import _find_entitlement

        client = self._mock_client_with_entitlements([
            {"Account": {"Id": 3, "AssetId": 30, "AssetName": "MyServer",
                         "AssetNetworkAddress": "10.0.0.2", "Name": "user1"}},
        ])
        result = _find_entitlement(client, "myserver", "password")
        assert result == {"AccountId": 3, "AssetId": 30}

    def test_filters_by_account_name(self):
        from safeguardaccessrequest import _find_entitlement

        client = self._mock_client_with_entitlements([
            {"Account": {"Id": 1, "AssetId": 10, "AssetName": "server",
                         "AssetNetworkAddress": "10.0.0.1", "Name": "root"}},
            {"Account": {"Id": 2, "AssetId": 10, "AssetName": "server",
                         "AssetNetworkAddress": "10.0.0.1", "Name": "admin"}},
        ])
        result = _find_entitlement(client, "server", "password", account_name="admin")
        assert result == {"AccountId": 2, "AssetId": 10}

    def test_raises_when_no_match(self):
        from ansible.errors import AnsibleError
        from safeguardaccessrequest import _find_entitlement

        client = self._mock_client_with_entitlements([
            {"Account": {"Id": 1, "AssetId": 10, "AssetName": "other",
                         "AssetNetworkAddress": "10.0.0.9", "Name": "root"}},
        ])
        with pytest.raises(AnsibleError, match="not found in entitlements"):
            _find_entitlement(client, "myserver", "password")

    def test_raises_when_account_not_found(self):
        from ansible.errors import AnsibleError
        from safeguardaccessrequest import _find_entitlement

        client = self._mock_client_with_entitlements([
            {"Account": {"Id": 1, "AssetId": 10, "AssetName": "server",
                         "AssetNetworkAddress": "10.0.0.1", "Name": "root"}},
        ])
        with pytest.raises(AnsibleError, match="No entitlement found for account"):
            _find_entitlement(client, "server", "password", account_name="nobody")

    def test_raises_on_multiple_matches(self):
        from ansible.errors import AnsibleError
        from safeguardaccessrequest import _find_entitlement

        client = self._mock_client_with_entitlements([
            {"Account": {"Id": 1, "AssetId": 10, "AssetName": "server",
                         "AssetNetworkAddress": "10.0.0.1", "Name": "root"}},
            {"Account": {"Id": 2, "AssetId": 10, "AssetName": "server",
                         "AssetNetworkAddress": "10.0.0.1", "Name": "admin"}},
        ])
        with pytest.raises(AnsibleError, match="Multiple entitlements"):
            _find_entitlement(client, "server", "password")

    def test_raises_on_api_error(self):
        from ansible.errors import AnsibleError
        from safeguardaccessrequest import _find_entitlement

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Forbidden"
        client.get.return_value = resp

        with pytest.raises(AnsibleError, match="Error obtaining entitlements"):
            _find_entitlement(client, "server", "password")


# ---------------------------------------------------------------------------
# safeguardaccessrequest — _find_existing_request
# ---------------------------------------------------------------------------

class TestFindExistingRequest:
    """Test _find_existing_request logic."""

    def test_finds_active_request(self):
        from safeguardaccessrequest import _find_existing_request

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [
            {"Id": "req-123", "State": "RequestAvailable", "WasExpired": False},
        ]
        client.get.return_value = resp

        result = _find_existing_request(client, 1, 10, "Password")
        assert result == "req-123"

    def test_skips_expired_request(self):
        from safeguardaccessrequest import _find_existing_request

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [
            {"Id": "req-old", "State": "RequestAvailable", "WasExpired": True},
        ]
        client.get.return_value = resp

        result = _find_existing_request(client, 1, 10, "Password")
        assert result is None

    def test_returns_none_on_api_error(self):
        from safeguardaccessrequest import _find_existing_request

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 500
        client.get.return_value = resp

        result = _find_existing_request(client, 1, 10, "Password")
        assert result is None

    def test_returns_none_when_no_requests(self):
        from safeguardaccessrequest import _find_existing_request

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = []
        client.get.return_value = resp

        result = _find_existing_request(client, 1, 10, "Password")
        assert result is None


# ---------------------------------------------------------------------------
# safeguardaccessrequest — _checkout_with_retry
# ---------------------------------------------------------------------------

class TestCheckoutWithRetry:
    """Test _checkout_with_retry logic."""

    def test_returns_on_first_success(self):
        from safeguardaccessrequest import _checkout_with_retry

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = "MyPassword123"
        client.post.return_value = resp

        result = _checkout_with_retry(client, "req-1", "password", timeout=10)
        assert result == "MyPassword123"
        assert client.post.call_count == 1

    def test_retries_on_failure_then_succeeds(self):
        from safeguardaccessrequest import _checkout_with_retry

        client = MagicMock()
        fail_resp = MagicMock()
        fail_resp.status_code = 409
        fail_resp.text = "Not ready"
        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.json.return_value = "GotIt"
        client.post.side_effect = [fail_resp, success_resp]

        result = _checkout_with_retry(client, "req-1", "password", timeout=30)
        assert result == "GotIt"

    def test_raises_after_timeout(self):
        from ansible.errors import AnsibleError
        from safeguardaccessrequest import _checkout_with_retry

        client = MagicMock()
        fail_resp = MagicMock()
        fail_resp.status_code = 409
        fail_resp.text = "Not ready"
        client.post.return_value = fail_resp

        with pytest.raises(AnsibleError, match="Error checking out credential"):
            _checkout_with_retry(client, "req-1", "password", timeout=0)


# ---------------------------------------------------------------------------
# safeguardaccessrequest — _create_or_reuse_request
# ---------------------------------------------------------------------------

class TestCreateOrReuseRequest:
    """Test _create_or_reuse_request logic."""

    def test_returns_new_request_id_on_201(self):
        from safeguardaccessrequest import _create_or_reuse_request

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 201
        resp.json.return_value = {"Id": "new-req-id"}
        client.post.return_value = resp

        result = _create_or_reuse_request(client, 1, 10, "myasset", "password")
        assert result == "new-req-id"

    def test_reuses_existing_on_error_90001(self):
        from safeguardaccessrequest import _create_or_reuse_request

        client = MagicMock()
        # First call: POST to create request fails with 90001
        create_resp = MagicMock()
        create_resp.status_code = 400
        create_resp.json.return_value = {"Code": "90001", "Message": "Already exists"}
        create_resp.text = '{"Code": "90001"}'
        # Second call: GET to find existing
        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.json.return_value = [
            {"Id": "existing-id", "State": "RequestAvailable", "WasExpired": False}
        ]
        client.post.return_value = create_resp
        client.get.return_value = get_resp

        result = _create_or_reuse_request(client, 1, 10, "myasset", "password")
        assert result == "existing-id"

    def test_raises_on_other_error(self):
        from ansible.errors import AnsibleError
        from safeguardaccessrequest import _create_or_reuse_request

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Forbidden"
        resp.json.return_value = {"Code": "60108", "Message": "Forbidden"}
        client.post.return_value = resp

        with pytest.raises(AnsibleError, match="Error creating access request"):
            _create_or_reuse_request(client, 1, 10, "myasset", "password")


# ---------------------------------------------------------------------------
# safeguardcredentials — validate_certs normalization
# ---------------------------------------------------------------------------

class TestCredentialsValidateCertsNormalization:
    """Test that validate_certs string values are properly normalized.

    This tests the logic inline in the LookupModule.run method by verifying
    _resolve_verify handles the normalized boolean values correctly.
    """

    def test_string_false_normalizes(self):
        """'false' string should map to validate_certs=False."""
        from safeguardcredentials import _resolve_verify

        val = "false"
        normalized = val.lower() not in ('false', '0', 'no')
        assert normalized is False
        assert _resolve_verify(None, validate_certs=normalized) is False

    def test_string_true_normalizes(self):
        """'true' string should map to validate_certs=True."""
        from safeguardcredentials import _resolve_verify

        val = "true"
        normalized = val.lower() not in ('false', '0', 'no')
        assert normalized is True
        assert _resolve_verify(None, validate_certs=normalized) is True

    def test_string_zero_normalizes(self):
        """'0' string should map to validate_certs=False."""
        from safeguardcredentials import _resolve_verify

        val = "0"
        normalized = val.lower() not in ('false', '0', 'no')
        assert normalized is False
        assert _resolve_verify(None, validate_certs=normalized) is False

    def test_string_no_normalizes(self):
        """'no' string should map to validate_certs=False."""
        from safeguardcredentials import _resolve_verify

        val = "no"
        normalized = val.lower() not in ('false', '0', 'no')
        assert normalized is False
        assert _resolve_verify(None, validate_certs=normalized) is False
