# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Unit tests for the credential type plugin.

These tests do NOT require a live SPP appliance or pysafeguard to be
exercising the import path. They verify the plugin's defensive behavior.
"""

import importlib
import sys
from unittest.mock import patch

import pytest


class TestLazyImport:
    """Verify that the plugin module loads without pysafeguard (issue #3)."""

    def test_module_loads_without_pysafeguard(self):
        """The entry point module must import even if pysafeguard is absent."""
        # Temporarily hide pysafeguard from the import system
        with patch.dict(sys.modules, {"pysafeguard": None}):
            # Force a fresh import of the plugin module
            if "safeguardcredentialtype" in sys.modules:
                mod = importlib.reload(
                    sys.modules["safeguardcredentialtype"]
                )
            else:
                mod = importlib.import_module("safeguardcredentialtype")

            # The CredentialPlugin namedtuple must be accessible
            assert mod.spp_plugin is not None
            assert mod.spp_plugin.name == "Safeguard Credential"

    def test_backend_raises_clear_error_when_pysafeguard_missing(self):
        """Calling the backend without pysafeguard gives a helpful message."""
        from safeguardcredentialtype import _get_spp_credential

        with patch.dict(sys.modules, {"pysafeguard": None}):
            # Also need to make the import inside the function fail
            original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

            def mock_import(name, *args, **kwargs):
                if name == "pysafeguard":
                    raise ImportError("No module named 'pysafeguard'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                with pytest.raises(ValueError, match="pysafeguard.*not installed"):
                    _get_spp_credential(
                        spp_api_key="fake-key",
                        spp_appliance="10.0.0.1",
                        spp_certificate_path="/tmp/cert.pem",
                        spp_key_path="/tmp/key.pem",
                    )


class TestResolveVerify:
    """Test the _resolve_verify helper."""

    def test_path_string_returns_path(self):
        from safeguardcredentialtype import _resolve_verify

        assert _resolve_verify("/path/to/ca.pem") == "/path/to/ca.pem"

    def test_empty_string_with_validate_true_returns_true(self):
        from safeguardcredentialtype import _resolve_verify

        assert _resolve_verify("", validate_certs=True) is True

    def test_none_with_validate_true_returns_true(self):
        from safeguardcredentialtype import _resolve_verify

        assert _resolve_verify(None, validate_certs=True) is True

    def test_none_with_validate_false_returns_false(self):
        from safeguardcredentialtype import _resolve_verify

        assert _resolve_verify(None, validate_certs=False) is False

    def test_path_overrides_validate_false(self):
        from safeguardcredentialtype import _resolve_verify

        # If a CA path is given, it takes precedence over validate_certs=False
        assert _resolve_verify("/path/to/ca.pem", validate_certs=False) == "/path/to/ca.pem"


class TestInputValidation:
    """Test input validation in the backend function."""

    def test_missing_api_key(self):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Missing credential API key"):
            _get_spp_credential(
                spp_appliance="10.0.0.1",
                spp_certificate_path="/tmp/cert.pem",
                spp_key_path="/tmp/key.pem",
            )

    def test_missing_appliance(self):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Missing appliance"):
            _get_spp_credential(
                spp_api_key="fake-key",
                spp_certificate_path="/tmp/cert.pem",
                spp_key_path="/tmp/key.pem",
            )

    def test_missing_certificate(self):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Missing client authentication certificate"):
            _get_spp_credential(
                spp_api_key="fake-key",
                spp_appliance="10.0.0.1",
                spp_key_path="/tmp/key.pem",
            )

    def test_missing_key(self):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Missing client authentication key"):
            _get_spp_credential(
                spp_api_key="fake-key",
                spp_appliance="10.0.0.1",
                spp_certificate_path="/tmp/cert.pem",
            )

    def test_invalid_credential_type(self):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Invalid credential type"):
            _get_spp_credential(
                spp_api_key="fake-key",
                spp_appliance="10.0.0.1",
                spp_certificate_path="/tmp/cert.pem",
                spp_key_path="/tmp/key.pem",
                spp_credential_type="invalid",
            )


class TestValidateCertsNormalization:
    """Test string-to-bool normalization for validate_certs."""

    def test_string_false(self):
        from safeguardcredentialtype import _get_spp_credential

        # Should not raise about validate_certs — will fail on network instead
        with pytest.raises(ValueError, match="Failed to retrieve"):
            _get_spp_credential(
                spp_api_key="fake-key",
                spp_appliance="192.0.2.1",
                spp_certificate_path="/tmp/cert.pem",
                spp_key_path="/tmp/key.pem",
                spp_validate_certs="false",
            )

    def test_string_zero(self):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Failed to retrieve"):
            _get_spp_credential(
                spp_api_key="fake-key",
                spp_appliance="192.0.2.1",
                spp_certificate_path="/tmp/cert.pem",
                spp_key_path="/tmp/key.pem",
                spp_validate_certs="0",
            )

    def test_string_true(self):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Failed to retrieve"):
            _get_spp_credential(
                spp_api_key="fake-key",
                spp_appliance="192.0.2.1",
                spp_certificate_path="/tmp/cert.pem",
                spp_key_path="/tmp/key.pem",
                spp_validate_certs="true",
            )
