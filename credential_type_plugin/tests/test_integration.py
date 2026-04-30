# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Integration tests for the credential type plugin.

These tests require a live SPP appliance. They self-provision all needed
objects (asset, account, A2A registration, client cert) and clean up
afterward. Set the following environment variables:

    SPP_HOST            Appliance address (required)
    SPP_ADMIN_PASSWORD  Bootstrap admin password (default: Admin123)
    SPP_CA_FILE         TLS CA bundle path (optional)

All tests are marked with @pytest.mark.integration and will be skipped
when SPP_HOST is not set.
"""

import pytest


pytestmark = pytest.mark.integration


class TestPasswordRetrieval:
    """Test password retrieval via the plugin backend."""

    def test_retrieve_password(self, spp_host, spp_verify, a2a_setup):
        from safeguardcredentialtype import _get_spp_credential

        result = _get_spp_credential(
            spp_api_key=a2a_setup["api_key"],
            spp_appliance=spp_host,
            spp_certificate_path=a2a_setup["cert_path"],
            spp_key_path=a2a_setup["key_path"],
            spp_tls_path=spp_verify if spp_verify else None,
            spp_validate_certs=bool(spp_verify),
            spp_credential_type="password",
        )
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0

    def test_retrieve_known_password(self, spp_host, spp_verify, a2a_setup):
        from safeguardcredentialtype import _get_spp_credential

        result = _get_spp_credential(
            spp_api_key=a2a_setup["api_key"],
            spp_appliance=spp_host,
            spp_certificate_path=a2a_setup["cert_path"],
            spp_key_path=a2a_setup["key_path"],
            spp_tls_path=spp_verify if spp_verify else None,
            spp_validate_certs=bool(spp_verify),
            spp_credential_type="password",
        )
        assert result == a2a_setup["known_password"]


class TestErrorHandling:
    """Test error handling with invalid inputs against a live appliance."""

    def test_invalid_api_key(self, spp_host, spp_verify, a2a_setup):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Failed to retrieve"):
            _get_spp_credential(
                spp_api_key="00000000-0000-0000-0000-000000000000",
                spp_appliance=spp_host,
                spp_certificate_path=a2a_setup["cert_path"],
                spp_key_path=a2a_setup["key_path"],
                spp_tls_path=spp_verify if spp_verify else None,
                spp_validate_certs=bool(spp_verify),
                spp_credential_type="password",
            )

    def test_unreachable_appliance(self, a2a_setup):
        from safeguardcredentialtype import _get_spp_credential

        with pytest.raises(ValueError, match="Failed to retrieve"):
            _get_spp_credential(
                spp_api_key=a2a_setup["api_key"],
                spp_appliance="192.0.2.1",
                spp_certificate_path=a2a_setup["cert_path"],
                spp_key_path=a2a_setup["key_path"],
                spp_validate_certs="false",
                spp_credential_type="password",
            )
