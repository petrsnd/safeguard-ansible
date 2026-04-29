# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Integration tests for TLS certificate verification."""

import pytest

from conftest import run_playbook


pytestmark = pytest.mark.integration


class TestTlsVerification:
    """Tests that TLS verification works end-to-end with a CA bundle."""

    def test_a2a_with_ca_bundle(self, a2a_setup, spp_host, ca_bundle_path, ansible_env):
        """A2A retrieval succeeds with TLS verification using the appliance CA bundle."""
        run_playbook(
            "a2a_tls_verified.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
                "spp_ca_cert": ca_bundle_path,
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": a2a_setup["pw_api_key"]},
        )

    def test_accessrequest_with_ca_bundle(self, ar_setup, ca_bundle_path, ansible_env):
        """Access request retrieval succeeds with TLS verification using the appliance CA bundle."""
        run_playbook(
            "accessrequest_tls_verified.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["pw_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
                "spp_ca_cert": ca_bundle_path,
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
        )

    def test_a2a_fails_without_ca_bundle(self, a2a_setup, spp_host, ansible_env):
        """A2A retrieval fails when validate_certs=true but no CA bundle covers the appliance."""
        result = run_playbook(
            "a2a_tls_verified.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
                "spp_ca_cert": "/nonexistent/bogus_ca.pem",
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": a2a_setup["pw_api_key"]},
            expect_failure=True,
        )
        assert result.returncode != 0
