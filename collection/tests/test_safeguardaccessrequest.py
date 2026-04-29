# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Integration tests for the safeguardaccessrequest lookup plugin."""

import pytest

from conftest import run_playbook, KNOWN_PASSWORD


pytestmark = pytest.mark.integration


class TestAccessRequestPassword:
    """Tests for access request password retrieval."""

    def test_retrieve_password(self, ar_setup, ansible_env):
        run_playbook(
            "accessrequest_password.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["pw_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
        )

    def test_retrieve_with_account_name(self, ar_setup, ansible_env):
        run_playbook(
            "accessrequest_account.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["pw_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
        )

    def test_password_value_matches(self, ar_setup, ansible_env):
        """Verify the retrieved password matches the known value we provisioned."""
        run_playbook(
            "accessrequest_known_password.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["pw_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={
                "SGANS_SPP_PASSWORD": ar_setup["spp_password"],
                "SGANS_EXPECTED_PASSWORD": KNOWN_PASSWORD,
            },
        )


class TestAccessRequestPrivateKey:
    """Tests for access request SSH private key retrieval."""

    def test_retrieve_privatekey(self, ar_setup, ansible_env):
        run_playbook(
            "accessrequest_privatekey.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["sshkey_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
        )

    def test_sshkey_with_explicit_account(self, ar_setup, ansible_env):
        """Retrieve SSH key specifying the account name explicitly."""
        run_playbook(
            "accessrequest_sshkey_account.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["sshkey_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
        )


class TestAccessRequestEnvVars:
    """Tests using environment variable configuration."""

    def test_envvar_config(self, ar_setup, ansible_env):
        env_secrets = {
            "SPP_APPLIANCE": ar_setup["spp_appliance"],
            "SPP_PROVIDER": ar_setup["spp_provider"],
            "SPP_USER": ar_setup["spp_user"],
            "SPP_PASSWORD": ar_setup["spp_password"],
        }
        run_playbook(
            "accessrequest_envvars.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["pw_account_name"],
            },
            ansible_env=ansible_env,
            secret_env=env_secrets,
        )


class TestAccessRequestErrorHandling:
    """Tests for error conditions."""

    def test_invalid_asset(self, ar_setup, ansible_env):
        result = run_playbook(
            "accessrequest_password.yml",
            extra_vars={
                "asset_name": "SgAns_NonExistent_Asset",
                "account_name": "nonexistent",
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
            expect_failure=True,
        )
        assert result.returncode != 0

    def test_invalid_account_name(self, ar_setup, ansible_env):
        """Valid asset but non-existent account should produce an entitlement error."""
        result = run_playbook(
            "accessrequest_account.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": "SgAns_BogusAccount",
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
            expect_failure=True,
        )
        assert result.returncode != 0

    def test_invalid_credential_type(self, ar_setup, ansible_env):
        """Invalid spp_credential_type should produce a clear validation error."""
        result = run_playbook(
            "accessrequest_invalid_credtype.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["pw_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_SPP_PASSWORD": ar_setup["spp_password"]},
            expect_failure=True,
        )
        assert result.returncode != 0
        assert "bogus" in result.stdout, "Error output should mention the invalid value"

    def test_bad_credentials(self, ar_setup, ansible_env):
        """Wrong password should produce an authentication error."""
        result = run_playbook(
            "accessrequest_bad_credentials.yml",
            extra_vars={
                "asset_name": ar_setup["asset_name"],
                "account_name": ar_setup["pw_account_name"],
                "spp_appliance": ar_setup["spp_appliance"],
                "spp_provider": ar_setup["spp_provider"],
                "spp_user": ar_setup["spp_user"],
            },
            ansible_env=ansible_env,
            expect_failure=True,
        )
        assert result.returncode != 0
