# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Integration tests for the safeguardcredentials A2A lookup plugin."""

import pytest

from conftest import run_playbook, KNOWN_PASSWORD


pytestmark = pytest.mark.integration


class TestA2APasswordRetrieval:
    """Tests for A2A password credential retrieval."""

    def test_retrieve_password(self, a2a_setup, spp_host, ansible_env):
        run_playbook(
            "a2a_password.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": a2a_setup["pw_api_key"]},
        )

    def test_password_value_matches(self, a2a_setup, spp_host, ansible_env):
        """Verify the retrieved password matches what was provisioned."""
        run_playbook(
            "a2a_known_password.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={
                "SGANS_A2A_API_KEY": a2a_setup["pw_api_key"],
                "SGANS_EXPECTED_PASSWORD": KNOWN_PASSWORD,
            },
        )


class TestA2APrivateKeyRetrieval:
    """Tests for A2A SSH private key credential retrieval."""

    def test_retrieve_privatekey(self, a2a_setup, spp_host, ansible_env):
        run_playbook(
            "a2a_privatekey.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": a2a_setup["sshkey_api_key"]},
        )


class TestA2AMultiKeyRetrieval:
    """Tests for retrieving multiple credentials in a single lookup call."""

    def test_two_api_keys(self, a2a_setup, spp_host, ansible_env):
        """Pass two API keys in one lookup — should get two password results."""
        run_playbook(
            "a2a_multi_key.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={
                "SGANS_A2A_API_KEY_1": a2a_setup["pw_api_key"],
                "SGANS_A2A_API_KEY_2": a2a_setup["sshkey_api_key"],
            },
        )


class TestA2AErrorHandling:
    """Tests for error conditions in the A2A plugin."""

    def test_invalid_api_key(self, a2a_setup, spp_host, ansible_env):
        result = run_playbook(
            "a2a_password.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": "00000000-0000-0000-0000-000000000000"},
            expect_failure=True,
        )
        assert result.returncode != 0

    def test_missing_appliance(self, a2a_setup, ansible_env):
        """Missing spp_appliance should produce a clear validation error."""
        result = run_playbook(
            "a2a_missing_appliance.yml",
            extra_vars={
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": a2a_setup["pw_api_key"]},
            expect_failure=True,
        )
        assert result.returncode != 0
        assert "Missing appliance" in result.stdout or "Missing appliance" in result.stderr

    def test_missing_cert(self, a2a_setup, spp_host, ansible_env):
        """Missing spp_certificate_file should produce a clear validation error."""
        result = run_playbook(
            "a2a_missing_cert.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": a2a_setup["pw_api_key"]},
            expect_failure=True,
        )
        assert result.returncode != 0
        assert "Missing client authentication" in result.stdout or "Missing client authentication" in result.stderr

    def test_invalid_credential_type(self, a2a_setup, spp_host, ansible_env):
        """Invalid spp_credential_type should produce a clear error."""
        result = run_playbook(
            "a2a_invalid_credtype.yml",
            extra_vars={
                "spp_host": spp_host,
                "a2a_cert_file": a2a_setup["cert_path"],
                "a2a_cert_key": a2a_setup["key_path"],
            },
            ansible_env=ansible_env,
            secret_env={"SGANS_A2A_API_KEY": a2a_setup["pw_api_key"]},
            expect_failure=True,
        )
        assert result.returncode != 0
        assert "Invalid credential type" in result.stdout or "Invalid credential type" in result.stderr
