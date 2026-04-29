# Copyright (c) One Identity LLC.
# Licensed under the Apache License, Version 2.0.
# See LICENSE file in the project root for full license information.

"""Generate self-signed client certificates for A2A integration testing."""

import os
import subprocess
import tempfile


def generate_client_cert(tmpdir=None):
    """Generate a self-signed client certificate and private key.

    :arg tmpdir: Directory to write files into (created if None)
    :returns: (cert_path, key_path, thumbprint)
    """
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp(prefix="sgans_")

    cert_path = os.path.join(tmpdir, "client.pem")
    key_path = os.path.join(tmpdir, "client.key")

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes",
            "-subj", "/CN=SgAns_IntegrationTest",
        ],
        capture_output=True,
        check=True,
    )

    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-fingerprint", "-noout", "-sha1"],
        capture_output=True,
        text=True,
        check=True,
    )
    thumbprint = result.stdout.strip().split("=")[1].replace(":", "")

    return cert_path, key_path, thumbprint


def read_cert_base64(cert_path):
    """Read a PEM certificate and return the base64-encoded DER data.

    :arg cert_path: Path to a PEM-encoded certificate
    :returns: Base64 string (no PEM headers/footers)
    """
    with open(cert_path) as f:
        pem = f.read()
    return "".join(
        pem.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .split()
    )


def generate_ssh_keypair(tmpdir=None):
    """Generate an RSA SSH key pair.

    :arg tmpdir: Directory to write files into (created if None)
    :returns: (private_key_path, private_key_contents)
    """
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp(prefix="sgans_")

    key_path = os.path.join(tmpdir, "ssh_test_key")
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", key_path, "-N", "", "-q"],
        capture_output=True,
        check=True,
    )

    with open(key_path) as f:
        private_key = f.read()

    return key_path, private_key
