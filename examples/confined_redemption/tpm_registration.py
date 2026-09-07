"""Synthetic software-TPM enrollment and serialized quotations for each role.

Each principal receives its own saved AK context. Quote generation reads only
that role's context and writes temporary output under /tmp. A shared, read-only
lock file serializes simulator use across UIDs; it contains no secret material.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import subprocess  # nosec B404
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from resource_bound_authorization.tpm_verification import (
    SoftwareTPMAttestation,
    SoftwareTPMTrust,
    software_tpm_qualifying_data,
)
from resource_bound_authorization.verification import (
    PrincipalRegistration,
    verify_registered_manifest,
)

_COMMANDS = frozenset(
    {
        "tpm2_createak",
        "tpm2_createek",
        "tpm2_flushcontext",
        "tpm2_pcrreset",
        "tpm2_pcrextend",
        "tpm2_quote",
    }
)
_PROFILE_EVENT = hashlib.sha256(b"resource-bound-authorization:enrolled-software-tpm:v1").digest()
_EXPECTED_COMPOSITE = hashlib.sha256(
    hashlib.sha256(bytes(32) + _PROFILE_EVENT).digest()
).hexdigest()


@contextmanager
def _simulator_lock(lock_path: Path) -> Iterator[None]:
    # flock on Linux accepts an exclusive lock on a read-only regular file.
    with lock_path.open("rb") as stream:
        deadline = time.monotonic() + 10
        while True:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("software TPM operation lock timed out") from None
                time.sleep(0.01)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _run(interface: str, command: str, *arguments: str, check: bool = True) -> None:
    if command not in _COMMANDS or type(interface) is not str or not interface:
        raise ValueError("invalid software TPM operation")
    executable = shutil.which(command)
    if executable is None:
        raise RuntimeError("required software TPM tool is unavailable")
    # Fixed executable allowlist, fixed operation arguments, and no shell execution.
    subprocess.run(  # noqa: S603  # nosec B603
        [executable, *arguments],
        env={**os.environ, "TPM2TOOLS_TCTI": interface},
        check=check,
        capture_output=True,
        timeout=20,
    )


def _certificate_usage(ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _synthetic_certificate_chain(public_pem: bytes) -> tuple[str, str]:
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("synthetic enrollment requires an RSA AK")
    now = datetime.now(UTC)
    root_key = Ed25519PrivateKey.generate()
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic TPM Enrollment Authority")]
    )
    root = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=24))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_certificate_usage(True), critical=True)
        .sign(root_key, algorithm=None)
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Enrolled software TPM AK")])
        )
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=24))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_certificate_usage(False), critical=True)
        .sign(root_key, algorithm=None)
    )
    root_pem = root.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return leaf.public_bytes(serialization.Encoding.PEM).decode("ascii") + root_pem, root_pem


def enroll_principal_tpm(
    registration: PrincipalRegistration,
    role_directory: Path,
    interface: str,
    *,
    lock_path: Path,
) -> SoftwareTPMTrust:
    """Bootstrap a fresh AK and public synthetic trust before role ownership is applied.

    This resets and extends the disposable simulator's PCR 16 to the same fixed
    fixture value for both principals. Quote operations never reset or extend it.
    """

    verify_registered_manifest(registration)
    context_destination = role_directory / "attestation.context"
    with (
        _simulator_lock(lock_path),
        tempfile.TemporaryDirectory(prefix="software-tpm-enrollment-") as temporary,
    ):
        if context_destination.exists():
            raise FileExistsError("principal already has an enrolled attestation context")
        directory = Path(temporary)
        endorsement_context = directory / "endorsement.context"
        attestation_context = directory / "attestation.context"
        public_path = directory / "attestation.public.pem"
        try:
            _run(interface, "tpm2_flushcontext", "-t", check=False)
            _run(interface, "tpm2_pcrreset", "16")
            _run(interface, "tpm2_pcrextend", f"16:sha256={_PROFILE_EVENT.hex()}")
            _run(interface, "tpm2_createek", "-G", "rsa", "-c", str(endorsement_context))
            _run(
                interface,
                "tpm2_createak",
                "-C",
                str(endorsement_context),
                "-G",
                "rsa",
                "-g",
                "sha256",
                "-s",
                "rsassa",
                "-c",
                str(attestation_context),
                "-u",
                str(public_path),
                "-f",
                "pem",
            )
            public_pem = public_path.read_bytes()
            chain, roots = _synthetic_certificate_chain(public_pem)
            trust = SoftwareTPMTrust(
                principal_identifier=registration.principal_identifier,
                holder_public_key=registration.identity_public_key,
                manifest_digest=registration.manifest_digest,
                ak_certificate_chain_pem=chain,
                trusted_roots_pem=roots,
                enrolled_ak_public_key_pem=public_pem.decode("ascii"),
                expected_pcr_digest=_EXPECTED_COMPOSITE,
            )
            descriptor = os.open(context_destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(attestation_context.read_bytes())
            context_destination.chmod(0o600)
            return trust
        finally:
            _run(interface, "tpm2_flushcontext", "-t", check=False)


def create_software_tpm_attestation(
    registration: PrincipalRegistration,
    role_directory: Path,
    interface: str,
    challenge: str,
    expires_at: int,
    *,
    lock_path: Path,
) -> SoftwareTPMAttestation:
    """Quote the exact caller transcript using only this principal's enrolled AK."""

    qualifying_data = software_tpm_qualifying_data(
        registration.principal_identifier,
        registration.identity_public_key,
        registration.manifest_digest,
        challenge,
        expires_at,
    )
    context_path = role_directory / "attestation.context"
    with (
        _simulator_lock(lock_path),
        tempfile.TemporaryDirectory(prefix="software-tpm-quote-") as temporary,
    ):
        directory = Path(temporary)
        qualifying_path = directory / "qualifying.bin"
        qualifying_path.write_bytes(qualifying_data)
        quote_path = directory / "quote.attest"
        signature_path = directory / "quote.signature"
        try:
            _run(interface, "tpm2_flushcontext", "-t", check=False)
            _run(
                interface,
                "tpm2_quote",
                "-Q",
                "-c",
                str(context_path),
                "-l",
                "sha256:16",
                "-q",
                str(qualifying_path),
                "-g",
                "sha256",
                "-f",
                "tss",
                "-m",
                str(quote_path),
                "-s",
                str(signature_path),
            )
            return SoftwareTPMAttestation(
                principal_identifier=registration.principal_identifier,
                holder_public_key=registration.identity_public_key,
                manifest_digest=registration.manifest_digest,
                challenge=challenge,
                expires_at=expires_at,
                quote_hex=quote_path.read_bytes().hex(),
                signature_hex=signature_path.read_bytes().hex(),
            )
        finally:
            _run(interface, "tpm2_flushcontext", "-t", check=False)
