"""Provision ephemeral role-owned credentials; never overwrite existing enrollment."""

from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from examples.confined_redemption.configuration import (
    PRINCIPAL_ROLES,
    ROLE_IDENTIFIERS,
    PublicConfiguration,
)
from fixtures.registration import RegistrationFixture, generate_registration_fixture
from resource_bound_authorization.signatures import (
    load_private_key,
    private_key_hex,
    public_key_hex,
)


def _write_new_json(path: Path, document: dict[str, Any], mode: int, owner: int | None) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, sort_keys=True)
        stream.write("\n")
    path.chmod(mode)
    if owner is not None:
        os.chown(path, owner, owner)


def provision_registration(
    directory: Path, *, assign_ownership: bool = True
) -> PublicConfiguration:
    """An empty mount is allowed; any existing enrollment contents stop provisioning."""

    if assign_ownership and os.geteuid() != 0:
        raise PermissionError("role ownership provisioning requires root")
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise FileExistsError("registration directory is not empty")
    directory.chmod(0o755)
    fixtures = {role: generate_registration_fixture(role) for role in PRINCIPAL_ROLES}
    issuer_key = Ed25519PrivateKey.generate()
    bearer_credentials = {role: secrets.token_urlsafe(32) for role in PRINCIPAL_ROLES}
    public = PublicConfiguration(
        issuer_public_key=public_key_hex(issuer_key),
        registrations={role: fixture.registration for role, fixture in fixtures.items()},
    )
    for role, user_identifier in ROLE_IDENTIFIERS.items():
        role_directory = directory / role
        role_directory.mkdir(mode=0o700)
        role_directory.chmod(0o700)
        owner = user_identifier if assign_ownership else None
        private: dict[str, Any] = {}
        if role == "authorization_server":
            private["issuer_private_key"] = private_key_hex(issuer_key)
        elif role == "authorization_proxy":
            private["bearer_credentials"] = bearer_credentials
        elif role in PRINCIPAL_ROLES:
            private = {
                "holder_private_key": private_key_hex(fixtures[role].holder_private_key),
                "attestation_private_key": private_key_hex(fixtures[role].attestation_private_key),
                "proxy_bearer_credential": bearer_credentials[role],
            }
        _write_new_json(role_directory / "private.json", private, 0o600, owner)
        if owner is not None:
            os.chown(role_directory, owner, owner)
    _write_new_json(directory / "public.json", public.model_dump(mode="json"), 0o644, None)
    return public


def load_public_registration(directory: Path) -> PublicConfiguration:
    return PublicConfiguration.model_validate_json((directory / "public.json").read_bytes())


def load_role_private(directory: Path, role: str) -> dict[str, Any]:
    if role not in ROLE_IDENTIFIERS:
        raise ValueError("unknown_reference_role")
    document: Any = json.loads((directory / role / "private.json").read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("invalid_private_configuration")
    return document


def load_principal_fixture(directory: Path, role: str) -> RegistrationFixture:
    if role not in PRINCIPAL_ROLES:
        raise ValueError("role_is_not_a_registered_principal")
    registration = load_public_registration(directory).registrations[role]
    private = load_role_private(directory, role)
    return RegistrationFixture(
        registration=registration,
        holder_private_key=load_private_key(private["holder_private_key"]),
        attestation_private_key=load_private_key(private["attestation_private_key"]),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("/registration"))
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("registration provisioning must run as root")
    provision_registration(arguments.directory)
    print('{"registration":"created","assurance":"development"}')


if __name__ == "__main__":
    main()
