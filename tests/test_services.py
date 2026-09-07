"""Local transport, enrollment, and issuance boundaries with real loopback servers."""

from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

from examples.confined_redemption.procedure import run_procedure
from examples.confined_redemption.registration import (
    load_principal_fixture,
    provision_registration,
)
from examples.confined_redemption.service import (
    MAXIMUM_BODY_BYTES,
    ReferenceHTTPServer,
    create_server,
    parse_json_object,
    send_request,
)
from fixtures.registration import create_development_attestation


@dataclass
class ServiceHarness:
    directory: Path
    destinations: dict[str, tuple[str, int]]
    servers: dict[str, ReferenceHTTPServer]


@pytest.fixture
def reference_services(tmp_path: Path) -> Iterator[ServiceHarness]:
    directory = tmp_path / "registration"
    provision_registration(directory, assign_ownership=False)
    destinations: dict[str, tuple[str, int]] = {}
    servers: dict[str, ReferenceHTTPServer] = {}
    threads: list[threading.Thread] = []
    for role in (
        "authorization_server",
        "resource_server",
        "authorization_proxy",
        "delegated_principal",
    ):
        server = create_server(
            role,
            port=0,
            registration_directory=directory,
            database_path=tmp_path / "redemption.sqlite3",
            destinations=destinations,
        )
        servers[role] = server
        destinations[role] = ("127.0.0.1", server.server_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    try:
        yield ServiceHarness(directory, destinations, servers)
    finally:
        for server in servers.values():
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


def test_confined_redemption_http_procedure(reference_services: ServiceHarness) -> None:
    result = run_procedure(
        reference_services.directory, destinations=reference_services.destinations
    )
    assert result["assurance"] == "development"
    assert reference_services.servers["resource_server"].application.handler_count == 3


def test_issuance_challenge_consumed_at_most_once(reference_services: ServiceHarness) -> None:
    status, challenge = send_request(
        "authorization_server", "/challenge", {}, destinations=reference_services.destinations
    )
    assert status == 200
    registration = load_principal_fixture(reference_services.directory, "calling_principal")
    evidence = create_development_attestation(
        registration, challenge["challenge"], challenge["expires_at"]
    )
    request = {
        "challenge": challenge["challenge"],
        "calling_attestation": evidence.model_dump(mode="json"),
    }
    barrier = threading.Barrier(6)

    def request_issuance() -> int:
        barrier.wait(timeout=10)
        status, _response = send_request(
            "authorization_server",
            "/issuance",
            request,
            destinations=reference_services.destinations,
        )
        return status

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _index: request_issuance(), range(6)))
    assert results.count(200) == 1
    assert results.count(403) == 5


def test_enrollment_cannot_be_replaced_by_request(reference_services: ServiceHarness) -> None:
    status, challenge = send_request(
        "authorization_server", "/challenge", {}, destinations=reference_services.destinations
    )
    assert status == 200
    registration = load_principal_fixture(reference_services.directory, "calling_principal")
    evidence = create_development_attestation(
        registration, challenge["challenge"], challenge["expires_at"]
    )
    status, _response = send_request(
        "authorization_server",
        "/issuance",
        {
            "challenge": challenge["challenge"],
            "calling_attestation": evidence.model_dump(mode="json"),
            "trusted_registration": registration.registration.model_dump(mode="json"),
        },
        destinations=reference_services.destinations,
    )
    assert status == 400
    assert reference_services.servers["resource_server"].application.handler_count == 0


@pytest.mark.parametrize(
    "payload",
    [
        b'{"principal":"calling_principal","principal":"delegated_principal"}',
        b'{"argument":NaN}',
        b'{"argument":Infinity}',
        b"[]",
        b'{"argument":' + b"[" * 26 + b"0" + b"]" * 26 + b"}",
        b'{"argument":"' + b"a" * MAXIMUM_BODY_BYTES + b'"}',
    ],
)
def test_ambiguous_or_unbounded_json_rejected(payload: bytes) -> None:
    with pytest.raises(ValueError):
        parse_json_object(payload)


def test_duplicate_authorization_headers_rejected(reference_services: ServiceHarness) -> None:
    host, port = reference_services.destinations["resource_server"]
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.putrequest("POST", "/redemption")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "2")
        connection.putheader("Authorization", "Bearer synthetic_first_credential")
        connection.putheader("Authorization", "Bearer synthetic_second_credential")
        connection.endheaders(b"{}")
        response = connection.getresponse()
        assert response.status == 400
        assert json.loads(response.read()) == {"error": "invalid_reference_request"}
    finally:
        connection.close()
    assert reference_services.servers["resource_server"].application.handler_count == 0


def test_reference_transport_rejects_unregistered_destinations() -> None:
    with pytest.raises(ValueError, match="unrecognized_reference_destination"):
        send_request("unregistered_server", "/redemption", {})
    with pytest.raises(ValueError, match="unrecognized_reference_destination"):
        send_request("resource_server", "https://example.invalid/redemption", {})


def test_registration_does_not_overwrite_existing_credentials(tmp_path: Path) -> None:
    directory = tmp_path / "registration"
    provision_registration(directory, assign_ownership=False)
    original = (directory / "public.json").read_bytes()
    with pytest.raises((ValueError, FileExistsError)):
        provision_registration(directory, assign_ownership=False)
    assert (directory / "public.json").read_bytes() == original


def test_private_fixture_permissions_are_restricted(tmp_path: Path) -> None:
    directory = tmp_path / "registration"
    provision_registration(directory, assign_ownership=False)
    for role in ("authorization_server", "calling_principal", "delegated_principal"):
        assert (directory / role).stat().st_mode & 0o777 == 0o700
        assert (directory / role / "private.json").stat().st_mode & 0o777 == 0o600
    public_text = (directory / "public.json").read_text()
    assert "private_key" not in public_text
    assert "bearer_credential" not in public_text
