"""Bounded local HTTP services for synthetic resource authorization verification."""

from __future__ import annotations

import argparse
import hmac
import http.client
import json
import math
import os
import secrets
import threading
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from examples.confined_redemption.configuration import (
    DEFAULT_DESTINATIONS,
    OBJECT_IDENTIFIER,
    PRINCIPAL_ROLES,
    SERVICE_ROLES,
    resource_policy,
)
from examples.confined_redemption.registration import (
    load_principal_fixture,
    load_public_registration,
    load_role_private,
)
from fixtures.registration import create_development_attestation
from resource_bound_authorization.attenuation import verify_attenuation_record
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.forwarding import (
    build_forwarding_request,
    reject_forwarded_bearer,
)
from resource_bound_authorization.issuance import issue_capability, verify_capability
from resource_bound_authorization.models import CapabilityEnvelope, ResourceRequest
from resource_bound_authorization.redemption import (
    RedemptionStore,
    create_invocation,
    redeem_capability,
)
from resource_bound_authorization.signatures import load_private_key
from resource_bound_authorization.verification import (
    DevelopmentAttestation,
    verify_development_attestation,
)

MAXIMUM_BODY_BYTES = 65536
DestinationMap = Mapping[str, tuple[str, int]]
_PATHS = frozenset(
    {
        "/health",
        "/challenge",
        "/issuance",
        "/forwarding",
        "/redemption",
        "/attestation",
        "/verification",
    }
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("nonfinite_json_number")


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > 24:
        raise ValueError("json_nesting_exceeded")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite_json_number")
    values = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for child in values:
        _check_depth(child, depth + 1)


def parse_json_object(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAXIMUM_BODY_BYTES:
        raise ValueError("request_body_too_large")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except RecursionError as error:
        raise ValueError("json_nesting_exceeded") from error
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    _check_depth(value)
    return value


def send_request(
    server_name: str,
    path: str,
    body: dict[str, Any] | None,
    headers: Mapping[str, str] | None = None,
    *,
    destinations: DestinationMap | None = None,
) -> tuple[int, dict[str, Any]]:
    """Use fixed trusted destinations; no redirect following or environment proxies."""

    if server_name not in SERVICE_ROLES or path not in _PATHS:
        raise ValueError("unrecognized_reference_destination")
    configured = DEFAULT_DESTINATIONS if destinations is None else destinations
    host, port = configured[server_name]
    payload = None if body is None else json.dumps(body, allow_nan=False).encode("utf-8")
    if payload is not None and len(payload) > MAXIMUM_BODY_BYTES:
        raise ValueError("request_body_too_large")
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request(
            "GET" if body is None else "POST",
            path,
            body=payload,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        response = connection.getresponse()
        return response.status, parse_json_object(response.read(MAXIMUM_BODY_BYTES + 1))
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        return 503, {"error": "reference_transport_unavailable"}
    finally:
        connection.close()


class IssuanceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    challenge: str = Field(pattern=r"^[0-9a-f]{64}$")
    calling_attestation: DevelopmentAttestation
    delegated_attestation: DevelopmentAttestation | None = None


class AttestationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    challenge: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: int = Field(ge=0)


class ReferenceApplication:
    def __init__(
        self,
        role: str,
        registration_directory: Path,
        *,
        database_path: Path | None = None,
        destinations: DestinationMap | None = None,
    ) -> None:
        if role not in SERVICE_ROLES:
            raise ValueError("unknown_reference_service")
        self.role = role
        self.directory = registration_directory
        self.public = load_public_registration(registration_directory)
        self.policy = resource_policy(self.public)
        self.private = load_role_private(registration_directory, role)
        self.destinations = destinations
        self.lock = threading.Lock()
        self.challenges: dict[str, int] = {}
        self.handler_count = 0
        self.store = (
            RedemptionStore(database_path or Path("/state/redemption.sqlite3"))
            if role == "resource_server"
            else None
        )

    def _issue(self, document: dict[str, Any]) -> dict[str, Any]:
        request = IssuanceInput.model_validate(document)
        now = int(time.time())
        with self.lock:
            expiry = self.challenges.get(request.challenge)
        if expiry is None or now >= expiry:
            raise AuthorizationError("issuance_challenge_unavailable")
        statements = [request.calling_attestation]
        if request.delegated_attestation is not None:
            statements.append(request.delegated_attestation)
        if any(statement.expires_at > expiry for statement in statements):
            raise AuthorizationError("attestation_exceeds_challenge_validity")
        principal = verify_development_attestation(
            self.public.registrations["calling_principal"],
            request.calling_attestation,
            expected_challenge=request.challenge,
            now=now,
        )
        delegated = (
            verify_development_attestation(
                self.public.registrations["delegated_principal"],
                request.delegated_attestation,
                expected_challenge=request.challenge,
                now=now,
            )
            if request.delegated_attestation is not None
            else None
        )
        with self.lock:
            now = int(time.time())
            remaining = min(statement.expires_at for statement in statements) - now
            if self.challenges.get(request.challenge) != expiry or now >= expiry or remaining <= 0:
                raise AuthorizationError("issuance_challenge_unavailable")
            del self.challenges[request.challenge]
        capability = issue_capability(
            principal,
            load_private_key(self.private["issuer_private_key"]),
            self.policy,
            current_time=now,
            validity_seconds=min(60, remaining),
            delegated_principal=delegated,
        )
        return {"capability": capability.model_dump(mode="json"), "assurance": "development"}

    def _forward(
        self, document: dict[str, Any], headers: Mapping[str, str]
    ) -> tuple[int, dict[str, Any]]:
        request = ResourceRequest.model_validate(document)
        principal = request.invocation.claims.principal_identifier
        credentials = self.private["bearer_credentials"]
        authorization = next(
            (value for name, value in headers.items() if name.casefold() == "authorization"), ""
        )
        if principal not in PRINCIPAL_ROLES or not hmac.compare_digest(
            authorization, "Bearer " + credentials[principal]
        ):
            raise AuthorizationError("proxy_authentication_failed")
        outgoing_headers, outgoing_body = build_forwarding_request(request, headers)
        if any(credential.encode() in outgoing_body for credential in credentials.values()):
            raise AuthorizationError("credential_reflection_rejected")
        return send_request(
            "resource_server",
            "/redemption",
            parse_json_object(outgoing_body),
            outgoing_headers,
            destinations=self.destinations,
        )

    def handle(
        self, method: str, path: str, document: dict[str, Any], headers: Mapping[str, str]
    ) -> tuple[int, dict[str, Any]]:
        if method == "GET" and path == "/health":
            return 200, {"status": "ready", "role": self.role}
        if method == "GET" and path == "/verification" and self.role == "resource_server":
            with self.lock:
                return 200, {"handler_invocations": self.handler_count}
        if method != "POST":
            return 404, {"error": "unknown_reference_route"}
        if self.role == "authorization_server" and path == "/challenge":
            if document:
                raise ValueError("challenge_request_must_be_empty")
            now = int(time.time())
            with self.lock:
                self.challenges = {
                    key: expiry for key, expiry in self.challenges.items() if expiry > now
                }
                if len(self.challenges) >= 1024:
                    raise AuthorizationError("issuance_challenge_capacity_reached")
                challenge = secrets.token_hex(32)
                self.challenges[challenge] = now + 60
            return 200, {"challenge": challenge, "expires_at": now + 60}
        if self.role == "authorization_server" and path == "/issuance":
            return 200, self._issue(document)
        if self.role == "authorization_proxy" and path == "/forwarding":
            return self._forward(document, headers)
        if self.role == "resource_server" and path == "/redemption":
            reject_forwarded_bearer(headers)
            if self.store is None:
                raise RuntimeError("resource_store_not_initialized")
            redemption = redeem_capability(
                ResourceRequest.model_validate(document), self.policy, self.store, headers=headers
            )
            with self.lock:
                self.handler_count += 1
            return 200, {
                "redemption": redemption.model_dump(mode="json"),
                "result": {
                    "record_identifier": OBJECT_IDENTIFIER,
                    "content": "synthetic reference object",
                },
            }
        if self.role == "delegated_principal" and path == "/attestation":
            request = AttestationInput.model_validate(document)
            if not int(time.time()) < request.expires_at <= int(time.time()) + 60:
                raise AuthorizationError("invalid_attestation_validity")
            statement = create_development_attestation(
                load_principal_fixture(self.directory, self.role),
                request.challenge,
                request.expires_at,
            )
            return 200, {"attestation": statement.model_dump(mode="json")}
        if self.role == "delegated_principal" and path == "/redemption":
            capability = CapabilityEnvelope.model_validate(document)
            if capability.attenuation_record is None:
                raise AuthorizationError("attenuation_record_required")
            verify_capability(capability.capability, self.policy, int(time.time()))
            if verify_attenuation_record(capability).principal_identifier != self.role:
                raise AuthorizationError("delegated_principal_mismatch")
            fixture = load_principal_fixture(self.directory, self.role)
            invocation = create_invocation(capability, fixture.holder_private_key)
            return send_request(
                "authorization_proxy",
                "/forwarding",
                invocation.model_dump(mode="json"),
                {"Authorization": "Bearer " + self.private["proxy_bearer_credential"]},
                destinations=self.destinations,
            )
        return 404, {"error": "unknown_reference_route"}


class ReferenceHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    application: ReferenceApplication

    def __init__(
        self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]
    ) -> None:
        self._concurrency = threading.BoundedSemaphore(16)
        super().__init__(server_address, handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._concurrency.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._concurrency.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._concurrency.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Request material and exception details are not part of public evidence.
        pass


class ReferenceRequestHandler(BaseHTTPRequestHandler):
    server: ReferenceHTTPServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._respond(code, {"error": "invalid_http_request"})

    def _respond(self, status: int, response: dict[str, Any]) -> None:
        encoded = json.dumps(response, allow_nan=False).encode("utf-8")
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)
        except OSError:
            pass

    def _handle(self) -> None:
        try:
            names = [name.casefold() for name in self.headers]
            if len(names) != len(set(names)) or "transfer-encoding" in names:
                raise ValueError("unsupported_request_headers")
            document: dict[str, Any] = {}
            if self.command == "POST":
                if self.headers.get_content_type() != "application/json":
                    raise ValueError("json_content_type_required")
                content_length = int(self.headers.get("Content-Length", "-1"))
                if not 0 < content_length <= MAXIMUM_BODY_BYTES:
                    raise ValueError("invalid_content_length")
                payload = self.rfile.read(content_length)
                if len(payload) != content_length:
                    raise ValueError("incomplete_request_body")
                document = parse_json_object(payload)
            status, response = self.server.application.handle(
                self.command, self.path, document, dict(self.headers.items())
            )
        except AuthorizationError as error:
            status, response = 403, {"error": error.code}
        except (ValueError, TypeError, RecursionError):
            status, response = 400, {"error": "invalid_reference_request"}
        except OSError:
            status, response = 408, {"error": "reference_request_timeout"}
        except Exception:
            status, response = 500, {"error": "reference_service_failure"}
        self._respond(status, response)

    def do_POST(self) -> None:
        self._handle()

    def do_GET(self) -> None:
        self._handle()


def create_server(
    role: str,
    *,
    listen_address: str = "127.0.0.1",
    port: int = 8000,
    registration_directory: Path = Path("/registration"),
    database_path: Path | None = None,
    destinations: DestinationMap | None = None,
) -> ReferenceHTTPServer:
    application = ReferenceApplication(
        role, registration_directory, database_path=database_path, destinations=destinations
    )
    server = ReferenceHTTPServer((listen_address, port), ReferenceRequestHandler)
    server.application = application
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=SERVICE_ROLES)
    arguments = parser.parse_args()
    server = create_server(
        arguments.role,
        listen_address=os.environ.get("REFERENCE_LISTEN_ADDRESS", "127.0.0.1"),
        registration_directory=Path(
            os.environ.get("RESOURCE_AUTHORIZATION_REGISTRATION", "/registration")
        ),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
