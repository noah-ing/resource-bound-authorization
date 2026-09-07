"""Credential rejection and explicit outbound request construction."""

import json
from collections.abc import Mapping

from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.models import ResourceRequest


def reject_forwarded_bearer(headers: Mapping[str, str] | None) -> None:
    """This resource does not accept HTTP authorization credentials of any scheme."""
    if headers is not None and any(
        header_name.casefold() in {"authorization", "proxy-authorization"}
        for header_name in headers
    ):
        raise AuthorizationError("forwarded_bearer_rejected")


def build_forwarding_request(
    request: ResourceRequest, inbound_headers: Mapping[str, str] | None = None
) -> tuple[dict[str, str], bytes]:
    """Construct capability-only transport without copying inbound header fields."""
    outbound_body = request.model_dump_json().encode("utf-8")
    outbound_record: object = json.loads(outbound_body)
    for header_name, header_value in (inbound_headers or {}).items():
        if header_name.casefold() not in {"authorization", "proxy-authorization"}:
            continue
        authentication_fields = header_value.split(maxsplit=1)
        if len(authentication_fields) != 2:
            continue
        inbound_credential = authentication_fields[1]
        if inbound_credential.encode("utf-8") in outbound_body or _contains_credential(
            outbound_record, inbound_credential
        ):
            raise AuthorizationError("forwarded_bearer_reflection_rejected")
    return {"Content-Type": "application/json"}, outbound_body


def _contains_credential(record_value: object, credential: str) -> bool:
    """Inspect the serialized record's decoded strings, including object members."""
    if isinstance(record_value, str):
        return credential in record_value
    if isinstance(record_value, dict):
        return any(
            _contains_credential(member_name, credential)
            or _contains_credential(member_value, credential)
            for member_name, member_value in record_value.items()
        )
    if isinstance(record_value, list):
        return any(_contains_credential(member_value, credential) for member_value in record_value)
    return False
