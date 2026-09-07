"""Domain-separated RFC 8785 digests for restricted JSON records."""

import hashlib

import rfc8785
from pydantic import BaseModel

from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.models import CapabilityEnvelope, SignedCapability


def canonical_record_bytes(record: BaseModel, domain: str) -> bytes:
    """Encode signed fields with an explicit record-purpose prefix."""
    try:
        document = rfc8785.dumps(record.model_dump(mode="json"))
        return b"resource-bound-authorization:" + domain.encode("ascii") + b"\x00" + document
    except (ValueError, TypeError, UnicodeError) as exception:
        raise AuthorizationError("invalid_canonical_record") from exception


def canonical_argument_digest(arguments: dict[str, str]) -> str:
    """Digest only a bounded string-to-string argument object."""
    if (
        not isinstance(arguments, dict)
        or not 1 <= len(arguments) <= 16
        or any(
            not isinstance(argument_name, str)
            or not 1 <= len(argument_name) <= 128
            or not isinstance(argument_value, str)
            or len(argument_value) > 4096
            for argument_name, argument_value in arguments.items()
        )
    ):
        raise AuthorizationError("invalid_arguments")
    try:
        document = rfc8785.dumps(arguments)
    except (ValueError, TypeError, UnicodeError) as exception:
        raise AuthorizationError("invalid_canonical_arguments") from exception
    return hashlib.sha256(b"resource-bound-authorization:arguments\x00" + document).hexdigest()


def root_capability_digest(capability: SignedCapability) -> str:
    return hashlib.sha256(canonical_record_bytes(capability, "root-capability")).hexdigest()


def capability_digest(capability: CapabilityEnvelope) -> str:
    return hashlib.sha256(canonical_record_bytes(capability, "final-capability")).hexdigest()
