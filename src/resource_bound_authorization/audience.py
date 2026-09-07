"""Exact resource audience verification."""

import hmac

from resource_bound_authorization.errors import AuthorizationError


def verify_audience(audience: str, expected_audience: str) -> None:
    if not hmac.compare_digest(audience.encode("utf-8"), expected_audience.encode("utf-8")):
        raise AuthorizationError("audience_mismatch")
