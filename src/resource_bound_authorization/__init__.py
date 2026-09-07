"""A narrow resource-bound authorization reference implementation."""

from resource_bound_authorization.attenuation import append_attenuation_record
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.issuance import issue_capability
from resource_bound_authorization.redemption import (
    RedemptionStore,
    create_invocation,
    redeem_capability,
)

__all__ = [
    "AuthorizationError",
    "RedemptionStore",
    "append_attenuation_record",
    "create_invocation",
    "issue_capability",
    "redeem_capability",
]
