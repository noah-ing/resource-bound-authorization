"""Explicit authorization rejection without permissive fallback."""


class AuthorizationError(ValueError):
    """A request failed a required authorization condition."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)
