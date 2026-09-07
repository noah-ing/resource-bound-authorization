"""Inspect the installable archive boundary without distributing fixture credentials."""

from pathlib import Path
from zipfile import ZipFile


def verify_distribution() -> None:
    distributions = list(Path("dist").glob("*.whl"))
    if len(distributions) != 1:
        raise RuntimeError("one_wheel_distribution_required")
    with ZipFile(distributions[0]) as distribution:
        members = distribution.namelist()
    if not any(member.endswith("resource_bound_authorization/issuance.py") for member in members):
        raise RuntimeError("library_missing_from_distribution")
    for member in members:
        if member.startswith(("examples/", "tests/", "fixtures/", "registration/")):
            raise RuntimeError("nonlibrary_content_in_wheel")
        if member.endswith((".sqlite", ".sqlite3", ".pem", ".key", "private.json")):
            raise RuntimeError("generated_material_in_distribution")
    print("Installable wheel contains the library and distribution metadata only.")


if __name__ == "__main__":
    verify_distribution()
