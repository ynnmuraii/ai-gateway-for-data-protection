"""Run the real PostgreSQL suite; never silently skip database acceptance tests."""

import os
from pathlib import Path

import pytest
from dotenv import dotenv_values


def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    local = root / ".runtime" / "test.env"
    if local.exists() and not os.environ.get("GATEWAY_TEST_DATABASE_URL"):
        os.environ.update({key: value for key, value in dotenv_values(local).items() if value is not None})
    if not os.environ.get("GATEWAY_TEST_DATABASE_URL"):
        raise SystemExit(
            "Set GATEWAY_TEST_DATABASE_URL to a dedicated PostgreSQL test database (role creation required)."
        )
    return pytest.main(["backend/tests", "-q"])


if __name__ == "__main__":
    # Windows spawn imports this module again for each detector process.
    raise SystemExit(main())
