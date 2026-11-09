"""Export the running code's API contract without connecting to a database."""

import argparse
import json
from pathlib import Path

from gateway.main import create_app
from gateway.settings import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("openapi.json"))
    args = parser.parse_args()
    settings = Settings(
        _env_file=None,
        csrf_secret="contract-csrf-" * 4,
        identity_secret="contract-identity-" * 4,
        pseudonym_secret="contract-pseudonym-" * 4,
    )
    document = create_app(settings).openapi()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Exported {len(document['paths'])} API paths to {args.output}.")


if __name__ == "__main__":
    main()
