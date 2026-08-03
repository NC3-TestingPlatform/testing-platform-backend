"""Exports the generated OpenAPI document to `api/openapi.json`.

Run: `uv run export-openapi` or `make export-openapi`.
"""

import json
import sys
from pathlib import Path

from nc3_testing_platform.main import app

ROOT = Path(__file__).resolve().parents[3]
DEST = ROOT / "api" / "openapi.json"


def main() -> None:
    """Entry point for the `export-openapi` project script."""
    spec = app.openapi()
    DEST.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n")
    print(
        f"Generated {DEST.relative_to(ROOT)} "
        f"(openapi {spec['openapi']}, {len(spec['paths'])} paths)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
