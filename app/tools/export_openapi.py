"""
Export the generated OpenAPI document to `docs/openapi.json`.
Run: `uv run python -m app.tools.export_openapi`
"""

import json
import sys
from pathlib import Path

from app.main import app

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "api" / "openapi.json"


def main() -> None:
    spec = app.openapi()
    DEST.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n")
    print(
        f"Generated {DEST.relative_to(ROOT)} "
        f"(openapi {spec['openapi']}, {len(spec['paths'])} paths)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
