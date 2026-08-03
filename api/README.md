# API contract

`openapi.json` is the generated OpenAPI 3.1 contract for the v4 backend.
It is committed so the frontend and client generators can consume it without a Python toolchain, and so contract changes 
show up as reviewable PR diffs.

Do not edit it by hand.
The source of truth is the FastAPI app; regenerate after any schema or route change:

```bash
make export-openapi
```

Commit the regenerated file together with the code change that caused it.
CI validates the committed spec and fails if it drifts from what the app generates.