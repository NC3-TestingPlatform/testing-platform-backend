"""Registers models missing from FastAPI's OpenAPI generation.

FastAPI adds a model to the document's `components.schemas` only when a route
uses it as a request body or response type. A model referenced only from a
handwritten `openapi_extra` schema is missed — its `$ref` dangles and client
generators emit untyped placeholders.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from pydantic.json_schema import models_json_schema

_REF_TEMPLATE = "#/components/schemas/{model}"


def register_component_schemas(app: FastAPI, *models: type[BaseModel]) -> None:
    """Ensures each model, and every model nested inside it, has an entry in `components.schemas`.

    A model FastAPI already emitted keeps its original entry rather than being
    replaced by a subtly different rendering.
    """
    previous_openapi = app.openapi

    def openapi() -> dict:
        schema = previous_openapi()
        components = schema.setdefault("components", {}).setdefault("schemas", {})
        # `validation` mode: every model registered this way describes a request
        # body or an event payload the client parses. Revisit if a registered model
        # ever serializes differently from how it validates.
        _, definitions = models_json_schema(
            [(model, "validation") for model in models],
            ref_template=_REF_TEMPLATE,
        )
        for name, definition in definitions.get("$defs", {}).items():
            components.setdefault(name, definition)
        return schema

    app.openapi = openapi
