"""Tests the `DomainName` canonicalization applied at the contract boundary."""

import pytest
from pydantic import TypeAdapter, ValidationError

from nc3_testing_platform.core.schemas import DomainName

_parse = TypeAdapter(DomainName).validate_python

CANONICAL = [
    ("example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("Example.Com", "example.com"),
    ("example.com.", "example.com"),
    ("example.com。", "example.com"),
    ("example.com．", "example.com"),
    ("example.com｡", "example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("xn--bcher-kva.de", "xn--bcher-kva.de"),
    ("sub.Example.com.", "sub.example.com"),
]

REJECTED = [
    "example.com..",
    "example..com",
    "。",
    ".",
    "",
    "localhost",
    "example com.nl",
    "a" * 64 + ".com",
    ".".join(["a" * 63] * 4),
]


@pytest.mark.parametrize(("supplied", "expected"), CANONICAL)
def test_canonicalizes(supplied: str, expected: str) -> None:
    """Canonical form is lowercase A-labels with no trailing dot, whichever full stop the client sent."""
    assert _parse(supplied) == expected


@pytest.mark.parametrize("supplied", REJECTED)
def test_rejects(supplied: str) -> None:
    """Empty labels, single-label names, and over-long names are not domains."""
    with pytest.raises(ValidationError):
        _parse(supplied)


@pytest.mark.parametrize("canonical", sorted({expected for _, expected in CANONICAL}))
def test_canonical_form_is_a_fixed_point(canonical: str) -> None:
    """Reparsing a canonical value returns it unchanged, so asset uniqueness holds across repeated writes."""
    assert _parse(canonical) == canonical
