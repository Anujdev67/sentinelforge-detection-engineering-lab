"""Repository-wide privacy checks for committed, human-authored content."""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, ip_address
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
TEXT_SUFFIXES = {
    ".css",
    ".env",
    ".html",
    ".json",
    ".kql",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".sigma",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".venv",
    "dist",
    "node_modules",
    "work",
}

# Stored obfuscated so the forbidden customer/employer strings are not themselves committed.
FORBIDDEN_PATTERNS = [
    "".join(("wi", "pro")),
    "".join(("voda", "fone")),
    "".join(("qatar", " energy")),
]
PUBLIC_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _text_files() -> list[Path]:
    return [
        path
        for path in REPOSITORY_ROOT.rglob("*")
        if path.is_file()
        and path.suffix.lower() in TEXT_SUFFIXES
        and not any(part in EXCLUDED_PARTS for part in path.parts)
    ]


def test_forbidden_organization_names_are_absent() -> None:
    findings: list[str] = []
    for path in _text_files():
        text = path.read_text(encoding="utf-8").lower()
        for term in FORBIDDEN_PATTERNS:
            if term in text:
                findings.append(f"{path.relative_to(REPOSITORY_ROOT)}:{term}")
    assert not findings, f"forbidden organization references found: {findings}"


def test_literal_ipv4_addresses_are_documentation_or_private() -> None:
    findings: list[str] = []
    for path in _text_files():
        for candidate in PUBLIC_IPV4.findall(path.read_text(encoding="utf-8")):
            parsed = ip_address(candidate)
            assert isinstance(parsed, IPv4Address)
            documentation = any(
                parsed in network
                for network in (
                    IPv4Network("192.0.2.0/24"),
                    IPv4Network("198.51.100.0/24"),
                    IPv4Network("203.0.113.0/24"),
                )
            )
            if not (
                documentation or parsed.is_private or parsed.is_loopback or parsed.is_unspecified
            ):
                findings.append(f"{path.relative_to(REPOSITORY_ROOT)}:{candidate}")
    assert not findings, f"non-documentation public IPv4 addresses found: {findings}"
