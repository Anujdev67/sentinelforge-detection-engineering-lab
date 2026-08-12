"""Check that relative Markdown links and images resolve inside the repository."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "#")


def broken_links() -> list[str]:
    """Return source/target descriptions for missing local Markdown targets."""

    failures: list[str] = []
    for source in sorted(ROOT.rglob("*.md")):
        if any(part in {"node_modules", ".venv", ".terraform", "work"} for part in source.parts):
            continue
        for raw_target in LINK_PATTERN.findall(source.read_text(encoding="utf-8")):
            target = raw_target.strip().strip("<>")
            if target.startswith(EXTERNAL_PREFIXES):
                continue
            path_part = target.split("#", maxsplit=1)[0]
            if not path_part:
                continue
            resolved = (source.parent / path_part).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                failures.append(f"{source.relative_to(ROOT)} -> outside repository: {target}")
                continue
            if not resolved.exists():
                failures.append(f"{source.relative_to(ROOT)} -> missing: {target}")
    return failures


def main() -> None:
    failures = broken_links()
    if failures:
        formatted = "\n".join(f"  {failure}" for failure in failures)
        raise SystemExit(f"Broken local Markdown links:\n{formatted}")
    print("Local Markdown link validation passed")


if __name__ == "__main__":
    main()
