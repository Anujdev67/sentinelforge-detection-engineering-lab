"""Create an ignored local environment file with a random database password."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

_PASSWORD_PLACEHOLDER = "change-me-locally"


def create_env(example_path: Path, output_path: Path) -> bool:
    """Create *output_path* once from the template and return whether it was created."""
    if output_path.exists():
        return False

    template = example_path.read_text(encoding="utf-8")
    if template.count(_PASSWORD_PLACEHOLDER) < 2:
        raise ValueError("The environment template is missing its password placeholders.")

    password = secrets.token_hex(24)
    rendered = template.replace(_PASSWORD_PLACEHOLDER, password)
    with output_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        # Windows ACLs remain inherited from the user-owned workspace.
        pass
    return True


def main() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    output_path = repository_root / ".env"
    created = create_env(repository_root / ".env.example", output_path)
    state = "Created" if created else "Kept existing"
    print(f"{state} ignored local configuration: {output_path.name}")


if __name__ == "__main__":
    main()
