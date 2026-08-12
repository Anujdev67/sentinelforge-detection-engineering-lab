"""Documentation integrity gates."""

from scripts.check_links import broken_links


def test_local_markdown_links_resolve() -> None:
    assert broken_links() == []
