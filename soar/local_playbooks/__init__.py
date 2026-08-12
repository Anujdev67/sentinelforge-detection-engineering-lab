"""Deterministic local playbooks that never call external containment APIs."""

from soar.local_playbooks.registry import PLAYBOOKS, PlaybookDefinition

__all__ = ["PLAYBOOKS", "PlaybookDefinition"]
