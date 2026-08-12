"""Load and validate file-backed detection packs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from telemetry.models import DetectionMetadata

DETECTIONS_ROOT = Path(__file__).parent / "rules"


@dataclass(frozen=True, slots=True)
class DetectionPack:
    """Validated metadata plus authoritative cloud content."""

    path: Path
    metadata: DetectionMetadata
    kql: str
    sigma: dict[str, Any] | None


def load_detection_packs(root: Path = DETECTIONS_ROOT) -> list[DetectionPack]:
    """Load every detection pack in stable rule-ID order."""

    packs: list[DetectionPack] = []
    for metadata_path in sorted(root.glob("*/metadata.yml")):
        raw_metadata = yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
        if not isinstance(raw_metadata, dict):
            raise ValueError(f"metadata must be an object: {metadata_path}")
        metadata = DetectionMetadata.model_validate(raw_metadata)
        pack_path = metadata_path.parent
        kql_path = pack_path / metadata.kql_file
        if not kql_path.is_file():
            raise FileNotFoundError(kql_path)
        kql = kql_path.read_text(encoding="utf-8").strip()
        sigma: dict[str, Any] | None = None
        if metadata.sigma_file:
            sigma_path = pack_path / metadata.sigma_file
            raw_sigma = yaml.safe_load(sigma_path.read_text(encoding="utf-8"))
            if not isinstance(raw_sigma, dict):
                raise ValueError(f"Sigma rule must be an object: {sigma_path}")
            sigma = raw_sigma
        packs.append(DetectionPack(path=pack_path, metadata=metadata, kql=kql, sigma=sigma))
    return sorted(packs, key=lambda pack: pack.metadata.rule_id)


def load_detection_pack(rule_id: str, root: Path = DETECTIONS_ROOT) -> DetectionPack:
    """Return one validated pack or raise a clear lookup error."""

    for pack in load_detection_packs(root):
        if pack.metadata.rule_id == rule_id:
            return pack
    raise KeyError(f"unknown detection rule: {rule_id}")
