"""Safe, read-only threat-intelligence reputation enrichment."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.sentinelforge_api.config import Settings
from apps.api.sentinelforge_api.db_models import IncidentRecord, ReputationLookupRecord
from apps.api.sentinelforge_api.schemas import (
    ObservableType,
    ReputationLookupRequest,
    ReputationLookupResponse,
    ReputationProviderStatus,
    ReputationResult,
    ReputationVerdict,
)

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_LOCAL_DOMAIN_SUFFIXES = (".example", ".invalid", ".localhost", ".local", ".test")
_VERDICT_RANK = {
    ReputationVerdict.ERROR: -1,
    ReputationVerdict.UNKNOWN: 0,
    ReputationVerdict.BENIGN: 1,
    ReputationVerdict.SUSPICIOUS: 2,
    ReputationVerdict.MALICIOUS: 3,
}


class ConnectorError(RuntimeError):
    """A sanitized provider failure safe to return to the analyst."""


@dataclass(slots=True)
class ConnectorFinding:
    verdict: ReputationVerdict
    confidence: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    total_sources: int = 0
    categories: list[str] = field(default_factory=list)
    country: str | None = None
    as_owner: str | None = None
    reference_url: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ReputationConnector:
    name = "base"
    display_name = "Base connector"
    supported_types: frozenset[ObservableType] = frozenset()
    live = False
    privacy_notice = "No external lookup is performed."

    def __init__(self, client: httpx.AsyncClient | None, api_key: str | None = None) -> None:
        self.client = client
        self.api_key = (api_key or "").strip()

    @property
    def configured(self) -> bool:
        return not self.live or bool(self.api_key)

    async def lookup(
        self, observable: str, observable_type: ObservableType
    ) -> ConnectorFinding:
        raise NotImplementedError

    async def _get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        if self.client is None:
            raise ConnectorError("The connector HTTP client is unavailable.")
        try:
            response = await self.client.get(url, headers=headers, params=params)
        except httpx.TimeoutException as exc:
            raise ConnectorError("The provider request timed out.") from exc
        except httpx.RequestError as exc:
            raise ConnectorError("The provider request could not be completed.") from exc
        if response.status_code in {401, 403}:
            raise ConnectorError("The provider rejected its configured API key.")
        if response.status_code == 429:
            raise ConnectorError("The provider rate limit was reached.")
        if response.status_code >= 400 and response.status_code != 404:
            raise ConnectorError(f"The provider returned HTTP {response.status_code}.")
        if response.status_code == 404:
            return response.status_code, {}
        try:
            payload = response.json()
        except ValueError as exc:
            raise ConnectorError("The provider returned an invalid response.") from exc
        if not isinstance(payload, dict):
            raise ConnectorError("The provider returned an unexpected response shape.")
        return response.status_code, payload


class SyntheticConnector(ReputationConnector):
    name = "synthetic"
    display_name = "Deterministic Local Intelligence"
    supported_types = frozenset({ObservableType.IP, ObservableType.DOMAIN})
    privacy_notice = "The observable remains local; results are deterministic simulation data."

    async def lookup(
        self, observable: str, observable_type: ObservableType
    ) -> ConnectorFinding:
        score = int(
            hashlib.sha256(f"{observable_type}:{observable}".encode()).hexdigest()[:4], 16
        )
        bucket = score % 100
        if bucket < 12:
            verdict, confidence = ReputationVerdict.MALICIOUS, 72 + (bucket % 20)
        elif bucket < 36:
            verdict, confidence = ReputationVerdict.SUSPICIOUS, 55 + (bucket % 30)
        elif bucket < 76:
            verdict, confidence = ReputationVerdict.UNKNOWN, 30
        else:
            verdict, confidence = ReputationVerdict.BENIGN, 68 + (bucket % 25)
        return ConnectorFinding(
            verdict=verdict,
            confidence=min(confidence, 100),
            categories=["synthetic-simulation"],
            details={
                "deterministic_score": bucket,
                "source": "local deterministic mock",
                "simulation": True,
            },
        )


class VirusTotalConnector(ReputationConnector):
    name = "virustotal"
    display_name = "VirusTotal API v3"
    supported_types = frozenset({ObservableType.IP, ObservableType.DOMAIN})
    live = True
    privacy_notice = "The observable is shared with VirusTotal under your account and plan terms."

    async def lookup(
        self, observable: str, observable_type: ObservableType
    ) -> ConnectorFinding:
        resource = "ip_addresses" if observable_type is ObservableType.IP else "domains"
        url = f"https://www.virustotal.com/api/v3/{resource}/{quote(observable, safe='')}"
        status, payload = await self._get_json(url, headers={"x-apikey": self.api_key})
        gui_kind = "ip-address" if observable_type is ObservableType.IP else "domain"
        reference = (
            f"https://www.virustotal.com/gui/{gui_kind}/{quote(observable, safe='')}"
        )
        if status == 404:
            return ConnectorFinding(
                verdict=ReputationVerdict.UNKNOWN,
                reference_url=reference,
                details={"report_found": False},
            )
        data = payload.get("data", {})
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attributes.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            stats = {}
        malicious = _safe_int(stats.get("malicious"))
        suspicious = _safe_int(stats.get("suspicious"))
        total = sum(_safe_int(value) for value in stats.values())
        reputation = _safe_int(attributes.get("reputation"))
        verdict = ReputationVerdict.UNKNOWN
        if malicious >= 5 or reputation <= -50:
            verdict = ReputationVerdict.MALICIOUS
        elif malicious > 0 or suspicious > 0 or reputation < 0:
            verdict = ReputationVerdict.SUSPICIOUS
        elif total > 0:
            verdict = ReputationVerdict.BENIGN
        confidence = 0
        if total:
            signal = malicious * 100 + suspicious * 50
            confidence = min(100, max(35, round(signal / total)))
            if verdict is ReputationVerdict.BENIGN:
                harmless = _safe_int(stats.get("harmless"))
                confidence = min(100, max(50, round(harmless * 100 / total)))
        return ConnectorFinding(
            verdict=verdict,
            confidence=confidence,
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_sources=total,
            categories=_vt_categories(attributes),
            country=_optional_text(attributes.get("country"), 8),
            as_owner=_optional_text(attributes.get("as_owner"), 255),
            reference_url=reference,
            details={"reputation": reputation, "report_found": True},
        )


class AbuseIPDBConnector(ReputationConnector):
    name = "abuseipdb"
    display_name = "AbuseIPDB API v2"
    supported_types = frozenset({ObservableType.IP})
    live = True
    privacy_notice = "The IP address is shared with AbuseIPDB under your account and plan terms."

    async def lookup(
        self, observable: str, observable_type: ObservableType
    ) -> ConnectorFinding:
        del observable_type
        _, payload = await self._get_json(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": observable, "maxAgeInDays": "90", "verbose": ""},
        )
        data = payload.get("data", {})
        if not isinstance(data, dict):
            data = {}
        score = min(100, max(0, _safe_int(data.get("abuseConfidenceScore"))))
        reports = max(0, _safe_int(data.get("totalReports")))
        if score >= 75:
            verdict = ReputationVerdict.MALICIOUS
        elif score >= 25 or reports > 0:
            verdict = ReputationVerdict.SUSPICIOUS
        elif data:
            verdict = ReputationVerdict.BENIGN
        else:
            verdict = ReputationVerdict.UNKNOWN
        confidence = score
        if verdict is ReputationVerdict.BENIGN:
            confidence = max(50, 100 - score)
        return ConnectorFinding(
            verdict=verdict,
            confidence=confidence,
            malicious_count=reports,
            total_sources=reports,
            categories=["reported-abuse"] if reports else [],
            country=_optional_text(data.get("countryCode"), 8),
            as_owner=_optional_text(data.get("isp") or data.get("domain"), 255),
            reference_url=f"https://www.abuseipdb.com/check/{quote(observable, safe='')}",
            details={
                "abuse_confidence_score": score,
                "usage_type": _optional_text(data.get("usageType"), 100),
                "is_whitelisted": bool(data.get("isWhitelisted")),
            },
        )


class GreyNoiseConnector(ReputationConnector):
    name = "greynoise"
    display_name = "GreyNoise Community API"
    supported_types = frozenset({ObservableType.IP})
    live = True
    privacy_notice = "The IP address is shared with GreyNoise under your account and plan terms."

    async def lookup(
        self, observable: str, observable_type: ObservableType
    ) -> ConnectorFinding:
        del observable_type
        _, payload = await self._get_json(
            f"https://api.greynoise.io/v3/community/{quote(observable, safe='')}",
            headers={"key": self.api_key, "Accept": "application/json"},
        )
        if not payload:
            return ConnectorFinding(verdict=ReputationVerdict.UNKNOWN)
        classification = str(payload.get("classification", "unknown")).lower()
        noise = bool(payload.get("noise"))
        riot = bool(payload.get("riot"))
        if classification == "malicious":
            verdict, confidence = ReputationVerdict.MALICIOUS, 85
        elif noise and not riot:
            verdict, confidence = ReputationVerdict.SUSPICIOUS, 65
        elif classification == "benign" or riot:
            verdict, confidence = ReputationVerdict.BENIGN, 75
        else:
            verdict, confidence = ReputationVerdict.UNKNOWN, 30
        categories = [
            item
            for item, present in (("internet-noise", noise), ("riot", riot))
            if present
        ]
        return ConnectorFinding(
            verdict=verdict,
            confidence=confidence,
            malicious_count=1 if verdict is ReputationVerdict.MALICIOUS else 0,
            suspicious_count=1 if verdict is ReputationVerdict.SUSPICIOUS else 0,
            total_sources=1,
            categories=categories,
            reference_url=_optional_text(payload.get("link"), 500),
            details={
                "classification": classification,
                "name": _optional_text(payload.get("name"), 120),
                "noise": noise,
                "riot": riot,
            },
        )


def normalize_observable(
    value: str, declared_type: ObservableType | None = None
) -> tuple[str, ObservableType]:
    """Normalize an IP/domain and reject URLs, paths, credentials, and malformed values."""
    candidate = value.strip().lower().rstrip(".")
    forbidden = ("://", "/", "\\", "@", " ")
    if not candidate or any(token in candidate for token in forbidden):
        raise ValueError("Enter a bare IP address or domain, not a URL, path, or credential.")
    try:
        normalized_ip = ipaddress.ip_address(candidate).compressed
    except ValueError:
        if declared_type is ObservableType.IP:
            raise ValueError("The observable is not a valid IP address.") from None
    else:
        if declared_type is ObservableType.DOMAIN:
            raise ValueError("The observable is an IP address, not a domain.")
        return normalized_ip, ObservableType.IP

    try:
        domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The observable is not a valid domain.") from exc
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or not all(_DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("The observable is not a valid fully qualified domain.")
    return domain, ObservableType.DOMAIN


def validate_live_observable(observable: str, observable_type: ObservableType) -> None:
    """Prevent disclosure of local, reserved, and documentation-only observables."""
    if observable_type is ObservableType.IP:
        address = ipaddress.ip_address(observable)
        if not address.is_global:
            raise ValueError(
                "Reserved, private, local, and documentation IPs are never sent "
                "to live providers."
            )
        return
    if observable == "localhost" or observable.endswith(_LOCAL_DOMAIN_SUFFIXES):
        raise ValueError("Local and documentation domains are never sent to live providers.")


def provider_statuses(settings: Settings) -> list[ReputationProviderStatus]:
    statuses: list[ReputationProviderStatus] = []
    for connector in connector_registry(settings, None).values():
        enabled = connector.configured and (
            not connector.live or settings.live_reputation_enabled
        )
        if enabled:
            status = "ready"
        elif connector.live and not settings.live_reputation_enabled:
            status = "disabled"
        else:
            status = "not_configured"
        statuses.append(
            ReputationProviderStatus(
                provider=connector.name,
                display_name=connector.display_name,
                supported_types=sorted(connector.supported_types, key=str),
                configured=connector.configured,
                live=connector.live,
                enabled=enabled,
                status=status,
                privacy_notice=connector.privacy_notice,
            )
        )
    return statuses


def connector_registry(
    settings: Settings, client: httpx.AsyncClient | None
) -> dict[str, ReputationConnector]:
    connectors: list[ReputationConnector] = [
        SyntheticConnector(client),
        VirusTotalConnector(client, _secret_value(settings.virustotal_api_key)),
        AbuseIPDBConnector(client, _secret_value(settings.abuseipdb_api_key)),
        GreyNoiseConnector(client, _secret_value(settings.greynoise_api_key)),
    ]
    return {connector.name: connector for connector in connectors}


async def lookup_reputation(
    session: Session,
    payload: ReputationLookupRequest,
    settings: Settings,
    client: httpx.AsyncClient,
) -> ReputationLookupResponse:
    observable, observable_type = normalize_observable(
        payload.observable, payload.observable_type
    )
    if payload.incident_id is not None and session.get(
        IncidentRecord, payload.incident_id
    ) is None:
        raise LookupError("Incident not found.")
    connectors = connector_registry(settings, client)
    selected = _selected_connectors(payload, settings, connectors, observable_type)
    results: list[ReputationResult] = []
    for connector in selected:
        if connector.live:
            validate_live_observable(observable, observable_type)
        if not payload.force_refresh:
            cached = _cached_result(
                session, observable, observable_type, connector.name
            )
            if cached is not None:
                results.append(cached)
                continue
        results.append(
            await _execute_and_persist(
                session,
                connector,
                observable,
                observable_type,
                payload,
                settings,
            )
        )
    session.commit()
    usable = [
        result for result in results if result.verdict is not ReputationVerdict.ERROR
    ]
    overall = (
        max(usable, key=lambda item: _VERDICT_RANK[item.verdict]).verdict
        if usable
        else ReputationVerdict.ERROR
    )
    risk = max((_risk_score(result) for result in results), default=0)
    return ReputationLookupResponse(
        observable=observable,
        observable_type=observable_type,
        overall_verdict=overall,
        risk_score=risk,
        results=results,
        live_connectors_used=any(
            result.live_lookup and not result.cache_hit for result in results
        ),
        analyst_notice=(
            "Reputation is investigation context, not proof. Validate against internal "
            "telemetry; no containment action was performed."
        ),
    )


def reputation_history(
    session: Session,
    *,
    observable: str | None = None,
    incident_id: str | None = None,
    limit: int = 100,
) -> list[ReputationResult]:
    statement = select(ReputationLookupRecord)
    if observable:
        normalized, _ = normalize_observable(observable)
        statement = statement.where(
            ReputationLookupRecord.observable_value == normalized
        )
    if incident_id:
        statement = statement.where(ReputationLookupRecord.incident_id == incident_id)
    rows = session.scalars(
        statement.order_by(ReputationLookupRecord.created_at.desc()).limit(limit)
    )
    return [_record_to_result(row, cache_hit=False) for row in rows]


def _selected_connectors(
    payload: ReputationLookupRequest,
    settings: Settings,
    registry: dict[str, ReputationConnector],
    observable_type: ObservableType,
) -> list[ReputationConnector]:
    names = [name.strip().lower() for name in payload.providers if name.strip()]
    if len(names) != len(set(names)):
        raise ValueError("Provider names must be unique.")
    if not names:
        names = [
            connector.name
            for connector in registry.values()
            if connector.live
            and settings.live_reputation_enabled
            and connector.configured
            and observable_type in connector.supported_types
        ] or ["synthetic"]
    selected: list[ReputationConnector] = []
    for name in names:
        connector = registry.get(name)
        if connector is None:
            raise ValueError(f"Unknown reputation provider: {name}.")
        if observable_type not in connector.supported_types:
            raise ValueError(
                f"{connector.display_name} does not support {observable_type.value} lookups."
            )
        if connector.live and not settings.live_reputation_enabled:
            raise ValueError("Live reputation connectors are disabled by configuration.")
        if not connector.configured:
            raise ValueError(f"{connector.display_name} is not configured.")
        selected.append(connector)
    return selected


def _cached_result(
    session: Session,
    observable: str,
    observable_type: ObservableType,
    provider: str,
) -> ReputationResult | None:
    now = datetime.now(UTC)
    statement = (
        select(ReputationLookupRecord)
        .where(
            ReputationLookupRecord.observable_value == observable,
            ReputationLookupRecord.observable_type == observable_type.value,
            ReputationLookupRecord.provider == provider,
            ReputationLookupRecord.expires_at > now,
            ReputationLookupRecord.error.is_(None),
        )
        .order_by(ReputationLookupRecord.created_at.desc())
        .limit(1)
    )
    record = session.scalar(statement)
    return _record_to_result(record, cache_hit=True) if record else None


async def _execute_and_persist(
    session: Session,
    connector: ReputationConnector,
    observable: str,
    observable_type: ObservableType,
    payload: ReputationLookupRequest,
    settings: Settings,
) -> ReputationResult:
    now = datetime.now(UTC)
    error: str | None = None
    try:
        finding = await connector.lookup(observable, observable_type)
    except ConnectorError as exc:
        error = str(exc)
        finding = ConnectorFinding(verdict=ReputationVerdict.ERROR)
    record = ReputationLookupRecord(
        lookup_id=f"rep-{uuid4().hex[:14]}",
        incident_id=payload.incident_id,
        observable_type=observable_type.value,
        observable_value=observable,
        provider=connector.name,
        verdict=finding.verdict.value,
        confidence=finding.confidence,
        malicious_count=finding.malicious_count,
        suspicious_count=finding.suspicious_count,
        total_sources=finding.total_sources,
        categories=finding.categories,
        country=finding.country,
        as_owner=finding.as_owner,
        reference_url=finding.reference_url,
        live_lookup=connector.live,
        requested_by=payload.requested_by,
        created_at=now,
        expires_at=now + timedelta(minutes=settings.reputation_cache_ttl_minutes),
        error=error,
        details=finding.details,
    )
    session.add(record)
    session.flush()
    return _record_to_result(record, cache_hit=False)


def _record_to_result(
    record: ReputationLookupRecord, *, cache_hit: bool
) -> ReputationResult:
    return ReputationResult(
        lookup_id=record.lookup_id,
        incident_id=record.incident_id,
        observable=record.observable_value,
        observable_type=ObservableType(record.observable_type),
        provider=record.provider,
        verdict=ReputationVerdict(record.verdict),
        confidence=record.confidence,
        malicious_count=record.malicious_count,
        suspicious_count=record.suspicious_count,
        total_sources=record.total_sources,
        categories=record.categories,
        country=record.country,
        as_owner=record.as_owner,
        reference_url=record.reference_url,
        live_lookup=record.live_lookup,
        cache_hit=cache_hit,
        requested_by=record.requested_by,
        queried_at=_aware(record.created_at),
        expires_at=_aware(record.expires_at),
        error=record.error,
        details=record.details,
    )


def _risk_score(result: ReputationResult) -> int:
    base = {
        ReputationVerdict.ERROR: 0,
        ReputationVerdict.UNKNOWN: 15,
        ReputationVerdict.BENIGN: 5,
        ReputationVerdict.SUSPICIOUS: 55,
        ReputationVerdict.MALICIOUS: 85,
    }[result.verdict]
    if result.verdict in {
        ReputationVerdict.SUSPICIOUS,
        ReputationVerdict.MALICIOUS,
    }:
        return min(100, base + round(result.confidence * 0.15))
    return base


def _vt_categories(attributes: dict[str, Any]) -> list[str]:
    values: list[str] = []
    categories = attributes.get("categories", {})
    if isinstance(categories, dict):
        values.extend(str(item) for item in categories.values())
    tags = attributes.get("tags", [])
    if isinstance(tags, list):
        values.extend(str(item) for item in tags)
    return sorted({item[:100] for item in values if item})[:20]


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _optional_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _secret_value(secret: Any) -> str | None:
    if secret is None:
        return None
    value = secret.get_secret_value().strip()
    return value or None


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value
