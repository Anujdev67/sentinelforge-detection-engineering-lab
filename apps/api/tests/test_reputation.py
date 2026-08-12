"""Unit tests for safe reputation normalization and provider response mapping."""

import asyncio
from typing import Any

import httpx
import pytest

from apps.api.sentinelforge_api.reputation import (
    AbuseIPDBConnector,
    GreyNoiseConnector,
    VirusTotalConnector,
    normalize_observable,
    validate_live_observable,
)
from apps.api.sentinelforge_api.schemas import ObservableType, ReputationVerdict


def _run_lookup(
    connector: VirusTotalConnector | AbuseIPDBConnector | GreyNoiseConnector,
    observable: str,
    observable_type: ObservableType,
) -> Any:
    return asyncio.run(connector.lookup(observable, observable_type))


def test_observable_normalization_and_live_disclosure_guard() -> None:
    assert normalize_observable(" EXAMPLE.COM. ") == (
        "example.com",
        ObservableType.DOMAIN,
    )
    assert normalize_observable("2001:4860:4860::8888") == (
        "2001:4860:4860::8888",
        ObservableType.IP,
    )
    with pytest.raises(ValueError, match="bare IP address"):
        normalize_observable("https://example.com/report")
    with pytest.raises(ValueError, match="never sent"):
        validate_live_observable("203.0.113.10", ObservableType.IP)
    with pytest.raises(ValueError, match="never sent"):
        validate_live_observable("soc.example", ObservableType.DOMAIN)


def test_virustotal_response_mapping_uses_fixed_read_only_report_endpoint() -> None:
    async def scenario() -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            assert request.url == "https://www.virustotal.com/api/v3/domains/example.org"
            assert request.headers["x-apikey"] == "test-key"
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 7,
                                "suspicious": 2,
                                "harmless": 40,
                                "undetected": 10,
                            },
                            "reputation": -60,
                            "categories": {"vendor": "command-and-control"},
                            "tags": ["synthetic-test"],
                            "country": "ZZ",
                            "as_owner": "Fictional Transit",
                        }
                    }
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            connector = VirusTotalConnector(client, "test-key")
            return await connector.lookup("example.org", ObservableType.DOMAIN)

    finding = asyncio.run(scenario())
    assert finding.verdict is ReputationVerdict.MALICIOUS
    assert finding.malicious_count == 7
    assert finding.total_sources == 59
    assert finding.categories == ["command-and-control", "synthetic-test"]
    assert finding.details == {"reputation": -60, "report_found": True}


def test_abuseipdb_and_greynoise_response_mapping() -> None:
    async def abuse_scenario() -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            assert request.url.path == "/api/v2/check"
            assert request.headers["Key"] == "abuse-key"
            assert request.url.params["ipAddress"] == "203.0.113.8"
            return httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 82,
                        "totalReports": 12,
                        "countryCode": "ZZ",
                        "isp": "Fictional ISP",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "isWhitelisted": False,
                    }
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            return await AbuseIPDBConnector(client, "abuse-key").lookup(
                "203.0.113.8", ObservableType.IP
            )

    async def greynoise_scenario() -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            assert request.url.path == "/v3/community/203.0.113.8"
            assert request.headers["key"] == "greynoise-key"
            return httpx.Response(
                200,
                json={
                    "classification": "benign",
                    "noise": True,
                    "riot": True,
                    "name": "Fictional public resolver",
                    "link": "https://viz.greynoise.io/ip/203.0.113.8",
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            return await GreyNoiseConnector(client, "greynoise-key").lookup(
                "203.0.113.8", ObservableType.IP
            )

    abuse = asyncio.run(abuse_scenario())
    assert abuse.verdict is ReputationVerdict.MALICIOUS
    assert abuse.confidence == 82
    assert abuse.malicious_count == 12

    greynoise = asyncio.run(greynoise_scenario())
    assert greynoise.verdict is ReputationVerdict.BENIGN
    assert greynoise.categories == ["internet-noise", "riot"]
    assert greynoise.details["classification"] == "benign"
