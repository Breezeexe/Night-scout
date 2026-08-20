from __future__ import annotations

import json

import pytest

from recon.core.events import Event, EventType, ScopeState
from recon.intelligence.vulnerabilities import (
    CveCandidateStatus,
    InMemoryNvdCache,
    NvdClientConfig,
    NvdVulnerabilityIntelligence,
    parse_product_version,
    technology_version_from_event,
)


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def get_json(self, *, base_url, params, headers, timeout_seconds, max_response_bytes):
        del headers, timeout_seconds, max_response_bytes
        self.calls.append((base_url, dict(params)))
        serialized = json.dumps(params).lower()
        assert "api.target.example" not in serialized
        assert "203.0.113.10" not in serialized

        if "cpes" in base_url:
            return {
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "products": [{
                    "cpe": {
                        "deprecated": False,
                        "cpeName": "cpe:2.3:a:nginx:nginx:1.23.4:*:*:*:*:*:*:*",
                        "cpeNameId": "fixture",
                        "titles": [{"lang": "en", "title": "NGINX 1.23.4"}],
                    }
                }],
            }

        return {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-12345",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Fixture vulnerability"}],
                    "metrics": {"cvssMetricV31": [{
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 8.8,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        },
                    }]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                }
            }],
        }


@pytest.mark.asyncio
async def test_nvd_lookup_is_cached_and_never_receives_target_identifier():
    assert parse_product_version("nginx/1.24.0") == ("nginx", "1.24.0")
    assert parse_product_version("https://api.target.example/1.24.0") is None

    event = Event(
        type=EventType.TECHNOLOGY,
        value="nginx:1.24.0",
        source="http:test",
        scope_state=ScopeState.IN_SCOPE,
        confidence=0.85,
        metadata={
            "observed_on": "https://api.target.example/",
            "hostname": "api.target.example",
            "ip": "203.0.113.10",
        },
    )
    observation = technology_version_from_event(event)
    assert observation is not None
    assert "target.example" not in json.dumps(observation.model_dump(mode="json"))

    transport = FakeTransport()
    service = NvdVulnerabilityIntelligence(
        cache=InMemoryNvdCache(),
        transport=transport,
        config=NvdClientConfig(min_request_interval_seconds=0, max_attempts=1, min_cpe_score=0.5),
    )
    first = await service.lookup_event(event)
    second = await service.lookup_event(event)
    assert first is not None and second is not None
    assert first.cves[0].status is CveCandidateStatus.UNVALIDATED_CANDIDATE
    assert first.cves[0].validated_on_target is False
    assert second.nvd_requests == 0
    assert len(transport.calls) == 2
