from __future__ import annotations

import pytest

from recon.core.events import ScopeState
from recon.core.queue import Task
from recon.policy.restrictions import (
    ActionCapability,
    RestrictionEngine,
    StaticActionDescriptorProvider,
    default_recon_descriptor_rules,
)
from recon.policy.scope import ScopeAssetKind, ScopeEngine, ScopeRule, ScopeSubject


def test_scope_wildcard_does_not_include_apex_and_exclusion_wins():
    engine = ScopeEngine(
        [
            ScopeRule(
                rule_id="wild",
                kind=ScopeAssetKind.DOMAIN,
                pattern="*.example.com",
                state=ScopeState.IN_SCOPE,
                priority=100,
            ),
            ScopeRule(
                rule_id="blocked",
                kind=ScopeAssetKind.DOMAIN,
                pattern="payments.example.com",
                state=ScopeState.OUT_OF_SCOPE,
                priority=300,
            ),
        ]
    )

    assert engine.evaluate(
        ScopeSubject(kind=ScopeAssetKind.DOMAIN, value="api.example.com")
    ).state is ScopeState.IN_SCOPE
    assert engine.evaluate(
        ScopeSubject(kind=ScopeAssetKind.DOMAIN, value="example.com")
    ).state is ScopeState.UNKNOWN
    assert engine.evaluate(
        ScopeSubject(kind=ScopeAssetKind.DOMAIN, value="payments.example.com")
    ).state is ScopeState.OUT_OF_SCOPE


def test_url_path_exclusion_overrides_broad_api_rule():
    engine = ScopeEngine(
        [
            ScopeRule(
                rule_id="api",
                kind=ScopeAssetKind.URL,
                pattern="https://api.example.com/v1/*",
                state=ScopeState.IN_SCOPE,
                priority=100,
            ),
            ScopeRule(
                rule_id="billing",
                kind=ScopeAssetKind.URL,
                pattern="https://api.example.com/v1/billing/*",
                state=ScopeState.OUT_OF_SCOPE,
                priority=300,
            ),
        ]
    )

    assert engine.evaluate(
        ScopeSubject(kind=ScopeAssetKind.URL, value="https://api.example.com/v1/orders")
    ).state is ScopeState.IN_SCOPE
    assert engine.evaluate(
        ScopeSubject(kind=ScopeAssetKind.URL, value="https://api.example.com/v1/billing/card")
    ).state is ScopeState.OUT_OF_SCOPE


@pytest.mark.asyncio
async def test_permutations_descriptor_is_local_read_only():
    provider = StaticActionDescriptorProvider(default_recon_descriptor_rules())
    task = Task(worker="permutations", action="generate_targeted", input_event_id="evt_x")
    descriptor = await provider.descriptor_for(task)
    assert descriptor is not None
    assert ActionCapability.READ_ONLY in descriptor.capabilities
    assert ActionCapability.LOCAL_STATIC_ANALYSIS in descriptor.capabilities
    decision = RestrictionEngine().evaluate(task=task, descriptor=descriptor)
    assert decision.outcome.value == "ALLOW"
