from __future__ import annotations

import pytest

from recon.core.events import ScopeState
from recon.policy.scope import ScopeAssetKind, ScopeEngine, ScopeRule, ScopeSubject
from recon.policy.seeds import (
    DomainSeedMode,
    SeedPlanningError,
    effective_scope_rules,
    plan_domain_seeds,
)


def _rule(rule_id: str, pattern: str, state: ScopeState, priority: int = 100) -> ScopeRule:
    return ScopeRule(
        rule_id=rule_id,
        kind=ScopeAssetKind.DOMAIN,
        pattern=pattern,
        state=state,
        priority=priority,
    )


def test_wildcard_scope_derives_passive_apex_anchor_without_authorizing_apex_active() -> None:
    rules = (_rule("wild", "*.samokat.ru", ScopeState.IN_SCOPE),)
    plan = plan_domain_seeds(rules)
    assert len(plan.seeds) == 1
    seed = plan.seeds[0]
    assert seed.domain == "samokat.ru"
    assert seed.scope_state is ScopeState.PASSIVE_ONLY
    assert seed.mode is DomainSeedMode.WILDCARD_ANCHOR

    engine = ScopeEngine(list(effective_scope_rules(rules)))
    apex = engine.evaluate(ScopeSubject(kind=ScopeAssetKind.DOMAIN, value="samokat.ru"))
    child = engine.evaluate(ScopeSubject(kind=ScopeAssetKind.DOMAIN, value="api.samokat.ru"))
    assert apex.state is ScopeState.PASSIVE_ONLY
    assert child.state is ScopeState.IN_SCOPE


def test_explicit_apex_exclusion_is_never_weakened_by_wildcard_anchor() -> None:
    rules = (
        _rule("wild", "*.example.com", ScopeState.IN_SCOPE, 100),
        _rule("apex-block", "example.com", ScopeState.OUT_OF_SCOPE, 300),
    )
    plan = plan_domain_seeds(rules)
    assert plan.seeds == ()
    assert any("OUT_OF_SCOPE" in warning for warning in plan.warnings)

    with pytest.raises(SeedPlanningError):
        plan_domain_seeds(rules, requested_domains=("example.com",))


def test_scope_auto_plan_contains_many_exact_and_wildcard_domains() -> None:
    rules = (
        _rule("a", "api.example.com", ScopeState.IN_SCOPE),
        _rule("b", "portal.example.net", ScopeState.IN_SCOPE),
        _rule("c", "*.example.org", ScopeState.IN_SCOPE),
    )
    plan = plan_domain_seeds(rules)
    assert [seed.domain for seed in plan.seeds] == [
        "api.example.com",
        "example.org",
        "portal.example.net",
    ]
    states = {seed.domain: seed.scope_state for seed in plan.seeds}
    assert states["api.example.com"] is ScopeState.IN_SCOPE
    assert states["portal.example.net"] is ScopeState.IN_SCOPE
    assert states["example.org"] is ScopeState.PASSIVE_ONLY


def test_explicit_requested_seed_must_be_authorized() -> None:
    rules = (_rule("a", "api.example.com", ScopeState.IN_SCOPE),)
    with pytest.raises(SeedPlanningError):
        plan_domain_seeds(rules, requested_domains=("other.example.com",))
