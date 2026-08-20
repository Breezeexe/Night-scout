"""Scope-aware domain seed planning for Night Scout.

Scope and discovery seeds are deliberately separate concepts:

* scope rules define the authorization boundary;
* seeds define where recursive discovery starts.

A wildcard rule such as ``*.example.com`` does not authorize the apex
``example.com``.  Nevertheless, passive tools such as subfinder need the apex
as a discovery anchor.  For that case Night Scout derives an *ephemeral*
PASSIVE_ONLY anchor rule for the apex.  The derived rule is never persisted and
never permits active probing of the apex; discovered concrete subdomains are
classified independently against the original wildcard rule.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Sequence

from pydantic import BaseModel, ConfigDict

from recon.core.events import ScopeState
from recon.policy.scope import ScopeAssetKind, ScopeEngine, ScopeRule, ScopeSubject


class SeedPlanningError(ValueError):
    """Raised when requested seeds are not authorized by the configured scope."""


class DomainSeedMode(StrEnum):
    EXACT = "EXACT"
    WILDCARD_ANCHOR = "WILDCARD_ANCHOR"
    EXPLICIT = "EXPLICIT"


class DomainSeedSpec(BaseModel):
    """One normalized root-domain discovery seed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain: str
    scope_state: ScopeState
    mode: DomainSeedMode
    matched_rule_id: str | None = None
    source_rule_ids: tuple[str, ...] = ()


class DomainSeedPlan(BaseModel):
    """Explainable set of domain seeds derived from one scope document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seeds: tuple[DomainSeedSpec, ...]
    warnings: tuple[str, ...] = ()


def derived_wildcard_anchor_rules(rules: Sequence[ScopeRule]) -> tuple[ScopeRule, ...]:
    """Return ephemeral PASSIVE_ONLY apex anchors for IN_SCOPE ``*.domain`` rules.

    Anchors are created only when the apex has no explicit classification in the
    original rule set.  Thus an explicit IN_SCOPE/OUT_OF_SCOPE/PASSIVE_ONLY/
    AMBIGUOUS apex rule always wins and is never weakened or overridden.
    """

    original = tuple(rules)
    original_engine = ScopeEngine(list(original))
    derived: list[ScopeRule] = []

    for rule in original:
        if (
            rule.kind is not ScopeAssetKind.DOMAIN
            or rule.state is not ScopeState.IN_SCOPE
            or not rule.pattern.startswith("*.")
            or any(ch in rule.pattern[2:] for ch in "*?")
        ):
            continue

        apex = rule.pattern[2:]
        decision = original_engine.evaluate(
            ScopeSubject(kind=ScopeAssetKind.DOMAIN, value=apex)
        )
        if decision.state is not ScopeState.UNKNOWN:
            continue

        digest = hashlib.sha256(rule.rule_id.encode("utf-8")).hexdigest()[:12]
        derived.append(
            ScopeRule(
                rule_id=f"seed-anchor-{digest}",
                kind=ScopeAssetKind.DOMAIN,
                pattern=apex,
                state=ScopeState.PASSIVE_ONLY,
                priority=rule.priority,
                tier=rule.tier,
                reason=(
                    "Ephemeral passive discovery anchor derived from explicit "
                    f"wildcard scope rule {rule.rule_id}; active probing of the apex "
                    "is not authorized by this anchor"
                ),
            )
        )

    return tuple(derived)


def effective_scope_rules(rules: Sequence[ScopeRule]) -> tuple[ScopeRule, ...]:
    """Return original scope plus non-persistent wildcard discovery anchors."""

    original = tuple(rules)
    return (*original, *derived_wildcard_anchor_rules(original))


def plan_domain_seeds(
    rules: Sequence[ScopeRule],
    *,
    requested_domains: Sequence[str] = (),
) -> DomainSeedPlan:
    """Plan authorized domain seeds from explicit requests or the whole scope.

    When ``requested_domains`` is empty, every effective IN_SCOPE DOMAIN rule is
    used as a starting point. Exact rules seed themselves. Leading ``*.`` rules
    seed their apex through the ephemeral PASSIVE_ONLY anchor described above.

    Only domain-oriented scope entries become automatic seeds. URL, IP/CIDR and
    mobile-app rules remain valid authorization rules but need their dedicated
    worker/seed entry points rather than being silently coerced into DNS roots.
    """

    original = tuple(rules)
    anchors = derived_wildcard_anchor_rules(original)
    effective = (*original, *anchors)
    engine = ScopeEngine(list(effective))
    anchor_ids = {rule.rule_id for rule in anchors}

    if requested_domains:
        seeds: list[DomainSeedSpec] = []
        for raw in requested_domains:
            subject = ScopeSubject(kind=ScopeAssetKind.DOMAIN, value=raw)
            decision = engine.evaluate(subject)
            if decision.state not in {ScopeState.IN_SCOPE, ScopeState.PASSIVE_ONLY}:
                raise SeedPlanningError(
                    f"requested seed {subject.value!r} is {decision.state.value}; "
                    "it must be explicitly IN_SCOPE or PASSIVE_ONLY"
                )
            mode = (
                DomainSeedMode.WILDCARD_ANCHOR
                if decision.matched_rule_id in anchor_ids
                else DomainSeedMode.EXPLICIT
            )
            seeds.append(
                DomainSeedSpec(
                    domain=subject.value,
                    scope_state=decision.state,
                    mode=mode,
                    matched_rule_id=decision.matched_rule_id,
                    source_rule_ids=decision.matched_rule_ids,
                )
            )
        return DomainSeedPlan(seeds=_dedupe_seeds(seeds))

    seeds: list[DomainSeedSpec] = []
    warnings: list[str] = []
    for rule in original:
        if rule.kind is not ScopeAssetKind.DOMAIN or rule.state is not ScopeState.IN_SCOPE:
            continue

        if rule.pattern.startswith("*.") and not any(ch in rule.pattern[2:] for ch in "*?"):
            domain = rule.pattern[2:]
            expected_mode = DomainSeedMode.WILDCARD_ANCHOR
        elif "*" not in rule.pattern and "?" not in rule.pattern:
            domain = rule.pattern
            expected_mode = DomainSeedMode.EXACT
        else:
            warnings.append(
                f"scope rule {rule.rule_id} uses unsupported DOMAIN glob {rule.pattern!r}; "
                "it remains an authorization rule but was not auto-seeded"
            )
            continue

        decision = engine.evaluate(
            ScopeSubject(kind=ScopeAssetKind.DOMAIN, value=domain)
        )
        if decision.state not in {ScopeState.IN_SCOPE, ScopeState.PASSIVE_ONLY}:
            warnings.append(
                f"scope rule {rule.rule_id} did not produce an executable seed for {domain}: "
                f"effective state is {decision.state.value}"
            )
            continue

        mode = (
            DomainSeedMode.WILDCARD_ANCHOR
            if decision.matched_rule_id in anchor_ids
            else expected_mode
        )
        seeds.append(
            DomainSeedSpec(
                domain=domain,
                scope_state=decision.state,
                mode=mode,
                matched_rule_id=decision.matched_rule_id,
                source_rule_ids=tuple(dict.fromkeys((rule.rule_id, *decision.matched_rule_ids))),
            )
        )

    return DomainSeedPlan(
        seeds=_dedupe_seeds(seeds),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _dedupe_seeds(seeds: Sequence[DomainSeedSpec]) -> tuple[DomainSeedSpec, ...]:
    """Deduplicate domains while preferring an active exact classification."""

    by_domain: dict[str, DomainSeedSpec] = {}
    for seed in seeds:
        current = by_domain.get(seed.domain)
        if current is None:
            by_domain[seed.domain] = seed
            continue

        merged_rules = tuple(dict.fromkeys((*current.source_rule_ids, *seed.source_rule_ids)))
        if current.scope_state is ScopeState.IN_SCOPE:
            by_domain[seed.domain] = current.model_copy(update={"source_rule_ids": merged_rules})
        elif seed.scope_state is ScopeState.IN_SCOPE:
            by_domain[seed.domain] = seed.model_copy(update={"source_rule_ids": merged_rules})
        else:
            by_domain[seed.domain] = current.model_copy(update={"source_rule_ids": merged_rules})

    return tuple(by_domain[key] for key in sorted(by_domain))
