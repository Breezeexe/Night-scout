"""Event-to-task routing for Night Scout.

The router is intentionally policy-agnostic. Its only responsibility is to
answer a structural question:

    "Given this Event, which logical worker tasks could be useful next?"

Authorization, rate limits, budgets, worker availability, and final execution
priority are handled later by the policy, budget, scheduler, and lifecycle
layers.

Workers or pipeline profiles register RouteRule objects at startup. This keeps
the core router generic and prevents a central hard-coded dependency graph from
growing every time a worker is added or replaced.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from recon.core.events import Event, EventType
from recon.core.queue import Task


class RoutingPredicate(Protocol):
    """Callable used for optional code-level route filtering."""

    def __call__(self, event: Event, context: RoutingContext) -> bool:
        """Return True when the rule should produce a task."""
        ...


@dataclass(frozen=True, slots=True)
class RoutingContext:
    """Context supplied by lifecycle/scheduler when expanding an event.

    The router does not read policy state from this object. It only carries
    routing metadata that should be copied into generated tasks.
    """

    branch_id: str | None = None
    priority_bias: float = 0.0
    disabled_workers: frozenset[str] = field(default_factory=frozenset)
    disabled_rules: frozenset[str] = field(default_factory=frozenset)

    def worker_enabled(self, worker: str) -> bool:
        """Return whether a worker is enabled in this pipeline context."""
        return worker not in self.disabled_workers

    def rule_enabled(self, rule_id: str) -> bool:
        """Return whether a routing rule is enabled in this pipeline context."""
        return rule_id not in self.disabled_rules


@dataclass(frozen=True, slots=True)
class RouteRule:
    """Declarative mapping from one or more EventType values to a worker task."""

    rule_id: str
    accepts: frozenset[EventType]

    worker: str
    action: str

    reason: str | None = None
    base_priority: float = 0.0

    required_tags: frozenset[str] = field(default_factory=frozenset)
    excluded_tags: frozenset[str] = field(default_factory=frozenset)

    predicate: RoutingPredicate | None = None

    def __post_init__(self) -> None:
        """Validate and normalize immutable rule fields."""
        normalized_rule_id = self.rule_id.strip()
        normalized_worker = self.worker.strip()
        normalized_action = self.action.strip()

        if not normalized_rule_id:
            raise ValueError("rule_id must not be blank")
        if not normalized_worker:
            raise ValueError("worker must not be blank")
        if not normalized_action:
            raise ValueError("action must not be blank")
        if not self.accepts:
            raise ValueError("accepts must contain at least one EventType")

        if any(not isinstance(event_type, EventType) for event_type in self.accepts):
            raise TypeError("accepts must contain only EventType values")

        required_tags = _normalize_tags(self.required_tags)
        excluded_tags = _normalize_tags(self.excluded_tags)

        overlap = required_tags & excluded_tags
        if overlap:
            joined = ", ".join(sorted(overlap))
            raise ValueError(
                f"required_tags and excluded_tags overlap: {joined}"
            )

        normalized_reason = None
        if self.reason is not None:
            normalized_reason = self.reason.strip() or None

        object.__setattr__(self, "rule_id", normalized_rule_id)
        object.__setattr__(self, "worker", normalized_worker)
        object.__setattr__(self, "action", normalized_action)
        object.__setattr__(self, "reason", normalized_reason)
        object.__setattr__(self, "required_tags", required_tags)
        object.__setattr__(self, "excluded_tags", excluded_tags)

    def matches(self, event: Event, context: RoutingContext) -> bool:
        """Return whether this rule structurally applies to an event."""
        if event.type not in self.accepts:
            return False

        if not context.rule_enabled(self.rule_id):
            return False

        if not context.worker_enabled(self.worker):
            return False

        event_tags = _normalize_tags(event.tags)

        if not self.required_tags.issubset(event_tags):
            return False

        if self.excluded_tags & event_tags:
            return False

        if self.predicate is not None and not self.predicate(event, context):
            return False

        return True

    def build_task(self, event: Event, context: RoutingContext) -> Task:
        """Create the normalized Task represented by this rule."""
        reason = self.reason or (
            f"{event.type.value} event matched route "
            f"{self.worker}:{self.action}"
        )

        return Task(
            worker=self.worker,
            action=self.action,
            input_event_id=event.event_id,
            input_identity_key=event.identity_key,
            branch_id=context.branch_id,
            route_rule_id=self.rule_id,
            routing_reason=reason,
            priority=self.base_priority + context.priority_bias,
        )


class DuplicateRouteRuleError(ValueError):
    """Raised when two rules attempt to use the same stable rule identifier."""


class Router:
    """Registry and evaluator for event-to-task routing rules.

    Router instances are cheap and contain no persistence. The normal startup
    path is expected to:

        1. construct a Router,
        2. register rules exposed by enabled workers/pipeline profiles,
        3. expand newly stored Events into candidate Tasks,
        4. enqueue those Tasks,
        5. let policy/scheduler decide whether they may actually execute.
    """

    def __init__(self, rules: Iterable[RouteRule] = ()) -> None:
        self._rules: dict[str, RouteRule] = {}
        self._by_event_type: dict[EventType, list[str]] = {
            event_type: [] for event_type in EventType
        }
        self.register_many(rules)

    def register(self, rule: RouteRule) -> None:
        """Register a route rule using a stable unique rule_id."""
        if rule.rule_id in self._rules:
            raise DuplicateRouteRuleError(
                f"route rule already registered: {rule.rule_id}"
            )

        self._rules[rule.rule_id] = rule

        for event_type in rule.accepts:
            self._by_event_type[event_type].append(rule.rule_id)

    def register_many(self, rules: Iterable[RouteRule]) -> None:
        """Register multiple rules.

        Validation is performed before mutating the registry so a duplicate
        inside the incoming batch cannot leave the Router partially updated.
        """
        incoming = list(rules)

        seen: set[str] = set()
        for rule in incoming:
            if rule.rule_id in seen:
                raise DuplicateRouteRuleError(
                    f"duplicate route rule in batch: {rule.rule_id}"
                )
            if rule.rule_id in self._rules:
                raise DuplicateRouteRuleError(
                    f"route rule already registered: {rule.rule_id}"
                )
            seen.add(rule.rule_id)

        for rule in incoming:
            self.register(rule)

    def unregister(self, rule_id: str) -> RouteRule:
        """Remove and return a rule.

        This is mainly useful for tests and future dynamic pipeline profiles.
        """
        normalized = rule_id.strip()
        if not normalized:
            raise ValueError("rule_id must not be blank")

        try:
            rule = self._rules.pop(normalized)
        except KeyError as exc:
            raise KeyError(f"unknown route rule: {normalized}") from exc

        for event_type in rule.accepts:
            self._by_event_type[event_type].remove(rule.rule_id)

        return rule

    def get(self, rule_id: str) -> RouteRule | None:
        """Return a registered rule by identifier."""
        return self._rules.get(rule_id)

    def rules_for(self, event_type: EventType) -> tuple[RouteRule, ...]:
        """Return registered rules that accept the supplied EventType."""
        return tuple(
            self._rules[rule_id]
            for rule_id in self._by_event_type[event_type]
        )

    def matching_rules(
        self,
        event: Event,
        *,
        context: RoutingContext | None = None,
    ) -> tuple[RouteRule, ...]:
        """Return structurally matching rules in deterministic registration order."""
        routing_context = context or RoutingContext()

        return tuple(
            rule
            for rule in self.rules_for(event.type)
            if rule.matches(event, routing_context)
        )

    def expand(
        self,
        event: Event,
        *,
        context: RoutingContext | None = None,
    ) -> list[Task]:
        """Convert an Event into candidate Tasks.

        No scope or policy authorization occurs here. A task produced by this
        method is a candidate for later policy/scheduler evaluation, not
        permission to execute a worker.
        """
        routing_context = context or RoutingContext()

        return [
            rule.build_task(event, routing_context)
            for rule in self.matching_rules(event, context=routing_context)
        ]

    @property
    def rule_count(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules)


def _normalize_tags(tags: Iterable[str]) -> frozenset[str]:
    """Normalize tags used by declarative route constraints."""
    normalized: set[str] = set()

    for tag in tags:
        value = tag.strip().lower()
        if value:
            normalized.add(value)

    return frozenset(normalized)
