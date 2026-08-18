"""Action restrictions for Night Scout.

Scope answers:
    "WHERE may Night Scout operate?"

Restrictions answer:
    "WHAT may Night Scout do there?"

This module is intentionally monotonic: it can reduce permission, but it never
grants permission that another layer denied.

Two restriction layers are evaluated:

1. Night Scout baseline invariants
   Non-overridable recon-only guardrails. These prevent a future worker or
   configuration mistake from turning the project into an exploitation,
   credential-use, destructive, brute-force, social-engineering, or
   resource-exhaustion framework.

2. Program-specific RestrictionRule objects
   Additional BLOCK or REVIEW rules derived from a bug-bounty program policy.

Unknown worker/action descriptors fail closed into HUMAN REVIEW.

The normal lifecycle ordering is expected to be:

    ScopeGate
        -> RestrictionsGate
        -> budget/rate/runtime controls
        -> WorkerExecutor
"""

from __future__ import annotations

from enum import IntEnum, StrEnum
from fnmatch import fnmatchcase
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.lifecycle import GateDecision, GateOutcome
from recon.core.queue import Task
from recon.core.scheduler import ScheduleDecision


class ActionClass(StrEnum):
    """High-level classes of worker behavior."""

    PASSIVE_DISCOVERY = "PASSIVE_DISCOVERY"
    DNS_QUERY = "DNS_QUERY"
    HTTP_PROBE = "HTTP_PROBE"
    TLS_INSPECTION = "TLS_INSPECTION"
    ARCHIVE_LOOKUP = "ARCHIVE_LOOKUP"
    CRAWL = "CRAWL"
    JAVASCRIPT_ANALYSIS = "JAVASCRIPT_ANALYSIS"
    CONTENT_DISCOVERY = "CONTENT_DISCOVERY"
    PARAMETER_DISCOVERY = "PARAMETER_DISCOVERY"
    VHOST_DISCOVERY = "VHOST_DISCOVERY"
    MOBILE_STATIC_ANALYSIS = "MOBILE_STATIC_ANALYSIS"
    FINGERPRINTING = "FINGERPRINTING"

    # Classes below are outside Night Scout's recon-only execution model.
    AUTHENTICATED_ACCESS = "AUTHENTICATED_ACCESS"
    CREDENTIAL_USE = "CREDENTIAL_USE"
    BRUTE_FORCE = "BRUTE_FORCE"
    DESTRUCTIVE_ACTION = "DESTRUCTIVE_ACTION"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    EXPLOITATION = "EXPLOITATION"


class ActionCapability(StrEnum):
    """Fine-grained properties used by baseline and program rules."""

    PASSIVE_ONLY = "PASSIVE_ONLY"
    ACTIVE_NETWORK = "ACTIVE_NETWORK"

    READ_ONLY = "READ_ONLY"
    STATE_CHANGE = "STATE_CHANGE"

    AUTHENTICATED_SESSION = "AUTHENTICATED_SESSION"
    USES_CREDENTIALS = "USES_CREDENTIALS"
    ACCESSES_OTHER_USERS_DATA = "ACCESSES_OTHER_USERS_DATA"

    PASSWORD_GUESSING = "PASSWORD_GUESSING"
    HIGH_VOLUME_GUESSING = "HIGH_VOLUME_GUESSING"

    FILE_UPLOAD = "FILE_UPLOAD"
    ACCOUNT_MODIFICATION = "ACCOUNT_MODIFICATION"
    TRANSACTIONAL_ACTION = "TRANSACTIONAL_ACTION"

    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    AVAILABILITY_IMPACT = "AVAILABILITY_IMPACT"

    SOCIAL_INTERACTION = "SOCIAL_INTERACTION"
    EXPLOIT_EXECUTION = "EXPLOIT_EXECUTION"

    # Useful for program-specific restrictions without being prohibited by the
    # Night Scout baseline on its own.
    DIRECTORY_ENUMERATION = "DIRECTORY_ENUMERATION"
    PARAMETER_ENUMERATION = "PARAMETER_ENUMERATION"
    HOST_HEADER_VARIATION = "HOST_HEADER_VARIATION"
    HISTORICAL_DATA = "HISTORICAL_DATA"
    LOCAL_STATIC_ANALYSIS = "LOCAL_STATIC_ANALYSIS"


class RestrictionOutcome(StrEnum):
    """Program-rule outcome.

    There is intentionally no ALLOW rule. Restrictions only subtract
    permission; absence of a restriction means the next policy layer may
    continue evaluating the task.
    """

    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class RestrictionSource(StrEnum):
    """Why a restriction decision was produced."""

    BASELINE = "BASELINE"
    PROGRAM = "PROGRAM"
    DEFAULT = "DEFAULT"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"


class RuleSpecificity(IntEnum):
    """Coarse specificity used to select among matching program rules."""

    GENERIC = 10
    ACTION_CLASS = 20
    WORKER_OR_ACTION = 30
    CAPABILITY = 40
    COMBINED = 50


class ActionDescriptor(BaseModel):
    """Normalized description of what a worker invocation intends to do."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_class: ActionClass
    capabilities: frozenset[ActionCapability] = Field(default_factory=frozenset)

    description: str | None = None

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @model_validator(mode="after")
    def validate_capability_consistency(self) -> ActionDescriptor:
        """Catch obviously contradictory descriptor metadata."""
        if (
            ActionCapability.PASSIVE_ONLY in self.capabilities
            and ActionCapability.ACTIVE_NETWORK in self.capabilities
        ):
            raise ValueError(
                "action cannot be both PASSIVE_ONLY and ACTIVE_NETWORK"
            )

        if (
            ActionCapability.READ_ONLY in self.capabilities
            and ActionCapability.STATE_CHANGE in self.capabilities
        ):
            raise ValueError(
                "action cannot be both READ_ONLY and STATE_CHANGE"
            )

        return self


class ActionDescriptorRule(BaseModel):
    """Declarative mapping from worker/action names to an ActionDescriptor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    worker_pattern: str
    action_pattern: str

    descriptor: ActionDescriptor
    priority: int = 0

    @field_validator("rule_id", "worker_pattern", "action_pattern")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    def matches(self, task: Task) -> bool:
        """Return whether this descriptor rule describes the task."""
        return (
            fnmatchcase(task.worker, self.worker_pattern)
            and fnmatchcase(task.action, self.action_pattern)
        )

    @property
    def specificity(self) -> tuple[int, int]:
        """Return deterministic descriptor-rule specificity."""
        wildcards = (
            self.worker_pattern.count("*")
            + self.worker_pattern.count("?")
            + self.action_pattern.count("*")
            + self.action_pattern.count("?")
        )
        concrete_length = (
            len(self.worker_pattern)
            + len(self.action_pattern)
            - wildcards
        )
        return (-wildcards, concrete_length)


class ActionDescriptorProvider(Protocol):
    """Resolve the intended behavior of a worker task."""

    async def descriptor_for(self, task: Task) -> ActionDescriptor | None:
        """Return descriptor or None when the action is unknown."""
        ...


class StaticActionDescriptorProvider:
    """Rule-based action registry used until worker descriptors exist.

    Worker modules can later expose descriptors directly without changing the
    restrictions engine or lifecycle gate.
    """

    def __init__(
        self,
        rules: tuple[ActionDescriptorRule, ...] | list[ActionDescriptorRule],
    ) -> None:
        self._rules = tuple(rules)

        seen: set[str] = set()
        for rule in self._rules:
            if rule.rule_id in seen:
                raise ValueError(
                    f"duplicate action descriptor rule_id: {rule.rule_id}"
                )
            seen.add(rule.rule_id)

    async def descriptor_for(self, task: Task) -> ActionDescriptor | None:
        """Return the highest-priority/specificity matching descriptor."""
        matches = [rule for rule in self._rules if rule.matches(task)]

        if not matches:
            return None

        matches.sort(
            key=lambda rule: (
                rule.priority,
                rule.specificity[0],
                rule.specificity[1],
                rule.rule_id,
            ),
            reverse=True,
        )
        return matches[0].descriptor


class RestrictionRule(BaseModel):
    """Additional bug-bounty-program restriction.

    All populated selectors are ANDed together.

    Example:
        outcome=BLOCK
        action_classes={CONTENT_DISCOVERY}
        any_capabilities={HIGH_VOLUME_GUESSING}

    matches only content-discovery actions that also advertise the high-volume
    guessing capability.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    outcome: RestrictionOutcome

    action_classes: frozenset[ActionClass] = Field(default_factory=frozenset)
    workers: frozenset[str] = Field(default_factory=frozenset)
    actions: frozenset[str] = Field(default_factory=frozenset)

    all_capabilities: frozenset[ActionCapability] = Field(
        default_factory=frozenset
    )
    any_capabilities: frozenset[ActionCapability] = Field(
        default_factory=frozenset
    )
    excluded_capabilities: frozenset[ActionCapability] = Field(
        default_factory=frozenset
    )

    priority: int = 0
    reason: str

    @field_validator("rule_id", "reason")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("workers", "actions")
    @classmethod
    def normalize_patterns(cls, value: frozenset[str]) -> frozenset[str]:
        return frozenset(
            pattern.strip()
            for pattern in value
            if pattern.strip()
        )

    @model_validator(mode="after")
    def validate_rule(self) -> RestrictionRule:
        """Require at least one selector and non-contradictory capabilities."""
        has_selector = any(
            (
                self.action_classes,
                self.workers,
                self.actions,
                self.all_capabilities,
                self.any_capabilities,
                self.excluded_capabilities,
            )
        )

        if not has_selector:
            raise ValueError(
                "restriction rule must define at least one selector"
            )

        overlap = (
            (self.all_capabilities | self.any_capabilities)
            & self.excluded_capabilities
        )
        if overlap:
            joined = ", ".join(sorted(cap.value for cap in overlap))
            raise ValueError(
                f"required and excluded capabilities overlap: {joined}"
            )

        return self

    def matches(self, task: Task, descriptor: ActionDescriptor) -> bool:
        """Return whether all configured selectors match."""
        if (
            self.action_classes
            and descriptor.action_class not in self.action_classes
        ):
            return False

        if self.workers and not any(
            fnmatchcase(task.worker, pattern)
            for pattern in self.workers
        ):
            return False

        if self.actions and not any(
            fnmatchcase(task.action, pattern)
            for pattern in self.actions
        ):
            return False

        capabilities = descriptor.capabilities

        if not self.all_capabilities.issubset(capabilities):
            return False

        if (
            self.any_capabilities
            and not (self.any_capabilities & capabilities)
        ):
            return False

        if self.excluded_capabilities & capabilities:
            return False

        return True

    @property
    def specificity(self) -> tuple[int, int]:
        """Return coarse and fine-grained specificity."""
        selector_groups = sum(
            bool(group)
            for group in (
                self.action_classes,
                self.workers,
                self.actions,
                self.all_capabilities,
                self.any_capabilities,
                self.excluded_capabilities,
            )
        )

        if selector_groups >= 3:
            tier = RuleSpecificity.COMBINED
        elif self.all_capabilities or self.any_capabilities:
            tier = RuleSpecificity.CAPABILITY
        elif self.workers or self.actions:
            tier = RuleSpecificity.WORKER_OR_ACTION
        elif self.action_classes:
            tier = RuleSpecificity.ACTION_CLASS
        else:
            tier = RuleSpecificity.GENERIC

        fine = (
            len(self.action_classes)
            + len(self.workers)
            + len(self.actions)
            + len(self.all_capabilities)
            + len(self.any_capabilities)
            + len(self.excluded_capabilities)
        )

        return (int(tier), fine)


class RestrictionDecision(BaseModel):
    """Explainable restrictions-layer result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: GateOutcome
    source: RestrictionSource

    task_id: str
    worker: str
    action: str

    descriptor: ActionDescriptor | None = None

    matched_rule_id: str | None = None
    matched_rule_ids: tuple[str, ...] = ()

    reason: str


class RestrictionDecisionRecorder(Protocol):
    """Optional persistence hook for `nightscout explain`."""

    async def record(
        self,
        *,
        task: Task,
        decision: RestrictionDecision,
    ) -> None:
        """Persist one restriction decision."""
        ...


BASELINE_BLOCKED_ACTION_CLASSES = frozenset(
    {
        ActionClass.AUTHENTICATED_ACCESS,
        ActionClass.CREDENTIAL_USE,
        ActionClass.BRUTE_FORCE,
        ActionClass.DESTRUCTIVE_ACTION,
        ActionClass.RESOURCE_EXHAUSTION,
        ActionClass.SOCIAL_ENGINEERING,
        ActionClass.EXPLOITATION,
    }
)


BASELINE_BLOCKED_CAPABILITIES = frozenset(
    {
        ActionCapability.STATE_CHANGE,
        ActionCapability.AUTHENTICATED_SESSION,
        ActionCapability.USES_CREDENTIALS,
        ActionCapability.ACCESSES_OTHER_USERS_DATA,
        ActionCapability.PASSWORD_GUESSING,
        ActionCapability.HIGH_VOLUME_GUESSING,
        ActionCapability.FILE_UPLOAD,
        ActionCapability.ACCOUNT_MODIFICATION,
        ActionCapability.TRANSACTIONAL_ACTION,
        ActionCapability.RESOURCE_EXHAUSTION,
        ActionCapability.AVAILABILITY_IMPACT,
        ActionCapability.SOCIAL_INTERACTION,
        ActionCapability.EXPLOIT_EXECUTION,
    }
)


class RestrictionEngine:
    """Evaluate Night Scout baseline invariants and program restrictions."""

    def __init__(
        self,
        rules: tuple[RestrictionRule, ...] | list[RestrictionRule] = (),
    ) -> None:
        self._rules: dict[str, RestrictionRule] = {}

        for rule in rules:
            if rule.rule_id in self._rules:
                raise ValueError(
                    f"duplicate restriction rule_id: {rule.rule_id}"
                )
            self._rules[rule.rule_id] = rule

    def evaluate(
        self,
        *,
        task: Task,
        descriptor: ActionDescriptor,
    ) -> RestrictionDecision:
        """Return the most restrictive applicable decision."""
        baseline_reason = _baseline_violation_reason(descriptor)
        if baseline_reason is not None:
            return RestrictionDecision(
                outcome=GateOutcome.BLOCK,
                source=RestrictionSource.BASELINE,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                descriptor=descriptor,
                reason=baseline_reason,
            )

        matches = [
            rule
            for rule in self._rules.values()
            if rule.matches(task, descriptor)
        ]

        if not matches:
            return RestrictionDecision(
                outcome=GateOutcome.ALLOW,
                source=RestrictionSource.DEFAULT,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                descriptor=descriptor,
                reason="no baseline or program restriction matched",
            )

        matches.sort(key=_restriction_rule_sort_key, reverse=True)
        winner = matches[0]

        return RestrictionDecision(
            outcome=(
                GateOutcome.BLOCK
                if winner.outcome is RestrictionOutcome.BLOCK
                else GateOutcome.REVIEW
            ),
            source=RestrictionSource.PROGRAM,
            task_id=task.task_id,
            worker=task.worker,
            action=task.action,
            descriptor=descriptor,
            matched_rule_id=winner.rule_id,
            matched_rule_ids=tuple(rule.rule_id for rule in matches),
            reason=winner.reason,
        )

    @property
    def rule_count(self) -> int:
        """Return configured program-specific restriction count."""
        return len(self._rules)


class RestrictionsGate:
    """Lifecycle gate enforcing recon-only and program restrictions."""

    def __init__(
        self,
        *,
        engine: RestrictionEngine,
        descriptors: ActionDescriptorProvider,
        recorder: RestrictionDecisionRecorder | None = None,
    ) -> None:
        self._engine = engine
        self._descriptors = descriptors
        self._recorder = recorder

    async def evaluate(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> GateDecision:
        """Resolve intended action and enforce restrictions."""
        del schedule  # Restriction semantics do not depend on scheduler score.

        descriptor = await self._descriptors.descriptor_for(task)

        if descriptor is None:
            decision = RestrictionDecision(
                outcome=GateOutcome.REVIEW,
                source=RestrictionSource.UNKNOWN_ACTION,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                descriptor=None,
                reason=(
                    "worker/action has no registered ActionDescriptor; "
                    "manual review required"
                ),
            )
        else:
            decision = self._engine.evaluate(
                task=task,
                descriptor=descriptor,
            )

        if self._recorder is not None:
            await self._recorder.record(
                task=task,
                decision=decision,
            )

        return GateDecision(
            outcome=decision.outcome,
            reason=decision.reason,
        )


def default_recon_descriptor_rules() -> tuple[ActionDescriptorRule, ...]:
    """Return descriptors for the workers/actions currently planned in README.

    These are intentionally conservative. Future worker modules should expose
    their own descriptors and tests; this function provides a bootstrap
    registry for the initial native CLI runtime.
    """
    passive = ActionCapability.PASSIVE_ONLY
    active = ActionCapability.ACTIVE_NETWORK
    read_only = ActionCapability.READ_ONLY

    return (
        ActionDescriptorRule(
            rule_id="passive-domains.enumerate",
            worker_pattern="passive_domains",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.PASSIVE_DISCOVERY,
                capabilities=frozenset({passive, read_only}),
                description="Passive domain/subdomain discovery",
            ),
        ),
        ActionDescriptorRule(
            rule_id="permutations.generate",
            worker_pattern="permutations",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.PASSIVE_DISCOVERY,
                capabilities=frozenset(
                    {
                        passive,
                        read_only,
                        ActionCapability.LOCAL_STATIC_ANALYSIS,
                    }
                ),
                description=(
                    "Local bounded DNS candidate generation from "
                    "global/target vocabulary"
                ),
            ),
        ),
        ActionDescriptorRule(
            rule_id="dns.query",
            worker_pattern="dns",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.DNS_QUERY,
                capabilities=frozenset({active, read_only}),
                description="Read-only DNS resolution/querying",
            ),
        ),
        ActionDescriptorRule(
            rule_id="http.probe",
            worker_pattern="http",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.HTTP_PROBE,
                capabilities=frozenset({active, read_only}),
                description="Read-only HTTP service probing",
            ),
        ),
        ActionDescriptorRule(
            rule_id="tls.inspect",
            worker_pattern="tls",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.TLS_INSPECTION,
                capabilities=frozenset({active, read_only}),
                description="TLS/certificate inspection",
            ),
        ),
        ActionDescriptorRule(
            rule_id="asn.passive",
            worker_pattern="asn",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.PASSIVE_DISCOVERY,
                capabilities=frozenset({passive, read_only}),
                description="Passive ASN/network relationship discovery",
            ),
        ),
        ActionDescriptorRule(
            rule_id="archives.lookup",
            worker_pattern="archives",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.ARCHIVE_LOOKUP,
                capabilities=frozenset(
                    {
                        passive,
                        read_only,
                        ActionCapability.HISTORICAL_DATA,
                    }
                ),
                description="Public historical/archive lookup",
            ),
        ),
        ActionDescriptorRule(
            rule_id="crawler.crawl",
            worker_pattern="crawler",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.CRAWL,
                capabilities=frozenset({active, read_only}),
                description="Read-only web crawling",
            ),
        ),
        ActionDescriptorRule(
            rule_id="javascript.analyze",
            worker_pattern="javascript",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.JAVASCRIPT_ANALYSIS,
                capabilities=frozenset({passive, read_only}),
                description="Local/static JavaScript analysis",
            ),
        ),
        ActionDescriptorRule(
            rule_id="vhost.discover",
            worker_pattern="vhost",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.VHOST_DISCOVERY,
                capabilities=frozenset(
                    {
                        active,
                        read_only,
                        ActionCapability.HOST_HEADER_VARIATION,
                    }
                ),
                description="Read-only virtual-host discovery",
            ),
        ),
        ActionDescriptorRule(
            rule_id="content.discover",
            worker_pattern="content",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.CONTENT_DISCOVERY,
                capabilities=frozenset(
                    {
                        active,
                        read_only,
                        ActionCapability.DIRECTORY_ENUMERATION,
                    }
                ),
                description="Rate-limited read-only content discovery",
            ),
        ),
        ActionDescriptorRule(
            rule_id="parameters.discover",
            worker_pattern="parameters",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.PARAMETER_DISCOVERY,
                capabilities=frozenset(
                    {
                        active,
                        read_only,
                        ActionCapability.PARAMETER_ENUMERATION,
                    }
                ),
                description="Read-only parameter discovery",
            ),
        ),
        ActionDescriptorRule(
            rule_id="mobile.static",
            worker_pattern="mobile",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.MOBILE_STATIC_ANALYSIS,
                capabilities=frozenset(
                    {
                        passive,
                        read_only,
                        ActionCapability.LOCAL_STATIC_ANALYSIS,
                    }
                ),
                description="Local static analysis of mobile artifacts",
            ),
        ),
        ActionDescriptorRule(
            rule_id="fingerprints.analyze",
            worker_pattern="fingerprints",
            action_pattern="*",
            descriptor=ActionDescriptor(
                action_class=ActionClass.FINGERPRINTING,
                capabilities=frozenset({passive, read_only}),
                description="Fingerprint comparison/analysis",
            ),
        ),
    )


def _baseline_violation_reason(
    descriptor: ActionDescriptor,
) -> str | None:
    """Return a complete non-overridable baseline violation reason."""
    reasons: list[str] = []

    if descriptor.action_class in BASELINE_BLOCKED_ACTION_CLASSES:
        reasons.append(f"action_class={descriptor.action_class.value}")

    blocked = descriptor.capabilities & BASELINE_BLOCKED_CAPABILITIES
    if blocked:
        joined = ", ".join(sorted(capability.value for capability in blocked))
        reasons.append(f"capabilities={joined}")

    if not reasons:
        return None

    return (
        "Night Scout recon-only baseline blocks this action: "
        + "; ".join(reasons)
    )


def _restriction_rule_sort_key(
    rule: RestrictionRule,
) -> tuple[int, int, int, int, str]:
    """Return deterministic program-rule precedence.

    BLOCK wins over REVIEW when all other precedence values tie.
    """
    specificity_tier, specificity_count = rule.specificity

    outcome_safety = (
        2 if rule.outcome is RestrictionOutcome.BLOCK else 1
    )

    return (
        rule.priority,
        specificity_tier,
        specificity_count,
        outcome_safety,
        rule.rule_id,
    )
