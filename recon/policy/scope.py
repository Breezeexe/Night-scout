"""Scope evaluation for Night Scout.

This module is the fail-closed authorization boundary for target selection.

It answers two separate questions:

1. ScopeEngine:
       "How does the configured bug-bounty scope classify this asset?"

2. ScopeGate:
       "Given that classification and the worker's activity class, may this
       lifecycle task proceed?"

The scope engine does not resolve DNS, infer ownership from ASN data, or turn
relationships into authorization. A certificate neighbor, shared IP, ASN,
favicon match, or related hostname may be useful intelligence, but it becomes
actively testable only when an explicit scope rule classifies the execution
target accordingly.

Unknown/ambiguous targets are preserved for review rather than silently
executed or discarded.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from fnmatch import fnmatchcase
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import ScopeState
from recon.core.lifecycle import GateDecision, GateOutcome
from recon.core.queue import Task
from recon.core.scheduler import ScheduleDecision


IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


class ScopeAssetKind(StrEnum):
    """Kinds of assets that can be classified directly by the scope engine."""

    DOMAIN = "DOMAIN"
    URL = "URL"
    IP_ADDRESS = "IP_ADDRESS"
    CIDR = "CIDR"
    MOBILE_APP = "MOBILE_APP"


class WorkerActivity(StrEnum):
    """Whether a worker interacts with the target or only public/local data."""

    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"


class RuleSpecificity(IntEnum):
    """Coarse rule-specificity tiers used during precedence resolution."""

    GENERIC = 10
    WILDCARD = 20
    EXACT = 30
    URL_PATH = 40


class ScopeSubject(BaseModel):
    """Normalized asset presented to the scope engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ScopeAssetKind
    value: str

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        """Reject blank subject values."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("scope subject value must not be blank")
        return normalized

    @model_validator(mode="after")
    def validate_and_canonicalize(self) -> ScopeSubject:
        """Canonicalize values according to their asset kind."""
        canonical = _canonicalize_subject_value(self.kind, self.value)
        object.__setattr__(self, "value", canonical)
        return self


class ScopeRule(BaseModel):
    """One explicit scope rule.

    Examples:

        DOMAIN / example.com
        DOMAIN / *.example.com
        URL    / https://api.example.com/v1/*
        IP_ADDRESS / 203.0.113.10
        CIDR   / 203.0.113.0/24
        MOBILE_APP / com.example.mobile

    `priority` is the first precedence key. Use it for explicit program
    exceptions. Within the same priority, more specific rules win.

    If two equally specific rules conflict, the safer classification wins:
        OUT_OF_SCOPE > AMBIGUOUS > PASSIVE_ONLY > IN_SCOPE
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    kind: ScopeAssetKind
    pattern: str

    state: ScopeState

    priority: int = 0
    tier: str | None = None
    reason: str | None = None

    @field_validator("rule_id")
    @classmethod
    def normalize_rule_id(cls, value: str) -> str:
        """Normalize stable rule identifiers."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("rule_id must not be blank")
        return normalized

    @field_validator("tier", "reason")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        """Normalize optional human-readable metadata."""
        if value is None:
            return None
        return value.strip() or None

    @model_validator(mode="after")
    def validate_rule(self) -> ScopeRule:
        """Validate state/pattern and store a canonical pattern."""
        if self.state is ScopeState.UNKNOWN:
            raise ValueError("scope rules cannot explicitly classify UNKNOWN")

        canonical = _canonicalize_rule_pattern(self.kind, self.pattern)
        object.__setattr__(self, "pattern", canonical)
        return self

    @property
    def specificity(self) -> tuple[int, int]:
        """Return specificity tier plus pattern length for deterministic order."""
        if self.kind is ScopeAssetKind.DOMAIN:
            if self.pattern.startswith("*."):
                tier = RuleSpecificity.WILDCARD
            else:
                tier = RuleSpecificity.EXACT
        elif self.kind is ScopeAssetKind.URL:
            parsed = urlsplit(self.pattern)
            path_has_glob = "*" in parsed.path or "?" in parsed.path
            host_has_glob = parsed.hostname is not None and "*" in parsed.hostname

            if path_has_glob or parsed.path not in {"", "/"}:
                tier = RuleSpecificity.URL_PATH
            elif host_has_glob:
                tier = RuleSpecificity.WILDCARD
            else:
                tier = RuleSpecificity.EXACT
        elif self.kind in {ScopeAssetKind.IP_ADDRESS, ScopeAssetKind.MOBILE_APP}:
            tier = (
                RuleSpecificity.WILDCARD
                if "*" in self.pattern or "?" in self.pattern
                else RuleSpecificity.EXACT
            )
        elif self.kind is ScopeAssetKind.CIDR:
            network = ip_network(self.pattern, strict=False)
            # Longer prefixes are more specific. Keep the coarse tier stable.
            return (int(RuleSpecificity.EXACT), network.prefixlen)
        else:
            tier = RuleSpecificity.GENERIC

        return (int(tier), len(self.pattern))

    def matches(self, subject: ScopeSubject) -> bool:
        """Return whether this rule applies to the supplied subject."""
        if self.kind is ScopeAssetKind.DOMAIN:
            host = _subject_hostname(subject)
            return host is not None and _match_domain_pattern(host, self.pattern)

        if self.kind is ScopeAssetKind.URL:
            if subject.kind is not ScopeAssetKind.URL:
                return False
            return _match_url_pattern(subject.value, self.pattern)

        if self.kind is ScopeAssetKind.IP_ADDRESS:
            if subject.kind is not ScopeAssetKind.IP_ADDRESS:
                return False
            return _match_ip_pattern(subject.value, self.pattern)

        if self.kind is ScopeAssetKind.CIDR:
            return _match_network_pattern(subject, self.pattern)

        if self.kind is ScopeAssetKind.MOBILE_APP:
            if subject.kind is not ScopeAssetKind.MOBILE_APP:
                return False
            return fnmatchcase(subject.value, self.pattern)

        return False


class ScopeDecision(BaseModel):
    """Explainable classification of one scope subject."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: ScopeSubject
    state: ScopeState

    matched_rule_id: str | None = None
    matched_rule_ids: tuple[str, ...] = ()

    tier: str | None = None
    reason: str | None = None

    @property
    def is_known(self) -> bool:
        """Return whether at least one configured rule classified the subject."""
        return self.state is not ScopeState.UNKNOWN


class DuplicateScopeRuleError(ValueError):
    """Raised when two configured rules share one stable rule_id."""


class ScopeEngine:
    """Evaluate normalized assets against explicit program scope rules."""

    def __init__(self, rules: tuple[ScopeRule, ...] | list[ScopeRule] = ()) -> None:
        self._rules: dict[str, ScopeRule] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: ScopeRule) -> None:
        """Register a unique scope rule."""
        if rule.rule_id in self._rules:
            raise DuplicateScopeRuleError(
                f"scope rule already registered: {rule.rule_id}"
            )
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> ScopeRule:
        """Remove and return one scope rule."""
        normalized = rule_id.strip()
        if not normalized:
            raise ValueError("rule_id must not be blank")

        try:
            return self._rules.pop(normalized)
        except KeyError as exc:
            raise KeyError(f"unknown scope rule: {normalized}") from exc

    def evaluate(self, subject: ScopeSubject) -> ScopeDecision:
        """Classify a subject using deterministic precedence."""
        matches = [
            rule
            for rule in self._rules.values()
            if rule.matches(subject)
        ]

        if not matches:
            return ScopeDecision(
                subject=subject,
                state=ScopeState.UNKNOWN,
                reason="no configured scope rule matched this asset",
            )

        matches.sort(key=_rule_sort_key, reverse=True)
        winner = matches[0]

        return ScopeDecision(
            subject=subject,
            state=winner.state,
            matched_rule_id=winner.rule_id,
            matched_rule_ids=tuple(rule.rule_id for rule in matches),
            tier=winner.tier,
            reason=winner.reason or (
                f"matched scope rule {winner.rule_id}"
            ),
        )

    @property
    def rule_count(self) -> int:
        """Return the number of configured scope rules."""
        return len(self._rules)


class ScopeSubjectProvider(Protocol):
    """Resolve the concrete execution target represented by a Task.

    The task's input_event_id is not always itself the network target. For
    example, a JavaScript event may schedule a request against the HTTP service
    that served it. The future storage layer should follow provenance and return
    the actual asset that the worker would touch.
    """

    async def subject_for(self, task: Task) -> ScopeSubject | None:
        """Return the execution target for this task."""
        ...


class WorkerActivityProvider(Protocol):
    """Describe whether a worker is passive or active."""

    async def activity_for(self, task: Task) -> WorkerActivity:
        """Return the worker activity class."""
        ...


class ScopeDecisionRecorder(Protocol):
    """Optional persistence hook for scope decisions."""

    async def record(
        self,
        *,
        task: Task,
        decision: ScopeDecision,
        activity: WorkerActivity,
    ) -> None:
        """Persist an explainable scope decision."""
        ...


@dataclass(frozen=True, slots=True)
class StaticWorkerActivityProvider:
    """Simple worker activity registry used before worker descriptors exist.

    Unknown workers default to ACTIVE. This is intentionally fail-closed.
    """

    activities: dict[str, WorkerActivity]
    default: WorkerActivity = WorkerActivity.ACTIVE

    async def activity_for(self, task: Task) -> WorkerActivity:
        """Return configured activity or the fail-closed default."""
        return self.activities.get(task.worker, self.default)


class ScopeGate:
    """Lifecycle gate that enforces ScopeEngine classifications.

    Active workers:
        IN_SCOPE      -> ALLOW
        PASSIVE_ONLY  -> BLOCK
        OUT_OF_SCOPE  -> BLOCK
        UNKNOWN       -> REVIEW
        AMBIGUOUS     -> REVIEW

    Passive workers:
        IN_SCOPE      -> ALLOW
        PASSIVE_ONLY  -> ALLOW
        OUT_OF_SCOPE  -> BLOCK
        UNKNOWN       -> REVIEW by default
        AMBIGUOUS     -> REVIEW

    `allow_unknown_passive` can be enabled for programs where passive
    relationship collection outside the active scope is explicitly acceptable.
    This never permits an active worker.
    """

    def __init__(
        self,
        *,
        engine: ScopeEngine,
        subjects: ScopeSubjectProvider,
        activities: WorkerActivityProvider,
        recorder: ScopeDecisionRecorder | None = None,
        allow_unknown_passive: bool = False,
    ) -> None:
        self._engine = engine
        self._subjects = subjects
        self._activities = activities
        self._recorder = recorder
        self._allow_unknown_passive = allow_unknown_passive

    async def evaluate(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> GateDecision:
        """Classify the task's execution target and enforce activity policy."""
        del schedule  # Scope is independent from scheduler score.

        subject = await self._subjects.subject_for(task)
        activity = await self._activities.activity_for(task)

        if subject is None:
            return GateDecision(
                outcome=GateOutcome.REVIEW,
                reason=(
                    "scope execution target could not be resolved from task "
                    f"{task.task_id}"
                ),
            )

        decision = self._engine.evaluate(subject)

        if self._recorder is not None:
            await self._recorder.record(
                task=task,
                decision=decision,
                activity=activity,
            )

        return self._to_gate_decision(
            decision=decision,
            activity=activity,
        )

    def _to_gate_decision(
        self,
        *,
        decision: ScopeDecision,
        activity: WorkerActivity,
    ) -> GateDecision:
        state = decision.state

        if state is ScopeState.IN_SCOPE:
            return GateDecision(
                outcome=GateOutcome.ALLOW,
                reason=_scope_reason(decision, activity),
            )

        if state is ScopeState.PASSIVE_ONLY:
            if activity is WorkerActivity.PASSIVE:
                return GateDecision(
                    outcome=GateOutcome.ALLOW,
                    reason=_scope_reason(decision, activity),
                )
            return GateDecision(
                outcome=GateOutcome.BLOCK,
                reason=(
                    f"active worker cannot touch PASSIVE_ONLY asset: "
                    f"{decision.subject.value}; {_scope_reason(decision, activity)}"
                ),
            )

        if state is ScopeState.OUT_OF_SCOPE:
            return GateDecision(
                outcome=GateOutcome.BLOCK,
                reason=(
                    f"asset is OUT_OF_SCOPE: {decision.subject.value}; "
                    f"{_scope_reason(decision, activity)}"
                ),
            )

        if state is ScopeState.UNKNOWN:
            if (
                activity is WorkerActivity.PASSIVE
                and self._allow_unknown_passive
            ):
                return GateDecision(
                    outcome=GateOutcome.ALLOW,
                    reason=(
                        "unknown asset permitted for passive-only relationship "
                        "collection by scope configuration"
                    ),
                )

            return GateDecision(
                outcome=GateOutcome.REVIEW,
                reason=(
                    f"asset has no matching scope rule: "
                    f"{decision.subject.value}"
                ),
            )

        # AMBIGUOUS is always a human decision.
        return GateDecision(
            outcome=GateOutcome.REVIEW,
            reason=(
                f"asset scope is AMBIGUOUS: {decision.subject.value}; "
                f"{_scope_reason(decision, activity)}"
            ),
        )


def _rule_sort_key(rule: ScopeRule) -> tuple[int, int, int, int, str]:
    """Return deterministic precedence.

    Order:
        1. higher explicit priority
        2. higher specificity tier
        3. longer/more specific pattern
        4. safer state for otherwise identical rules
        5. stable rule_id tie-break
    """
    specificity_tier, specificity_length = rule.specificity

    state_safety = {
        ScopeState.IN_SCOPE: 1,
        ScopeState.PASSIVE_ONLY: 2,
        ScopeState.AMBIGUOUS: 3,
        ScopeState.OUT_OF_SCOPE: 4,
        ScopeState.UNKNOWN: 0,
    }[rule.state]

    return (
        rule.priority,
        specificity_tier,
        specificity_length,
        state_safety,
        rule.rule_id,
    )


def _canonicalize_subject_value(
    kind: ScopeAssetKind,
    value: str,
) -> str:
    if kind is ScopeAssetKind.DOMAIN:
        return _canonical_domain(value)

    if kind is ScopeAssetKind.URL:
        return _canonical_url(value)

    if kind is ScopeAssetKind.IP_ADDRESS:
        return str(ip_address(value))

    if kind is ScopeAssetKind.CIDR:
        return str(ip_network(value, strict=False))

    if kind is ScopeAssetKind.MOBILE_APP:
        return value.strip()

    raise ValueError(f"unsupported scope asset kind: {kind}")


def _canonicalize_rule_pattern(
    kind: ScopeAssetKind,
    pattern: str,
) -> str:
    value = pattern.strip()
    if not value:
        raise ValueError("scope rule pattern must not be blank")

    if kind is ScopeAssetKind.DOMAIN:
        if value.startswith("*."):
            suffix = _canonical_domain(value[2:])
            return f"*.{suffix}"
        if "*" in value or "?" in value:
            raise ValueError(
                "DOMAIN rules support only the leading '*.' wildcard form"
            )
        return _canonical_domain(value)

    if kind is ScopeAssetKind.URL:
        return _canonical_url_pattern(value)

    if kind is ScopeAssetKind.IP_ADDRESS:
        if "*" in value or "?" in value:
            # IP globbing is supported only as a generic textual rule. CIDR is
            # strongly preferred for network ranges.
            return value
        return str(ip_address(value))

    if kind is ScopeAssetKind.CIDR:
        return str(ip_network(value, strict=False))

    if kind is ScopeAssetKind.MOBILE_APP:
        return value

    raise ValueError(f"unsupported scope asset kind: {kind}")


def _canonical_domain(value: str) -> str:
    """Canonicalize a DNS name without resolving it."""
    domain = value.strip().rstrip(".").lower()
    if not domain:
        raise ValueError("domain must not be blank")

    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid internationalized domain: {value}") from exc

    labels = ascii_domain.split(".")
    if any(not label for label in labels):
        raise ValueError(f"invalid domain: {value}")

    return ascii_domain


def _canonical_url(value: str) -> str:
    """Canonicalize a concrete HTTP(S) URL for scope comparison."""
    parsed = urlsplit(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("scope URLs must use http or https")

    if parsed.hostname is None:
        raise ValueError("scope URL must contain a hostname")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("scope URLs must not contain userinfo")

    host = _canonical_domain(parsed.hostname)
    port = parsed.port

    netloc = host
    if port is not None and not _is_default_port(parsed.scheme.lower(), port):
        netloc = f"{host}:{port}"

    path = parsed.path or "/"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def _canonical_url_pattern(value: str) -> str:
    """Canonicalize a URL rule while preserving host/path wildcards."""
    parsed = urlsplit(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("URL rules must use http or https")

    raw_host = parsed.hostname
    if raw_host is None:
        raise ValueError("URL rule must contain a hostname")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL rules must not contain userinfo")

    if raw_host.startswith("*."):
        host = f"*.{_canonical_domain(raw_host[2:])}"
    else:
        if "*" in raw_host or "?" in raw_host:
            raise ValueError(
                "URL host rules support only the leading '*.' wildcard form"
            )
        host = _canonical_domain(raw_host)

    port = parsed.port
    netloc = host
    if port is not None and not _is_default_port(parsed.scheme.lower(), port):
        netloc = f"{host}:{port}"

    path = parsed.path or "/"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def _subject_hostname(subject: ScopeSubject) -> str | None:
    """Return the hostname represented by DOMAIN or URL subjects."""
    if subject.kind is ScopeAssetKind.DOMAIN:
        return subject.value

    if subject.kind is ScopeAssetKind.URL:
        return urlsplit(subject.value).hostname

    return None


def _match_domain_pattern(host: str, pattern: str) -> bool:
    """Match exact domains or recursive bug-bounty '*.example.com' wildcards."""
    host = _canonical_domain(host)

    if pattern.startswith("*."):
        suffix = pattern[2:]
        # Wildcard intentionally excludes the apex but includes any depth:
        # a.example.com and b.a.example.com match, example.com does not.
        return host != suffix and host.endswith(f".{suffix}")

    return host == pattern


def _match_url_pattern(value: str, pattern: str) -> bool:
    """Match a concrete URL against a normalized URL scope rule."""
    candidate = urlsplit(_canonical_url(value))
    rule = urlsplit(pattern)

    if candidate.scheme != rule.scheme:
        return False

    if candidate.hostname is None or rule.hostname is None:
        return False

    if not _match_domain_pattern(candidate.hostname, rule.hostname):
        return False

    if _effective_port(candidate) != _effective_port(rule):
        return False

    candidate_path = candidate.path or "/"
    rule_path = rule.path or "/"

    if not fnmatchcase(candidate_path, rule_path):
        return False

    # A query in the scope rule is treated as an explicit query constraint.
    # An empty rule query means "any query string on this matched path".
    if rule.query and not fnmatchcase(candidate.query, rule.query):
        return False

    return True


def _match_ip_pattern(value: str, pattern: str) -> bool:
    """Match an exact IP or a deliberately configured textual glob."""
    canonical = str(ip_address(value))
    if "*" in pattern or "?" in pattern:
        return fnmatchcase(canonical, pattern)
    return canonical == pattern


def _match_network_pattern(
    subject: ScopeSubject,
    pattern: str,
) -> bool:
    """Match IP/CIDR subjects against a configured CIDR rule."""
    rule_network = ip_network(pattern, strict=False)

    if subject.kind is ScopeAssetKind.IP_ADDRESS:
        address = ip_address(subject.value)
        return (
            address.version == rule_network.version
            and address in rule_network
        )

    if subject.kind is ScopeAssetKind.CIDR:
        candidate = ip_network(subject.value, strict=False)
        return (
            candidate.version == rule_network.version
            and candidate.subnet_of(rule_network)
        )

    return False


def _effective_port(parsed: SplitResult) -> int:
    """Return explicit or scheme-default URL port."""
    if parsed.port is not None:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "https" and port == 443) or (
        scheme == "http" and port == 80
    )


def _scope_reason(
    decision: ScopeDecision,
    activity: WorkerActivity,
) -> str:
    """Return compact explainable text for lifecycle logs/status."""
    pieces = [
        f"scope={decision.state.value}",
        f"activity={activity.value}",
    ]

    if decision.matched_rule_id is not None:
        pieces.append(f"rule={decision.matched_rule_id}")

    if decision.tier is not None:
        pieces.append(f"tier={decision.tier}")

    if decision.reason is not None:
        pieces.append(decision.reason)

    return "; ".join(pieces)
