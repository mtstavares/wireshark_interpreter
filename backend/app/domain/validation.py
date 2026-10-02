from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class ValidationStatus(StrEnum):
    AWAITING_APPROVAL = "awaiting_approval"
    BLOCKED = "blocked"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ValidationTechnicalResult(StrEnum):
    NOT_EXECUTED = "not_executed"
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    ERROR = "error"


class AnalystConclusion(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ValidationAuditEntry:
    id: str
    validation_id: str
    action: str
    actor: str
    occurred_at: datetime
    details: dict[str, str | int | bool | None]


@dataclass(frozen=True, slots=True)
class Validation:
    id: str
    analysis_id: str
    finding_id: str
    validator: str
    target_ip: str
    target_port: int
    status: ValidationStatus
    policy_allowed: bool
    policy_reason: str
    scope_reference: str
    requested_by: str
    approved_by: str | None
    created_at: datetime
    approved_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    technical_result: ValidationTechnicalResult
    analyst_conclusion: AnalystConclusion
    result_summary: str | None
    review_rationale: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    audit: list[ValidationAuditEntry] = field(default_factory=list[ValidationAuditEntry])
