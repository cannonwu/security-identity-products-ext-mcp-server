"""Normalized project models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CompartmentSummary:
    id: str
    name: str
    parent_id: Optional[str]
    path: str
    description: Optional[str]
    lifecycle_state: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PrincipalSummary:
    id: str
    name: str
    description: Optional[str]
    lifecycle_state: Optional[str]
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedPolicyStatement:
    original: str
    effect: str
    subject: str
    subject_kind: str
    subject_name: str
    verb: str
    resource_type: str
    location: str
    location_kind: str
    location_value: str
    condition_type: Optional[str]
    conditions: List[str]
    parse_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicySummary:
    id: str
    name: str
    compartment_id: str
    compartment_name: str
    compartment_path: str
    description: Optional[str]
    lifecycle_state: Optional[str]
    statements: List[str]
    parsed_statements: List[ParsedPolicyStatement]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["parsed_statements"] = [statement.to_dict() for statement in self.parsed_statements]
        return payload


@dataclass
class PolicyRiskFinding:
    code: str
    severity: str
    title: str
    evidence: str
    rationale: str
    recommendation: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
