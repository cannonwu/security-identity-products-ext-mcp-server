"""Parser for OCI IAM policy statements."""

from __future__ import annotations

import re
from typing import List, Optional

from ..models import ParsedPolicyStatement

ALLOW_PATTERN = re.compile(
    r"^\s*(?P<effect>Allow)\s+(?P<subject>.+?)\s+to\s+(?P<verb>inspect|read|use|manage)\s+(?P<resource>.+?)\s+in\s+(?P<location>.+?)(?:\s+where\s+(?P<conditions>.+))?\s*$",
    re.IGNORECASE,
)


def _split_top_level_csv(source: str) -> List[str]:
    depth = 0
    token = []
    parts: List[str] = []
    for char in source:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0:
            part = "".join(token).strip()
            if part:
                parts.append(part)
            token = []
            continue
        token.append(char)

    tail = "".join(token).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_subject(subject: str) -> tuple[str, str]:
    normalized = subject.strip()
    lowered = normalized.lower()
    if lowered in {"any-user", "any group", "any-group"}:
        return lowered.replace(" ", "-"), normalized
    if lowered.startswith("group "):
        return "group", normalized[6:].strip()
    if lowered.startswith("dynamic-group "):
        return "dynamic-group", normalized[len("dynamic-group ") :].strip()
    if lowered.startswith("service "):
        return "service", normalized[8:].strip()
    return "unknown", normalized


def _parse_location(location: str) -> tuple[str, str]:
    normalized = location.strip()
    lowered = normalized.lower()
    if lowered == "tenancy":
        return "tenancy", "tenancy"
    if lowered.startswith("compartment "):
        return "compartment", normalized[len("compartment ") :].strip()
    return "unknown", normalized


def _parse_conditions(raw_conditions: Optional[str]) -> tuple[Optional[str], List[str]]:
    if not raw_conditions:
        return None, []

    candidate = raw_conditions.strip()
    lowered = candidate.lower()
    if lowered.startswith("any {") and candidate.endswith("}"):
        inner = candidate[candidate.find("{") + 1 : -1].strip()
        return "any", _split_top_level_csv(inner)
    if lowered.startswith("all {") and candidate.endswith("}"):
        inner = candidate[candidate.find("{") + 1 : -1].strip()
        return "all", _split_top_level_csv(inner)
    return "single", [candidate]


def parse_policy_statement(statement: str) -> ParsedPolicyStatement:
    match = ALLOW_PATTERN.match(statement)
    if not match:
        return ParsedPolicyStatement(
            original=statement,
            effect="unknown",
            subject="",
            subject_kind="unknown",
            subject_name="",
            verb="unknown",
            resource_type="unknown",
            location="",
            location_kind="unknown",
            location_value="",
            condition_type=None,
            conditions=[],
            parse_errors=["Unsupported or unrecognized policy statement syntax."],
        )

    subject = match.group("subject")
    location = match.group("location")
    subject_kind, subject_name = _parse_subject(subject)
    location_kind, location_value = _parse_location(location)
    condition_type, conditions = _parse_conditions(match.group("conditions"))

    return ParsedPolicyStatement(
        original=statement,
        effect=match.group("effect").lower(),
        subject=subject,
        subject_kind=subject_kind,
        subject_name=subject_name,
        verb=match.group("verb").lower(),
        resource_type=match.group("resource").strip(),
        location=location,
        location_kind=location_kind,
        location_value=location_value,
        condition_type=condition_type,
        conditions=conditions,
        parse_errors=[],
    )
