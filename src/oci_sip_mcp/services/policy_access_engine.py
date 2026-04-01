"""Core policy engine for IAM policy simulation."""

import re
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum
import json


class PolicyEffect(Enum):
    """Policy effect types."""
    ALLOW = "Allow"
    DENY = "Deny"


class Statement:
    """Represents an OCI IAM policy statement."""
    
    def __init__(self, sid: str, effect: PolicyEffect, principals: List[str], 
                 resources: List[str], actions: List[str], 
                 conditions: Optional[Dict] = None):
        self.sid = sid
        self.effect = effect
        self.principals = principals
        self.resources = resources
        self.actions = actions
        self.conditions = conditions or {}
    
    def to_dict(self) -> Dict:
        """Convert statement to dictionary."""
        return {
            'sid': self.sid,
            'effect': self.effect.value,
            'principals': self.principals,
            'resources': self.resources,
            'actions': self.actions,
            'conditions': self.conditions
        }


class PolicyEvaluationResult:
    """Result of policy evaluation."""
    
    def __init__(self, allowed: bool, matched_statements: List[Statement], 
                 reason: str, audit_trail: List[str]):
        self.allowed = allowed
        self.matched_statements = matched_statements
        self.reason = reason
        self.audit_trail = audit_trail
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return {
            'allowed': self.allowed,
            'matched_statements': [s.to_dict() for s in self.matched_statements],
            'reason': self.reason,
            'audit_trail': self.audit_trail,
            'timestamp': self.timestamp.isoformat()
        }


class PolicyEngine:
    """Core policy evaluation engine."""
    
    def __init__(self):
        self.policies = []
        self.compartments = {}  # Store compartment hierarchy
        self.oci_permissions = self._load_oci_permissions()

    # Subject grammar based on OCI policy syntax docs.
    # Supports:
    # - group <name> | group id <ocid>
    # - dynamic-group <name> | dynamic-group id <ocid>
    # - any-group | any-user
    # - comma-separated subject lists (for groups by name/id)
    _NAME_PATTERN = r"(?:'[^']+'|[^\s,/]+)"
    _GROUP_ENTRY_PATTERN = _NAME_PATTERN + r"(?:/" + _NAME_PATTERN + r")?"
    _GROUP_SUBJECT_PATTERN = r"group\s+" + _GROUP_ENTRY_PATTERN + r"(?:\s*,\s*" + _GROUP_ENTRY_PATTERN + r")*"
    _GROUP_ID_SUBJECT_PATTERN = r"group\s+id\s+ocid1\.[^\s,]+(?:\s*,\s*id\s+ocid1\.[^\s,]+)*"
    _DYNAMIC_GROUP_SUBJECT_PATTERN = r"dynamic-group\s+(?:id\s+ocid1\.[^\s,]+|" + _NAME_PATTERN + r")"
    _SUBJECT_PATTERN = (
        r"("
        + _GROUP_ID_SUBJECT_PATTERN
        + r"|"
        + _GROUP_SUBJECT_PATTERN
        + r"|"
        + _DYNAMIC_GROUP_SUBJECT_PATTERN
        + r"|any-group|any-user)"
    )
    _ACTION_PATTERN = r"((?:manage|use|read|inspect)|\{\s*[^}]+\s*\})"
    _SCOPE_PATTERN = r"(any-tenancy|tenancy(?:\s+" + _NAME_PATTERN + r")?|compartment\s+.+?)"
    _SUPPORTED_WHERE_VARIABLES = {
        'request.user.id',
        'request.user.name',
        'request.user.mfatotpverified',
        'request.groups.id',
        'request.principal.id',
        'request.principal.type',
        'request.permission',
        'request.operation',
        'request.networksource.name',
        'request.utc-timestamp',
        'request.utc-timestamp.month-of-year',
        'request.utc-timestamp.day-of-month',
        'request.utc-timestamp.day-of-week',
        'request.utc-timestamp.time-of-day',
        'request.region',
        'request.ad',
        'request.principal.compartment.tag',
        'request.principal.group.tag',
        'target.group.name',
        'target.group.id',
        'target.compartment.name',
        'target.compartment.id',
        'target.bucket.name',
        'target.resource.compartment.tag',
        'target.resource.tag',
    }
    _SUPPORTED_WHERE_PREFIXES = {
        'request.principal.compartment.tag.',
        'request.principal.group.tag.',
        'target.resource.compartment.tag.',
        'target.resource.tag.',
    }

    _ALLOW_DENY_PATTERN = re.compile(
        r"^(Allow|Deny)\s+"
        + _SUBJECT_PATTERN + r"\s+"
        r"to\s+"
        + _ACTION_PATTERN + r"\s+"
        r"(.+?)"
        r"(?:\s+in\s+"
        + _SCOPE_PATTERN + r")?"
        r"(?:\s+where\s+(.+))?$",
        re.IGNORECASE
    )

    _ENDORSE_ADMIT_PATTERN = re.compile(
        r"^(Endorse|Admit)\s+"
        + _SUBJECT_PATTERN
        + r"(?:\s+of\s+tenancy\s+(" + _NAME_PATTERN + r"))?\s+"
        r"to\s+"
        + _ACTION_PATTERN + r"\s+"
        r"(.+?)"
        r"(?:\s+in\s+"
        + _SCOPE_PATTERN + r")?"
        r"(?:\s+where\s+(.+))?$",
        re.IGNORECASE
    )

    _DEFINE_PATTERN = re.compile(
        r"^Define\s+"
        r"(tenancy|group|dynamic-group|compartment)\s+"
        + r"(" + _NAME_PATTERN + r")\s+"
        r"as\s+"
        r"(ocid1\.[^\s]+)$",
        re.IGNORECASE
    )

    @staticmethod
    def _parse_action(action_raw: str) -> Dict:
        """Parse action segment into verb or permission-set metadata."""
        action_raw = (action_raw or "").strip()
        if action_raw.startswith('{') and action_raw.endswith('}'):
            inner = action_raw[1:-1].strip()
            permissions = [p.strip() for p in inner.split(',') if p.strip()]
            return {
                'permission': action_raw,
                'permission_set': permissions,
                'is_permission_set': True,
            }

        return {
            'permission': action_raw.lower(),
            'permission_set': [],
            'is_permission_set': False,
        }

    @staticmethod
    def _split_condition_clauses(conditions_block: str) -> List[str]:
        """Split comma-separated condition clauses while preserving quoted/pattern and nested group literals."""
        clauses = []
        current = []
        in_single_quote = False
        in_pattern = False
        brace_depth = 0

        for char in conditions_block:
            if char == "'" and not in_pattern:
                in_single_quote = not in_single_quote
                current.append(char)
                continue

            if char == '/' and not in_single_quote:
                in_pattern = not in_pattern
                current.append(char)
                continue

            if char == '{' and not in_single_quote and not in_pattern:
                brace_depth += 1
                current.append(char)
                continue

            if char == '}' and not in_single_quote and not in_pattern:
                brace_depth = max(0, brace_depth - 1)
                current.append(char)
                continue

            if char == ',' and not in_single_quote and not in_pattern and brace_depth == 0:
                clause = ''.join(current).strip()
                if clause:
                    clauses.append(clause)
                current = []
                continue

            current.append(char)

        tail = ''.join(current).strip()
        if tail:
            clauses.append(tail)

        return clauses

    def _parse_condition_clause(self, clause: str) -> Optional[Dict[str, Any]]:
        """Parse one leaf condition clause (variable operator value)."""
        clause_match = re.match(
            r"^([a-zA-Z0-9_.-]+)\s*(=|!=)\s*(.+?)$",
            (clause or '').strip(),
            flags=re.IGNORECASE
        )
        if not clause_match:
            return None

        variable_raw, operator, value_raw = clause_match.groups()
        variable = variable_raw.strip()
        variable_key = variable.lower()
        value_literal = value_raw.strip()
        value_type = 'string'
        value = value_literal

        if value_literal.startswith("'") and value_literal.endswith("'") and len(value_literal) >= 2:
            value_type = 'string'
            value = value_literal[1:-1]
        elif value_literal.startswith('/') and value_literal.endswith('/') and len(value_literal) >= 2:
            value_type = 'pattern'
            value = value_literal[1:-1]
        elif value_literal.lower() in {'true', 'false'}:
            value_type = 'boolean'
            value = value_literal.lower()

        supported_variable = (
            variable_key in self._SUPPORTED_WHERE_VARIABLES
            or any(variable_key.startswith(prefix) for prefix in self._SUPPORTED_WHERE_PREFIXES)
        )

        return {
            'raw': clause.strip(),
            'variable': variable,
            'operator': operator,
            'value_raw': value_literal,
            'value': {
                'type': value_type,
                'value': value,
            },
            'supported_variable': supported_variable,
        }

    def _parse_where_expression(self, expression: str) -> Dict[str, Any]:
        """Parse a where expression into a recursive tree of any/all groups and condition leaves."""
        text = (expression or '').strip()
        if not text:
            return {
                'node': None,
                'conditions': [],
                'unknown_variables': set(),
                'invalid_conditions': [],
                'has_nested_groups': False,
            }

        group_match = re.match(r"^(any|all)\s*\{\s*(.*)\s*\}$", text, flags=re.IGNORECASE)
        if group_match:
            mode = group_match.group(1).lower()
            children_raw = self._split_condition_clauses(group_match.group(2))
            children = []
            parsed_conditions: List[Dict[str, Any]] = []
            unknown_variables = set()
            invalid_conditions: List[str] = []
            has_nested_groups = False

            for child_raw in children_raw:
                child = self._parse_where_expression(child_raw)
                child_node = child.get('node')
                if child_node is None:
                    invalid_conditions.extend(child.get('invalid_conditions', []))
                    if child_raw.strip():
                        invalid_conditions.append(child_raw.strip())
                    continue

                children.append(child_node)
                parsed_conditions.extend(child.get('conditions', []))
                unknown_variables.update(child.get('unknown_variables', set()))
                invalid_conditions.extend(child.get('invalid_conditions', []))
                has_nested_groups = has_nested_groups or child.get('has_nested_groups', False)
                if child_node.get('type') == 'group':
                    has_nested_groups = True

            return {
                'node': {
                    'type': 'group',
                    'mode': mode,
                    'children': children,
                },
                'conditions': parsed_conditions,
                'unknown_variables': unknown_variables,
                'invalid_conditions': invalid_conditions,
                'has_nested_groups': has_nested_groups,
            }

        condition = self._parse_condition_clause(text)
        if not condition:
            return {
                'node': None,
                'conditions': [],
                'unknown_variables': set(),
                'invalid_conditions': [text],
                'has_nested_groups': False,
            }

        unknown_variables = set()
        if not condition['supported_variable']:
            unknown_variables.add(condition['variable'])

        return {
            'node': {
                'type': 'condition',
                'condition': condition,
            },
            'conditions': [condition],
            'unknown_variables': unknown_variables,
            'invalid_conditions': [],
            'has_nested_groups': False,
        }

    @staticmethod
    def _match_condition_value(actual_value: str, clause_value: Dict[str, Any]) -> bool:
        """Case-insensitive match for string, pattern, and boolean condition values."""
        value_type = clause_value.get('type')
        expected = clause_value.get('value')

        if value_type == 'pattern':
            wildcard_pattern = re.escape(expected).replace('\\*', '.*')
            return re.match(rf"^{wildcard_pattern}$", actual_value, flags=re.IGNORECASE) is not None

        if value_type == 'boolean':
            return str(actual_value).strip().lower() == str(expected).strip().lower()

        return str(actual_value).strip().lower() == str(expected).strip().lower()

    @staticmethod
    def _normalize_where_variable(variable: str) -> str:
        return (variable or '').strip().lower()

    @staticmethod
    def _to_string_candidates(value: Any) -> List[str]:
        """Convert scalar/list condition values into a list of comparable strings."""
        if value is None:
            return []

        if isinstance(value, (list, tuple, set)):
            return [str(v) for v in value if v is not None]

        return [str(value)]

    @staticmethod
    def _get_case_insensitive_key(mapping: Dict[str, Any], target: str) -> Optional[str]:
        """Return the original key in mapping whose lowercase value equals target."""
        target_lower = (target or '').lower()
        for key in mapping.keys():
            if str(key).lower() == target_lower:
                return key
        return None

    def _get_context_value(self, context: Dict[str, Any], variable_key: str) -> Any:
        """Get context value by exact dotted variable path, case-insensitive."""
        if not isinstance(context, dict):
            return None

        exact_key = self._get_case_insensitive_key(context, variable_key)
        if exact_key is not None:
            return context.get(exact_key)

        current: Any = context
        for segment in variable_key.split('.'):
            if not isinstance(current, dict):
                return None
            resolved_key = self._get_case_insensitive_key(current, segment)
            if resolved_key is None:
                return None
            current = current.get(resolved_key)

        return current

    def _get_tag_context_value(self, context: Dict[str, Any], base_key: str, suffix: str) -> Any:
        """Resolve tag variables like target.resource.tag.<namespace>.<key>."""
        base_value = self._get_context_value(context, base_key)
        if base_value is None:
            return None

        if not suffix:
            return base_value

        if isinstance(base_value, dict):
            direct_key = self._get_case_insensitive_key(base_value, suffix)
            if direct_key is not None:
                return base_value.get(direct_key)

            current: Any = base_value
            for segment in suffix.split('.'):
                if not isinstance(current, dict):
                    return None
                resolved_key = self._get_case_insensitive_key(current, segment)
                if resolved_key is None:
                    return None
                current = current.get(resolved_key)
            return current

        return None

    def _derive_utc_timestamp_component(self, variable_key: str, context: Dict[str, Any]) -> Any:
        """Derive timestamp subcomponents from request.utc-timestamp when possible."""
        utc_timestamp = self._get_context_value(context, 'request.utc-timestamp')
        if not utc_timestamp:
            return None

        try:
            timestamp_text = str(utc_timestamp)
            parsed = datetime.fromisoformat(timestamp_text.replace('Z', '+00:00'))
        except ValueError:
            return None

        if variable_key == 'request.utc-timestamp.month-of-year':
            return str(parsed.month)
        if variable_key == 'request.utc-timestamp.day-of-month':
            return str(parsed.day)
        if variable_key == 'request.utc-timestamp.day-of-week':
            return parsed.strftime('%A')
        if variable_key == 'request.utc-timestamp.time-of-day':
            return parsed.strftime('%H:%M:%SZ')
        return None

    def _resolve_condition_candidates(
        self,
        variable_key: str,
        statement: Dict[str, Any],
        api_name: str,
        permission_tokens: List[str],
        evaluation_context: Optional[Dict[str, Any]]
    ) -> Tuple[List[str], bool]:
        """Resolve runtime candidate values for one condition variable.

        Returns (candidates, missing_context_flag).
        """
        context = evaluation_context or {}

        if variable_key == 'request.operation':
            return [api_name], False

        if variable_key == 'request.permission':
            return self._to_string_candidates(permission_tokens), len(permission_tokens) == 0

        if variable_key == 'target.compartment.name':
            explicit = self._get_context_value(context, variable_key)
            if explicit is not None:
                return self._to_string_candidates(explicit), False

            scope = (statement.get('scope') or '').strip()
            if scope.lower().startswith('compartment '):
                return [scope.split(' ', 1)[1]], False
            return [], True

        if variable_key == 'target.compartment.id':
            value = self._get_context_value(context, variable_key)
            candidates = self._to_string_candidates(value)
            return candidates, len(candidates) == 0

        if variable_key == 'target.bucket.name':
            value = self._get_context_value(context, variable_key)
            candidates = self._to_string_candidates(value)
            return candidates, len(candidates) == 0

        if variable_key.startswith('request.utc-timestamp.'):
            explicit = self._get_context_value(context, variable_key)
            if explicit is not None:
                return self._to_string_candidates(explicit), False

            derived = self._derive_utc_timestamp_component(variable_key, context)
            if derived is not None:
                return self._to_string_candidates(derived), False
            return [], True

        for prefix in self._SUPPORTED_WHERE_PREFIXES:
            if variable_key.startswith(prefix):
                suffix = variable_key[len(prefix):]
                base_key = prefix[:-1]
                value = self._get_tag_context_value(context, base_key, suffix)
                candidates = self._to_string_candidates(value)
                return candidates, len(candidates) == 0

        value = self._get_context_value(context, variable_key)
        candidates = self._to_string_candidates(value)
        return candidates, len(candidates) == 0

    @staticmethod
    def _condition_value_display(value: Dict[str, Any]) -> str:
        value_type = value.get('type')
        raw_value = value.get('value')
        if value_type == 'pattern':
            return f"/{raw_value}/"
        if value_type == 'boolean':
            return str(raw_value).lower()
        return f"'{raw_value}'"

    @staticmethod
    def _condition_variable_label(variable_key: str) -> str:
        labels = {
            'request.principal.id': 'requesting principal OCID',
            'request.principal.type': 'requesting principal type',
            'request.user.id': 'requesting user OCID',
            'request.user.name': 'requesting user name',
            'request.groups.id': 'requesting user group OCIDs',
            'request.permission': 'requested permission token',
            'request.operation': 'requested API operation',
            'request.networksource.name': 'request network source name',
            'request.region': 'request region',
            'request.ad': 'request availability domain',
            'target.compartment.name': 'target compartment name',
            'target.compartment.id': 'target compartment OCID',
            'target.bucket.name': 'target bucket name',
        }
        return labels.get(variable_key, variable_key)

    def _build_condition_interpretation(self, parsed_where: Dict[str, Any]) -> Dict[str, Any]:
        """Build a human-readable interpretation of WHERE conditions."""
        mode = parsed_where.get('mode', 'single')
        if parsed_where.get('has_nested_groups'):
            logic = 'Nested condition groups are used; each all{} is logical AND and each any{} is logical OR.'
        elif mode == 'all':
            logic = 'All listed conditions must be true (logical AND).'
        elif mode == 'any':
            logic = 'Any listed condition can be true (logical OR).'
        else:
            logic = 'Single condition must be true.'

        condition_phrases = []
        scoping_constraints = []
        summary_fragments = []

        for condition in parsed_where.get('conditions', []):
            variable_key = self._normalize_where_variable(condition.get('variable', ''))
            operator = condition.get('operator', '=')
            value_display = self._condition_value_display(condition.get('value', {}))
            label = self._condition_variable_label(variable_key)
            raw_clause = (condition.get('raw') or '').strip()
            supported_variable = condition.get('supported_variable', True)

            if operator == '=':
                phrase = f"{label} must match {value_display}."
            else:
                phrase = f"{label} must not match {value_display}."
            condition_phrases.append(phrase)

            if supported_variable:
                summary_fragments.append(phrase)
            else:
                fallback_text = raw_clause or f"{condition.get('variable', variable_key)} {operator} {value_display}"
                if fallback_text.endswith('.'):
                    summary_fragments.append(f"Fallback condition retained as written: {fallback_text}")
                else:
                    summary_fragments.append(f"Fallback condition retained as written: {fallback_text}.")

            if operator == '=' and variable_key == 'request.principal.id':
                scoping_constraints.append(
                    f"Access is restricted to requests from principal OCID {value_display}."
                )
            elif operator == '=' and variable_key == 'target.bucket.name':
                scoping_constraints.append(
                    f"Access is restricted to bucket name {value_display}."
                )
            elif operator == '=' and variable_key == 'target.compartment.name':
                scoping_constraints.append(
                    f"Access is restricted to target compartment {value_display}."
                )
            elif operator == '=' and variable_key == 'request.networksource.name':
                scoping_constraints.append(
                    f"Access is restricted to requests originating from IAM network source {value_display}."
                )

        for invalid_clause in parsed_where.get('invalid_conditions', []):
            invalid_text = (invalid_clause or '').strip()
            if not invalid_text:
                continue
            if invalid_text.endswith('.'):
                summary_fragments.append(f"Fallback condition retained as written: {invalid_text}")
            else:
                summary_fragments.append(f"Fallback condition retained as written: {invalid_text}.")

        summary = None
        if summary_fragments:
            summary = f"{logic} {' '.join(summary_fragments)}"

        return {
            'logic': logic,
            'condition_phrases': condition_phrases,
            'scoping_constraints': scoping_constraints,
            'summary': summary,
        }

    def _parse_where_clause(self, where_clause: Optional[str]) -> Optional[Dict[str, Any]]:
        """Parse OCI WHERE clause into structured conditions with support metadata."""
        if not where_clause:
            return None

        raw_clause = where_clause.strip()
        if not raw_clause:
            return None

        parsed_expression = self._parse_where_expression(raw_clause)
        root_node = parsed_expression.get('node')
        parsed_conditions = parsed_expression.get('conditions', [])
        unknown_variables = parsed_expression.get('unknown_variables', set())
        invalid_conditions = parsed_expression.get('invalid_conditions', [])

        if root_node and root_node.get('type') == 'group':
            mode = root_node.get('mode', 'single')
        else:
            mode = 'single'

        can_evaluate = (
            root_node is not None
            and
            len(parsed_conditions) > 0
            and len(invalid_conditions) == 0
            and len(unknown_variables) == 0
        )

        return {
            'raw_clause': raw_clause,
            'mode': mode,
            'expression_tree': root_node,
            'has_nested_groups': parsed_expression.get('has_nested_groups', False),
            'conditions': parsed_conditions,
            'unknown_variables': sorted(unknown_variables),
            'invalid_conditions': invalid_conditions,
            'supported_condition_count': sum(1 for c in parsed_conditions if c['supported_variable']),
            'total_condition_count': len(parsed_conditions),
            'can_evaluate': can_evaluate,
            'fallback_to_raw_clause': not can_evaluate,
            'interpretation': self._build_condition_interpretation({
                'mode': mode,
                'has_nested_groups': parsed_expression.get('has_nested_groups', False),
                'conditions': parsed_conditions,
                'invalid_conditions': invalid_conditions,
            }),
        }

    def _extract_condition_principals(self, where_clause: Optional[str]) -> List[str]:
        """Extract explicit request.principal.id equality values from WHERE clause."""
        parsed_where = self._parse_where_clause(where_clause)
        if not parsed_where:
            return []

        principals = []
        for condition in parsed_where.get('conditions', []):
            variable_key = self._normalize_where_variable(condition.get('variable', ''))
            if variable_key != 'request.principal.id':
                continue
            if condition.get('operator') != '=':
                continue

            value = condition.get('value', {})
            if value.get('type') != 'string':
                continue

            principal_value = str(value.get('value', '')).strip()
            if principal_value:
                principals.append(principal_value)

        return sorted(set(principals))

    def _get_effective_principals(self, statement: Dict[str, Any]) -> List[str]:
        """Return principal labels used for principal-pivoted views."""
        condition_principals = statement.get('condition_principals')
        if isinstance(condition_principals, list):
            resolved = sorted({str(p).strip() for p in condition_principals if str(p).strip()})
            if resolved:
                return resolved

        parsed = self._extract_condition_principals(statement.get('where_clause'))
        if parsed:
            return parsed

        principal = str(statement.get('principal', '')).strip()
        return [principal] if principal else []

    def _evaluate_where_clause_for_api(
        self,
        parsed_where: Dict[str, Any],
        statement: Dict[str, Any],
        api_name: str,
        permission_tokens: List[str],
        evaluation_context: Optional[Dict[str, Any]]
    ) -> Tuple[bool, set]:
        """Evaluate parsed where-clause conditions against one candidate API operation."""
        if not parsed_where.get('can_evaluate'):
            return True, set()

        expression_tree = parsed_where.get('expression_tree')
        if expression_tree:
            return self._evaluate_where_expression_node(
                expression_tree,
                statement,
                api_name,
                permission_tokens,
                evaluation_context,
            )

        condition_results = []
        missing_context_variables = set()
        for condition in parsed_where.get('conditions', []):
            variable = self._normalize_where_variable(condition.get('variable', ''))
            operator = condition.get('operator')
            clause_value = condition.get('value', {})

            candidates, missing_context = self._resolve_condition_candidates(
                variable,
                statement,
                api_name,
                permission_tokens,
                evaluation_context
            )
            if missing_context:
                missing_context_variables.add(condition.get('variable', ''))
                continue

            if operator == '=':
                matches = any(self._match_condition_value(candidate, clause_value) for candidate in candidates)
            else:
                matches = all(not self._match_condition_value(candidate, clause_value) for candidate in candidates)

            condition_results.append(matches)

        mode = parsed_where.get('mode', 'single')
        if mode == 'any':
            return any(condition_results), missing_context_variables
        return all(condition_results), missing_context_variables

    def _evaluate_where_expression_node(
        self,
        node: Dict[str, Any],
        statement: Dict[str, Any],
        api_name: str,
        permission_tokens: List[str],
        evaluation_context: Optional[Dict[str, Any]]
    ) -> Tuple[bool, set]:
        """Evaluate one node in a parsed where-expression tree."""
        node_type = (node or {}).get('type')
        if node_type == 'condition':
            condition = node.get('condition', {})
            variable = self._normalize_where_variable(condition.get('variable', ''))
            operator = condition.get('operator')
            clause_value = condition.get('value', {})

            candidates, missing_context = self._resolve_condition_candidates(
                variable,
                statement,
                api_name,
                permission_tokens,
                evaluation_context
            )
            if missing_context:
                return True, {condition.get('variable', '')}

            if operator == '=':
                return any(self._match_condition_value(candidate, clause_value) for candidate in candidates), set()

            return all(not self._match_condition_value(candidate, clause_value) for candidate in candidates), set()

        if node_type == 'group':
            mode = node.get('mode', 'single')
            child_results = []
            missing_context_variables = set()
            for child in node.get('children', []):
                child_result, child_missing = self._evaluate_where_expression_node(
                    child,
                    statement,
                    api_name,
                    permission_tokens,
                    evaluation_context,
                )
                child_results.append(child_result)
                missing_context_variables.update(child_missing)

            if mode == 'any':
                return any(child_results), missing_context_variables
            return all(child_results), missing_context_variables

        return True, set()

    def _apply_where_clause_filters(
        self,
        statement: Dict[str, Any],
        where_clause: Optional[str],
        allowed_apis: List[str],
        api_permission_tokens: Dict[str, List[str]],
        evaluation_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[str], Optional[Dict[str, Any]]]:
        """Apply supported where-clause filters to API list and return analysis metadata."""
        parsed_where = self._parse_where_clause(where_clause)
        if not parsed_where:
            return allowed_apis, None

        parsed_where['api_count_before_filter'] = len(allowed_apis)

        if not parsed_where.get('can_evaluate'):
            parsed_where['api_count_after_filter'] = len(allowed_apis)
            parsed_where['filter_applied'] = False
            return allowed_apis, parsed_where

        filtered_apis = []
        missing_context_variables = set()
        for api_name in allowed_apis:
            permission_tokens = api_permission_tokens.get(api_name, [])
            allowed, unresolved = self._evaluate_where_clause_for_api(
                parsed_where,
                statement,
                api_name,
                permission_tokens,
                evaluation_context,
            )
            missing_context_variables.update(unresolved)
            if allowed:
                filtered_apis.append(api_name)

        if missing_context_variables:
            parsed_where['missing_context_variables'] = sorted({
                v for v in missing_context_variables if v
            })
            parsed_where['api_count_after_filter'] = len(allowed_apis)
            parsed_where['filter_applied'] = False
            parsed_where['can_evaluate_with_context'] = False
            parsed_where['fallback_to_raw_clause'] = True
            return allowed_apis, parsed_where

        parsed_where['api_count_after_filter'] = len(filtered_apis)
        parsed_where['filter_applied'] = True
        parsed_where['can_evaluate_with_context'] = True
        parsed_where['missing_context_variables'] = []
        return filtered_apis, parsed_where

    def _parse_policy_statement_line(self, stmt: str, statement_index: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Parse one OCI policy line, including cross-tenancy syntax."""
        line = (stmt or '').strip()
        if not line:
            return None

        define_match = self._DEFINE_PATTERN.match(line)
        if define_match:
            subject_type, alias, ocid = define_match.groups()
            return {
                'effect': 'Define',
                'statement_type': 'define',
                'define_subject_type': subject_type.lower(),
                'define_alias': alias,
                'define_ocid': ocid,
                'statement_text': line,
                'statement_index': statement_index,
            }

        allow_deny_match = self._ALLOW_DENY_PATTERN.match(line)
        if allow_deny_match:
            effect, principal, action_raw, resource, scope, where_clause = allow_deny_match.groups()
            action = self._parse_action(action_raw)
            return {
                'effect': effect.capitalize(),
                'statement_type': 'action',
                'principal': principal,
                'permission': action['permission'],
                'permission_set': action['permission_set'],
                'is_permission_set': action['is_permission_set'],
                'resource': resource,
                'scope': scope or 'tenancy',
                'where_clause': where_clause.strip() if where_clause else None,
                'condition_principals': self._extract_condition_principals(where_clause),
                'statement_text': line,
                'statement_index': statement_index,
            }

        endorse_admit_match = self._ENDORSE_ADMIT_PATTERN.match(line)
        if endorse_admit_match:
            effect, principal, source_tenancy_alias, action_raw, resource, scope, where_clause = endorse_admit_match.groups()
            action = self._parse_action(action_raw)

            normalized_principal = principal
            if source_tenancy_alias:
                normalized_principal = f"{principal} of tenancy {source_tenancy_alias}"

            return {
                'effect': effect.capitalize(),
                'statement_type': 'action',
                'principal': normalized_principal,
                'source_tenancy_alias': source_tenancy_alias,
                'permission': action['permission'],
                'permission_set': action['permission_set'],
                'is_permission_set': action['is_permission_set'],
                'resource': resource,
                'scope': scope or 'tenancy',
                'where_clause': where_clause.strip() if where_clause else None,
                'condition_principals': self._extract_condition_principals(where_clause),
                'statement_text': line,
                'statement_index': statement_index,
            }

        return None
    
    def _load_oci_permissions(self) -> Dict[str, List[str]]:
        """Load OCI service permissions."""
        # This is a simplified set - in production, this would be comprehensive
        return {
            'compute': ['compute.instances.manage', 'compute.instances.read'],
            'database': ['database.databases.manage', 'database.databases.read'],
            'storage': ['storage.buckets.manage', 'storage.buckets.read'],
            'network': ['network.networks.manage', 'network.networks.read'],
            'iam': ['iam.policies.manage', 'iam.policies.read'],
        }
    
    def add_policy(self, policy_text: str) -> None:
        """Add a policy from text."""
        statements = [line.strip() for line in policy_text.split('\n') if line.strip()]
        
        if not statements:
            raise ValueError("Policy must contain at least one statement")
        
        for i, stmt in enumerate(statements):
            parsed = self._parse_policy_statement_line(stmt, statement_index=i + 1)
            if not parsed:
                raise ValueError(f"Invalid statement syntax in line {i+1}: {stmt}")
        
        # If validation passes, add the policy
        self.policies.append(policy_text)
    
    def parse_policy_statements(self, policy_text: str) -> List[Dict]:
        """Parse policy text into structured statements with WHERE clauses."""
        statements = [line.strip() for line in policy_text.split('\n') if line.strip()]

        parsed_statements = []
        for idx, stmt in enumerate(statements):
            parsed = self._parse_policy_statement_line(stmt, statement_index=idx + 1)
            if parsed and parsed.get('statement_type') == 'action':
                parsed_statements.append(parsed)
        
        return parsed_statements
    
    def parse_compartment_hierarchy(self, input_text: str) -> List[Dict]:
        """Parse hierarchical compartment and policy input."""
        lines = [line.strip() for line in input_text.split('\n') if line.strip()]
        
        compartments = {}
        current_compartment = None
        current_policy = None
        
        for line in lines:
            if line.startswith('+ COMPARTMENT:'):
                # New compartment
                compartment_id = line.replace('+ COMPARTMENT:', '').strip()
                current_compartment = compartment_id
                compartments[compartment_id] = {'policies': {}}
                current_policy = None
            elif line.startswith('++Policy:'):
                # New policy within compartment
                if current_compartment is None:
                    raise ValueError("Policy must be within a compartment")
                policy_id = line.replace('++Policy:', '').strip()
                current_policy = policy_id
                compartments[current_compartment]['policies'][policy_id] = {'statements': []}
            elif current_compartment and current_policy:
                # This should be a statement
                parsed = self._parse_policy_statement_line(line)
                if not parsed:
                    raise ValueError(f"Invalid statement syntax: {line}")

                # Define statements are valid for cross-tenancy syntax but are not actionable.
                if parsed.get('statement_type') != 'action':
                    continue

                compartments[current_compartment]['policies'][current_policy]['statements'].append(parsed)
        
        # Flatten into access matrix with compartment and policy info
        access_matrix = []
        for compartment_id, compartment_data in compartments.items():
            for policy_id, policy_data in compartment_data['policies'].items():
                for stmt_idx, stmt in enumerate(policy_data['statements']):
                    access_matrix.append({
                        'compartment': compartment_id,
                        'policy_id': policy_id,
                        'statement_index': stmt_idx + 1,
                        'effect': stmt['effect'],
                        'principal': stmt['principal'],
                        'condition_principals': stmt.get('condition_principals', []),
                        'permission': stmt['permission'],
                        'permission_set': stmt.get('permission_set', []),
                        'is_permission_set': stmt.get('is_permission_set', False),
                        'resource': stmt['resource'],
                        'scope': stmt['scope'],
                        'where_clause': stmt['where_clause'],
                        'statement_text': stmt['statement_text']
                    })
        
        return access_matrix
    
    def evaluate_access(self, principal: str, action: str, resource: str,
                       conditions: Optional[Dict] = None) -> PolicyEvaluationResult:
        """
        Evaluate if a principal can perform an action on a resource.
        
        Args:
            principal: The principal (user, group, service)
            action: The action to perform (e.g., 'compute.instances.read')
            resource: The resource (e.g., 'compute/instances/*')
            conditions: Optional conditions (time-based, IP-based, etc.)
        
        Returns:
            PolicyEvaluationResult with evaluation details
        """
        audit_trail = [f"Evaluating access for {principal} to {action} on {resource}"]
        matched_statements = []
        
        # Simplified evaluation logic
        # In production: parse policies, evaluate with deny-override principle
        
        # For demo, assume access is granted
        return PolicyEvaluationResult(
            allowed=True,
            matched_statements=[],
            reason="Access granted (simulated evaluation)",
            audit_trail=audit_trail
        )
        
        # Check resource pattern matching
        audit_trail.append(f"Checking resource pattern: {resource}")
        
        # Return default deny for now
        return PolicyEvaluationResult(
            allowed=False,
            matched_statements=matched_statements,
            reason="No allow policy found",
            audit_trail=audit_trail
        )
    
    def check_public_access(self, policy_text: str) -> List[Dict]:
        """Detect if policy allows public/external access."""
        issues = []
        
        # Check for wildcards and public principals
        if 'Principal: "*"' in policy_text or 'principal: "*"' in policy_text:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Public Principal',
                'description': 'Policy allows access from any principal',
                'recommendation': 'Restrict principal to specific users or groups'
            })
        
        return issues
    
    def get_least_privilege_suggestion(self, current_policy: str) -> Dict:
        """Suggest a more restrictive policy."""
        suggestion = {
            'current_policy': current_policy,
            'suggested_policy': None,
            'changes': [],
            'rationale': []
        }
        
        # Analyze current policy and suggest improvements
        # This is a placeholder - real logic would be more sophisticated
        
        return suggestion
    
    def validate_conditional_logic(self, conditions: Dict) -> Tuple[bool, List[str]]:
        """Validate conditional access logic."""
        errors = []
        
        # Check time-based conditions
        if 'time_based' in conditions:
            try:
                start = datetime.fromisoformat(conditions['time_based']['start'])
                end = datetime.fromisoformat(conditions['time_based']['end'])
                if start >= end:
                    errors.append("Time-based condition: start time must be before end time")
            except (KeyError, ValueError) as e:
                errors.append(f"Invalid time-based condition: {str(e)}")
        
        return len(errors) == 0, errors
    
    def get_allowed_apis_from_statements(
        self,
        policy_statements: List[Dict],
        evaluation_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Dict]:
        """
        Get all allowed APIs for policy statements with principal and resource details.
        
        Args:
            policy_statements: List of parsed policy statements
        
        Returns:
            List of access entries with APIs and metadata
        """
        from .resource_mapper import get_resource_mapper
        mapper = get_resource_mapper()
        
        access_apis = []

        def _statement_key(stmt: Dict) -> tuple:
            return (
                stmt.get('principal'),
                stmt.get('resource', '').strip(),
                stmt.get('scope'),
                stmt.get('compartment', 'Default')
            )

        def _deny_applies_to_statement(deny_stmt: Dict, allow_stmt: Dict) -> bool:
            if (deny_stmt.get('resource', '').strip() != allow_stmt.get('resource', '').strip()):
                return False

            deny_scope = (deny_stmt.get('scope') or 'tenancy').strip().lower()
            allow_scope = (allow_stmt.get('scope') or 'tenancy').strip().lower()

            # A tenancy-scoped Deny covers all compartments within it;
            # an explicit compartment-scoped Deny only applies to that compartment.
            if deny_scope != 'tenancy' and deny_scope != allow_scope:
                return False

            if deny_scope != 'tenancy':
                # Compartment-scoped Deny: compartments must match too
                if deny_stmt.get('compartment', 'Default') != allow_stmt.get('compartment', 'Default'):
                    return False

            deny_principal = (deny_stmt.get('principal') or '').strip().lower()
            allow_principal = (allow_stmt.get('principal') or '').strip().lower()

            if deny_principal == 'any-user':
                return True

            return deny_principal == allow_principal

        deny_entries = []
        for stmt in policy_statements:
            effect = stmt.get('effect', '').lower()
            if not effect.startswith('deny'):
                continue

            resource = stmt.get('resource', '').strip()
            principal = (stmt.get('principal') or '').strip().lower()
            permission_set = stmt.get('permission_set', [])
            permission = stmt.get('permission', '').lower() if stmt.get('permission') else ''

            if permission_set:
                denied_apis = mapper.get_apis_for_permission_set(resource, permission_set, effect='deny')
            else:
                denied_apis = mapper.get_denied_apis_for_resource(resource, permission)

            if denied_apis:
                deny_entries.append((stmt, set(denied_apis)))
        
        for stmt in policy_statements:
            if stmt.get('effect', '').lower().startswith('deny'):
                continue
            
            resource = stmt.get('resource', '').strip()
            permission_set = stmt.get('permission_set', [])
            permission = stmt.get('permission', '').lower() if stmt.get('permission') else ''
            
            # Get APIs for this resource and permission
            if permission_set:
                apis = set(mapper.get_apis_for_permission_set(resource, permission_set, effect='allow'))
            else:
                apis = set(mapper.get_apis_for_resource(resource, permission))
            denied_apis = set()
            for deny_stmt, deny_stmt_apis in deny_entries:
                if _deny_applies_to_statement(deny_stmt, stmt):
                    denied_apis.update(deny_stmt_apis)
            effective_apis = sorted(apis - denied_apis)
            
            if effective_apis:
                api_permission_tokens = mapper.get_permission_tokens_for_apis(resource, effective_apis)
                effective_apis, condition_analysis = self._apply_where_clause_filters(
                    stmt,
                    stmt.get('where_clause'),
                    effective_apis,
                    api_permission_tokens,
                    evaluation_context=evaluation_context,
                )
                api_permission_tokens = {
                    api_name: api_permission_tokens[api_name]
                    for api_name in effective_apis
                    if api_name in api_permission_tokens
                }
                statement_permission_tokens = sorted({
                    token
                    for tokens in api_permission_tokens.values()
                    for token in tokens
                })

                if not effective_apis:
                    continue

                effective_principals = self._get_effective_principals(stmt)
                if not effective_principals:
                    effective_principals = [stmt.get('principal')]

                for effective_principal in effective_principals:
                    access_apis.append({
                        'compartment': stmt.get('compartment', 'Default'),
                        'policy_id': stmt.get('policy_id', 'Default Policy'),
                        'statement_index': stmt.get('statement_index'),
                        'effect': stmt.get('effect'),
                        'principal': effective_principal,
                        'source_principal': stmt.get('principal'),
                        'condition_principals': stmt.get('condition_principals', []),
                        'permission': stmt.get('permission'),
                        'resource': resource,
                        'scope': stmt.get('scope'),
                        'where_clause': stmt.get('where_clause'),
                        'condition_analysis': condition_analysis,
                        'statement_text': stmt.get('statement_text'),
                        'allowed_apis': effective_apis,
                        'api_permission_tokens': api_permission_tokens,
                        'permission_tokens': statement_permission_tokens,
                        'api_count': len(effective_apis)
                    })
        
        return access_apis
