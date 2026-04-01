"""Resource to API operation mapper for OCI IAM policies."""

import json
import os
from typing import Dict, List, Optional, Set
from pathlib import Path


class ResourceAPIMapper:
    """Maps OCI IAM policy resources to their allowed API operations."""
    
    def __init__(self):
        """Initialize the mapper by loading all resource mappings."""
        self.mappings = {}
        self._load_mappings()
    
    def _load_mappings(self) -> None:
        """Load all resource mapping JSON files from the data directory."""
        # Always rebuild from disk so hot-added mapping files are visible.
        self.mappings = {}
        mappings_dir = Path(__file__).parent.parent / 'data' / 'resource_mappings'
        
        if not mappings_dir.exists():
            raise ValueError(f"Resource mappings directory not found: {mappings_dir}")
        
        for json_file in mappings_dir.glob('*.json'):
            service_name = json_file.stem
            try:
                with open(json_file, 'r') as f:
                    service_data = json.load(f)
                    self.mappings[service_name] = service_data
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Failed to load {json_file}: {e}")

    def _resource_exists_in_loaded_mappings(self, resource: str) -> bool:
        """Check if a resource exists in currently loaded mappings."""
        for service_data in self.mappings.values():
            for resource_obj in service_data.get('resources', []):
                if resource_obj.get('resource_family') == resource:
                    return True
        return False

    def _ensure_resource_loaded(self, resource: str) -> bool:
        """Ensure mappings include a resource after refreshing mapping files from disk."""
        # Mapping files are frequently edited during simulator tuning, so reload before lookup.
        self._load_mappings()
        return self._resource_exists_in_loaded_mappings(resource)

    def _resource_permission_prefix(self, resource: str) -> str:
        """Infer permission prefix from resource family (e.g., drgs -> DRG)."""
        r = (resource or "").strip().lower().replace("-family", "")
        r = r.replace("-", "_")

        # Keep known short names intact.
        preserve_trailing_s = {"dns", "fss"}

        if r.endswith("ies") and len(r) > 3:
            r = r[:-3] + "y"
        elif r.endswith("s") and len(r) > 3 and not r.endswith("ss") and r not in preserve_trailing_s:
            r = r[:-1]

        return r.upper()

    def _find_resource_mapping(self, resource: str) -> Optional[Dict]:
        """Return the resource mapping object for a resource family if present."""
        resource_name = (resource or '').strip()
        if not resource_name:
            return None

        for service_data in self.mappings.values():
            for resource_obj in service_data.get('resources', []):
                if resource_obj.get('resource_family') == resource_name:
                    return resource_obj
        return None

    def _operation_level_for_api(self, api_name: str) -> str:
        """Infer canonical permission level for an API operation name."""
        name = (api_name or "").strip()

        read_prefixes = (
            "Get", "List", "Head", "Fetch", "Read", "Describe", "Summarize", "Search"
        )
        create_prefixes = (
            "Create", "Initiate", "Start", "Generate", "Launch", "Provision"
        )
        update_prefixes = (
            "Update", "Patch", "Put", "Set", "Apply", "Enable", "Disable", "Attach",
            "Detach", "Connect", "Disconnect", "Upload", "Complete", "Copy", "Rename",
            "Move", "Assign", "Unassign", "Change", "Add", "Remove"
        )
        delete_prefixes = (
            "Delete", "Cancel", "Abort", "Terminate", "Stop", "Revoke"
        )

        if name.startswith(read_prefixes):
            return "READ"
        if name.startswith(create_prefixes):
            return "CREATE"
        if name.startswith(delete_prefixes):
            return "DELETE"
        if name.startswith(update_prefixes):
            return "UPDATE"

        return "USE"

    def infer_permission_token_for_api(self, resource: str, api_name: str) -> str:
        """Infer permission token controlling a specific API operation."""
        prefix = self._resource_permission_prefix(resource)
        level = self._operation_level_for_api(api_name)
        return f"{prefix}_{level}"

    def get_permission_tokens_for_apis(self, resource: str, apis: List[str]) -> Dict[str, List[str]]:
        """Build API -> permission token mapping for a list of operations."""
        self._ensure_resource_loaded(resource)
        resource_mapping = self._find_resource_mapping(resource)
        explicit_mapping = {}
        if resource_mapping:
            explicit_mapping = resource_mapping.get('api_permission_tokens', {}) or {}

        mapping = {}
        for api in apis:
            explicit_tokens = explicit_mapping.get(api)
            if isinstance(explicit_tokens, list) and explicit_tokens:
                mapping[api] = sorted({str(token).strip() for token in explicit_tokens if str(token).strip()})
                continue

            if isinstance(explicit_tokens, str) and explicit_tokens.strip():
                mapping[api] = [explicit_tokens.strip()]
                continue

            token = self.infer_permission_token_for_api(resource, api)
            mapping[api] = [token]
        return mapping
    
    def get_apis_for_resource(self, resource: str, verb: str) -> List[str]:
        """
        Get all API operations allowed for a resource with a given verb.
        
        Args:
            resource: Resource name (e.g., 'instances', 'buckets', 'drgs')
            verb: Permission verb (manage, use, read, inspect)
        
        Returns:
            List of API operations allowed
        """
        verb = verb.lower()

        # Handle newly added mapping files in long-running backend processes.
        self._ensure_resource_loaded(resource)

        # OCI metaverbs are cumulative for allow statements.
        # manage includes use/read/inspect, use includes read/inspect, read includes inspect.
        verb_hierarchy = {
            "inspect": ["inspect"],
            "read": ["inspect", "read"],
            "use": ["inspect", "read", "use"],
            "manage": ["inspect", "read", "use", "manage"],
        }
        target_verbs = verb_hierarchy.get(verb, [verb])
        
        def resolve_apis(target_resource: str, visited: Set[str]) -> Set[str]:
            if target_resource in visited:
                return set()

            visited.add(target_resource)

            # Search through all services to find the resource
            for service_data in self.mappings.values():
                for resource_obj in service_data.get('resources', []):
                    if resource_obj.get('resource_family') == target_resource:
                        direct_apis = set()
                        verbs_map = resource_obj.get('verbs', {})
                        for target_verb in target_verbs:
                            direct_apis.update(verbs_map.get(target_verb, []))

                        # Family entries can aggregate APIs from included child resources.
                        for child in resource_obj.get('includes', []):
                            direct_apis.update(resolve_apis(child, visited))

                        return direct_apis

            return set()

        apis = resolve_apis(resource, set())
        if apis:
            return sorted(apis)
        
        # If not found, return empty list
        return []

    def _get_all_mapped_apis_for_resource(self, resource: str) -> Set[str]:
        """Return union of all mapped APIs across inspect/read/use/manage for a resource."""
        all_apis = set()
        for verb in ("inspect", "read", "use", "manage"):
            all_apis.update(self.get_apis_for_resource(resource, verb))
        return all_apis

    def _resolve_permission_token_allow(self, resource: str, token: str) -> Set[str]:
        """Resolve a single permission-set token for allow statements."""
        token = token.strip()
        if not token:
            return set()

        # If token already matches an API operation in mappings, allow it directly.
        all_apis = self._get_all_mapped_apis_for_resource(resource)
        if token in all_apis:
            return {token}

        # Heuristic for metaverb-style permission tokens (e.g., BUCKET_INSPECT).
        upper = token.upper()
        for suffix in ("_INSPECT", "_READ", "_USE", "_MANAGE"):
            if upper.endswith(suffix):
                verb = suffix.replace("_", "").lower()
                return set(self.get_apis_for_resource(resource, verb))

        return set()

    def _resolve_permission_token_deny(self, resource: str, token: str) -> Set[str]:
        """Resolve a single permission-set token for deny statements."""
        token = token.strip()
        if not token:
            return set()

        all_apis = self._get_all_mapped_apis_for_resource(resource)
        if token in all_apis:
            return {token}

        upper = token.upper()
        for suffix in ("_INSPECT", "_READ", "_USE", "_MANAGE"):
            if upper.endswith(suffix):
                verb = suffix.replace("_", "").lower()
                return set(self.get_denied_apis_for_resource(resource, verb))

        return set()

    def get_apis_for_permission_set(self, resource: str, permissions: List[str], effect: str = "allow") -> List[str]:
        """
        Resolve OCI permission-set syntax tokens to API operations.

        Args:
            resource: Resource family from statement.
            permissions: Tokens from `{ ... }` permission set.
            effect: allow or deny.
        """
        resolved = set()
        effect = (effect or "allow").lower()

        for token in permissions:
            if effect.startswith("deny"):
                resolved.update(self._resolve_permission_token_deny(resource, token))
            else:
                resolved.update(self._resolve_permission_token_allow(resource, token))

        return sorted(resolved)

    def get_denied_apis_for_resource(self, resource: str, verb: str) -> List[str]:
        """
        Get API operations denied for a resource with a given deny verb.

        OCI deny metaverb semantics target higher permission levels:
        - deny inspect: deny inspect + read + use + manage APIs (all levels)
        - deny read:    deny read + use + manage APIs
        - deny use:     deny use + manage APIs
        - deny manage:  deny manage-only APIs

        This differs from allow semantics where each verb is cumulative downward.
        For deny we compute and remove incremental permission bands at or above
        the requested deny verb.
        """
        verb = verb.lower()
        if verb not in {"inspect", "read", "use", "manage"}:
            return []

        inspect_apis = set(self.get_apis_for_resource(resource, "inspect"))
        read_apis = set(self.get_apis_for_resource(resource, "read"))
        use_apis = set(self.get_apis_for_resource(resource, "use"))
        manage_apis = set(self.get_apis_for_resource(resource, "manage"))

        # Derive incremental permission bands from cumulative allow mappings.
        read_only_band = read_apis - inspect_apis
        use_only_band = use_apis - read_apis
        manage_only_band = manage_apis - use_apis

        if verb == "inspect":
            denied = inspect_apis | read_only_band | use_only_band | manage_only_band
        elif verb == "read":
            denied = read_only_band | use_only_band | manage_only_band
        elif verb == "use":
            denied = use_only_band | manage_only_band
        else:
            denied = manage_only_band

        return sorted(denied)
    
    def get_all_apis_for_verb(self, verb: str) -> Dict[str, List[str]]:
        """
        Get all APIs for a given verb across all resources.
        
        Args:
            verb: Permission verb (manage, use, read, inspect)
        
        Returns:
            Dictionary mapping resource families to their allowed APIs
        """
        verb = verb.lower()
        result = {}
        
        for service_name, service_data in self.mappings.items():
            for resource_obj in service_data.get('resources', []):
                resource_family = resource_obj['resource_family']
                apis = resource_obj.get('verbs', {}).get(verb, [])
                if apis:
                    result[resource_family] = apis
        
        return result
    
    def get_apis_for_policy_statement(self, effect: str, permission: str, 
                                      resource: str) -> List[str]:
        """
        Get allowed APIs for a policy statement.
        
        Args:
            effect: Allow or Deny
            permission: Permission verb (manage, use, read, inspect)
            resource: Resource name (e.g., 'instances', 'buckets')
        
        Returns:
            List of allowed API operations (empty list if Deny)
        """
        if effect.lower().startswith('deny'):
            return self.get_denied_apis_for_resource(resource, permission)

        return self.get_apis_for_resource(resource, permission)
    
    def get_service_info(self, service: str) -> Optional[Dict]:
        """
        Get information about a service.
        
        Args:
            service: Service name (compute, storage, network, database)
        
        Returns:
            Service information or None if not found
        """
        return self.mappings.get(service)
    
    def list_services(self) -> List[str]:
        """List all available services with mappings."""
        return list(self.mappings.keys())
    
    def list_resources_for_service(self, service: str) -> List[Dict]:
        """
        List all resources for a service.
        
        Args:
            service: Service name
        
        Returns:
            List of resource objects for the service
        """
        service_data = self.mappings.get(service)
        if not service_data:
            return []
        
        return service_data.get('resources', [])
    
    def get_principal_allowed_apis(self, policy_statements: List[Dict]) -> Dict[str, Set[str]]:
        """
        Get all allowed APIs for a principal based on policy statements.
        
        Args:
            policy_statements: List of parsed policy statements (from policy_engine)
        
        Returns:
            Dictionary mapping resource families to sets of allowed APIs
        """
        allowed_apis = {}
        denied_apis = {}

        for stmt in policy_statements:
            resource = stmt.get('resource', '').strip()
            permission = stmt.get('permission', '').lower() if stmt.get('permission') else ''
            permission_set = stmt.get('permission_set', [])
            effect = stmt.get('effect', '').lower()

            if effect.startswith('deny'):
                if permission_set:
                    apis = self.get_apis_for_permission_set(resource, permission_set, effect='deny')
                else:
                    apis = self.get_denied_apis_for_resource(resource, permission)
                if apis:
                    denied_apis.setdefault(resource, set()).update(apis)
                continue

            if permission_set:
                apis = self.get_apis_for_permission_set(resource, permission_set, effect='allow')
            else:
                apis = self.get_apis_for_resource(resource, permission)
            if apis:
                allowed_apis.setdefault(resource, set()).update(apis)

        for resource, denied in denied_apis.items():
            if resource in allowed_apis:
                allowed_apis[resource] = allowed_apis[resource] - denied
        
        # Convert sets to sorted lists for JSON serialization
        return {k: sorted(list(v)) for k, v in allowed_apis.items()}
    
    def validate_resource_exists(self, resource: str) -> bool:
        """Check if a resource exists in the mappings."""
        return self._ensure_resource_loaded(resource)


# Singleton instance
_mapper_instance = None


def get_resource_mapper() -> ResourceAPIMapper:
    """Get the singleton ResourceAPIMapper instance."""
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = ResourceAPIMapper()
    return _mapper_instance
