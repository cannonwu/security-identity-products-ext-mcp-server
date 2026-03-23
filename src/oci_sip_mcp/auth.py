"""OCI authentication helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import oci

from .config import ServerConfig
from .errors import ConfigurationError


class OCIAuthFactory:
    """Build OCI config and signer objects."""

    def __init__(self, settings: ServerConfig):
        self.settings = settings

    def build(self) -> Tuple[Dict[str, Any], Optional[Any]]:
        if self.settings.auth_mode == "config":
            kwargs: Dict[str, Any] = {"profile_name": self.settings.profile}
            if self.settings.config_file:
                kwargs["file_location"] = self.settings.config_file
            config = oci.config.from_file(**kwargs)
            if self.settings.region:
                config["region"] = self.settings.region
            return config, None

        if self.settings.auth_mode == "instance_principal":
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config: Dict[str, Any] = {"tenancy": signer.tenancy_id}
            config["region"] = self.settings.region or signer.region
            return config, signer

        if self.settings.auth_mode == "resource_principal":
            signer = oci.auth.signers.get_resource_principals_signer()
            config: Dict[str, Any] = {}
            signer_tenancy_id = getattr(signer, "tenancy_id", None)
            if signer_tenancy_id:
                config["tenancy"] = signer_tenancy_id
            signer_region = getattr(signer, "region", None)
            if self.settings.region or signer_region:
                config["region"] = self.settings.region or signer_region
            return config, signer

        raise ConfigurationError("Unsupported auth mode: {0}".format(self.settings.auth_mode))
