from unittest.mock import MagicMock, patch

from oci_sip_mcp.auth import OCIAuthFactory
from oci_sip_mcp.config import ServerConfig


def test_instance_principal_build_sets_tenancy_and_region_from_signer():
    signer = MagicMock()
    signer.tenancy_id = "ocid1.tenancy.oc1..example"
    signer.region = "us-phoenix-1"

    with patch("oci_sip_mcp.auth.oci.auth.signers.InstancePrincipalsSecurityTokenSigner", return_value=signer):
        config, built_signer = OCIAuthFactory(ServerConfig(auth_mode="instance_principal")).build()

    assert built_signer is signer
    assert config == {"tenancy": "ocid1.tenancy.oc1..example", "region": "us-phoenix-1"}


def test_instance_principal_build_preserves_explicit_region_override():
    signer = MagicMock()
    signer.tenancy_id = "ocid1.tenancy.oc1..example"
    signer.region = "us-phoenix-1"

    with patch("oci_sip_mcp.auth.oci.auth.signers.InstancePrincipalsSecurityTokenSigner", return_value=signer):
        config, _ = OCIAuthFactory(
            ServerConfig(auth_mode="instance_principal", region="us-ashburn-1")
        ).build()

    assert config == {"tenancy": "ocid1.tenancy.oc1..example", "region": "us-ashburn-1"}


def test_resource_principal_build_uses_signer_metadata_when_present():
    signer = MagicMock()
    signer.tenancy_id = "ocid1.tenancy.oc1..example"
    signer.region = "us-phoenix-1"

    with patch("oci_sip_mcp.auth.oci.auth.signers.get_resource_principals_signer", return_value=signer):
        config, built_signer = OCIAuthFactory(ServerConfig(auth_mode="resource_principal")).build()

    assert built_signer is signer
    assert config == {"tenancy": "ocid1.tenancy.oc1..example", "region": "us-phoenix-1"}
