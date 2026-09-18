# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for legacy eBGP/iBGP (and inherited AI) fabric secret masking.

# Summary

- Secret authentication/MACsec keys carry their real value in the API payload.
- The same keys are masked in the Ansible config and diff output.
- The keys are flagged ``no_log`` in the generated argument spec.
- AI eBGP/iBGP models inherit the masking behavior from their base classes.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)

MASK = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"

# eBGP secret fields retrofitted in Change E.
EBGP_SECRET_FIELDS = [
    "bgp_authentication_key",
    "bfd_authentication_key",
    "pim_hello_authentication_key",
    "macsec_key_string",
    "macsec_fallback_key_string",
]

# iBGP secret fields retrofitted in Change E.
IBGP_SECRET_FIELDS = [
    "bgp_authentication_key",
    "pim_hello_authentication_key",
    "bfd_authentication_key",
    "ospf_authentication_key",
    "isis_authentication_key",
    "macsec_key_string",
    "macsec_fallback_key_string",
    "vrf_lite_macsec_key_string",
    "vrf_lite_macsec_fallback_key_string",
]


# =============================================================================
# eBGP secret handling
# =============================================================================


def test_manage_fabric_secret_masking_00100() -> None:
    """
    # Summary

    Verify eBGP secret keys carry their real value in the API payload.

    ## Test

    - to_payload() emits the provided secret values verbatim
    """
    model = FabricEbgpModel.from_config(
        {
            "fabric_name": "ebgp1",
            "management": {
                "bgp_asn": "65001",
                "bgp_authentication_key": "SECRET_BGP",
                "macsec_key_string": "SECRET_MACSEC",
            },
        }
    )
    mgmt = model.to_payload()["management"]
    assert mgmt["bgpAuthenticationKey"] == "SECRET_BGP"
    assert mgmt["macsecKeyString"] == "SECRET_MACSEC"


def test_manage_fabric_secret_masking_00110() -> None:
    """
    # Summary

    Verify eBGP secret keys are masked in the config and diff output.

    ## Test

    - to_config() masks the secret fields with the no_log sentinel
    - to_diff_dict() masks the secret fields with the no_log sentinel
    """
    model = FabricEbgpModel.from_config(
        {
            "fabric_name": "ebgp1",
            "management": {
                "bgp_asn": "65001",
                "bgp_authentication_key": "SECRET_BGP",
                "macsec_key_string": "SECRET_MACSEC",
            },
        }
    )
    config = model.to_config()["management"]
    diff = model.to_diff_dict()["management"]
    assert config["bgp_authentication_key"] == MASK
    assert config["macsec_key_string"] == MASK
    assert diff["bgpAuthenticationKey"] == MASK
    assert diff["macsecKeyString"] == MASK


def test_manage_fabric_secret_masking_00120() -> None:
    """
    # Summary

    Verify all eBGP secret keys are flagged no_log in the argument spec.

    ## Test

    - each retrofitted field carries no_log True and type str
    """
    mgmt = FabricEbgpModel.get_argument_spec()["config"]["options"]["management"]["options"]
    for field in EBGP_SECRET_FIELDS:
        assert mgmt[field]["no_log"] is True, field
        assert mgmt[field]["type"] == "str", field


# =============================================================================
# iBGP secret handling
# =============================================================================


def test_manage_fabric_secret_masking_00200() -> None:
    """
    # Summary

    Verify iBGP secret keys carry their real value in the API payload.

    ## Test

    - to_payload() emits the provided secret values verbatim
    """
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "ibgp1",
            "management": {
                "bgp_asn": "65001",
                "ospf_authentication_key": "SECRET_OSPF",
                "vrf_lite_macsec_key_string": "SECRET_VRFLITE",
            },
        }
    )
    mgmt = model.to_payload()["management"]
    assert mgmt["ospfAuthenticationKey"] == "SECRET_OSPF"
    assert mgmt["vrfLiteMacsecKeyString"] == "SECRET_VRFLITE"


def test_manage_fabric_secret_masking_00210() -> None:
    """
    # Summary

    Verify iBGP secret keys are masked in the config and diff output.

    ## Test

    - to_config() masks the secret fields with the no_log sentinel
    - to_diff_dict() masks the secret fields with the no_log sentinel
    """
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "ibgp1",
            "management": {
                "bgp_asn": "65001",
                "ospf_authentication_key": "SECRET_OSPF",
                "vrf_lite_macsec_key_string": "SECRET_VRFLITE",
            },
        }
    )
    config = model.to_config()["management"]
    diff = model.to_diff_dict()["management"]
    assert config["ospf_authentication_key"] == MASK
    assert config["vrf_lite_macsec_key_string"] == MASK
    assert diff["ospfAuthenticationKey"] == MASK
    assert diff["vrfLiteMacsecKeyString"] == MASK


def test_manage_fabric_secret_masking_00220() -> None:
    """
    # Summary

    Verify all iBGP secret keys are flagged no_log in the argument spec.

    ## Test

    - each retrofitted field carries no_log True and type str
    """
    mgmt = FabricIbgpModel.get_argument_spec()["config"]["options"]["management"]["options"]
    for field in IBGP_SECRET_FIELDS:
        assert mgmt[field]["no_log"] is True, field
        assert mgmt[field]["type"] == "str", field


# =============================================================================
# AI variants inherit the masking behavior
# =============================================================================


def test_manage_fabric_secret_masking_00300() -> None:
    """
    # Summary

    Verify the AI eBGP model inherits secret masking from its base.

    ## Test

    - to_payload() emits the real secret; to_config() masks it
    """
    model = FabricAiEbgpVxlanModel.from_config(
        {
            "fabric_name": "ai_ebgp1",
            "management": {"bgp_asn": "65001", "bgp_authentication_key": "SECRET_AI_EBGP"},
        }
    )
    assert model.to_payload()["management"]["bgpAuthenticationKey"] == "SECRET_AI_EBGP"
    assert model.to_config()["management"]["bgp_authentication_key"] == MASK


def test_manage_fabric_secret_masking_00310() -> None:
    """
    # Summary

    Verify the AI iBGP model inherits secret masking from its base.

    ## Test

    - to_payload() emits the real secret; to_config() masks it
    """
    model = FabricAiIbgpVxlanModel.from_config(
        {
            "fabric_name": "ai_ibgp1",
            "management": {"bgp_asn": "65001", "ospf_authentication_key": "SECRET_AI_OSPF"},
        }
    )
    assert model.to_payload()["management"]["ospfAuthenticationKey"] == "SECRET_AI_OSPF"
    assert model.to_config()["management"]["ospf_authentication_key"] == MASK
