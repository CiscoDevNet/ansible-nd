# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the VXLAN Fabric Group (MSD) model.

Focus areas (PR #246 review remediation):
- Secret handling: BGP/CloudSec keys masked in config/diff output but sent in the
  API payload, and marked ``no_log`` in the generated argument spec.
- Downstream VNI ranges: documented defaults are emitted instead of blank ranges.
- Format validation: IP/CIDR/pattern constraints match the OpenAPI schema and the
  CloudSec key never leaks its value in validation errors.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    FabricGroupVxlanModel,
)

MASK = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
# ND enforces exact CloudSec key lengths per algorithm: 66 hex for AES_128_CMAC, 130 for AES_256_CMAC.
VALID_CS_KEY_128 = "ab" * 33
VALID_CS_KEY_256 = "ab" * 65


def _model(management: dict) -> FabricGroupVxlanModel:
    return FabricGroupVxlanModel.from_config({"fabric_name": "MSD1", "management": management})


# =============================================================================
# Downstream VNI defaults
# =============================================================================


def test_manage_fabric_group_vxlan_00010():
    """
    # Summary

    Verify downstream VNI ranges default to the documented values in the payload
    when downstream VNI is enabled and no ranges are supplied.

    ## Test

    - downstreamVni is True
    - downstreamL2VniRange == "10030000-10049000"
    - downstreamL3VniRange == "10050000-10059000"
    """
    mgmt = _model({"downstream_vni": True}).to_payload()["management"]
    assert mgmt["downstreamVni"] is True
    assert mgmt["downstreamL2VniRange"] == "10030000-10049000"
    assert mgmt["downstreamL3VniRange"] == "10050000-10059000"


def test_manage_fabric_group_vxlan_00020():
    """
    # Summary

    Verify downstream VNI ranges carry the documented defaults even when the
    toggle is off (matches the ND schema defaults; no blank ranges are sent).

    ## Test

    - downstreamVni is False
    - Both downstream ranges are the documented defaults, never blank
    """
    mgmt = _model({}).to_payload()["management"]
    assert mgmt["downstreamVni"] is False
    assert mgmt["downstreamL2VniRange"] == "10030000-10049000"
    assert mgmt["downstreamL3VniRange"] == "10050000-10059000"


# =============================================================================
# Secret handling (BGP / CloudSec keys)
# =============================================================================


def test_manage_fabric_group_vxlan_00100():
    """
    # Summary

    Verify secret keys carry their real value in the API payload.

    ## Test

    - multisiteInterConnectBgpKey and cloudSecKey equal the provided values
    """
    mgmt = _model(
        {
            "multisite_inter_connect_bgp_key": "0123456789abcdef",
            "cloud_sec_key": VALID_CS_KEY_128,
        }
    ).to_payload()["management"]
    assert mgmt["multisiteInterConnectBgpKey"] == "0123456789abcdef"
    assert mgmt["cloudSecKey"] == VALID_CS_KEY_128


def test_manage_fabric_group_vxlan_00110():
    """
    # Summary

    Verify secret keys are masked in the Ansible config output.

    ## Test

    - to_config() masks both secret fields with the no_log sentinel
    """
    mgmt = _model(
        {
            "multisite_inter_connect_bgp_key": "0123456789abcdef",
            "cloud_sec_key": VALID_CS_KEY_128,
        }
    ).to_config()["management"]
    assert mgmt["multisite_inter_connect_bgp_key"] == MASK
    assert mgmt["cloud_sec_key"] == MASK


def test_manage_fabric_group_vxlan_00120():
    """
    # Summary

    Verify secret keys are masked in the diff dictionary.

    ## Test

    - to_diff_dict() masks both secret fields with the no_log sentinel
    """
    diff = _model(
        {
            "multisite_inter_connect_bgp_key": "0123456789abcdef",
            "cloud_sec_key": VALID_CS_KEY_128,
        }
    ).to_diff_dict()["management"]
    assert diff["multisiteInterConnectBgpKey"] == MASK
    assert diff["cloudSecKey"] == MASK


def test_manage_fabric_group_vxlan_00130():
    """
    # Summary

    Verify secret keys are flagged no_log in the generated argument spec.

    ## Test

    - management.multisite_inter_connect_bgp_key.no_log is True
    - management.cloud_sec_key.no_log is True
    - Both are typed as str for Ansible
    """
    mgmt = FabricGroupVxlanModel.get_argument_spec()["config"]["options"]["management"]["options"]
    assert mgmt["multisite_inter_connect_bgp_key"]["no_log"] is True
    assert mgmt["cloud_sec_key"]["no_log"] is True
    assert mgmt["multisite_inter_connect_bgp_key"]["type"] == "str"
    assert mgmt["cloud_sec_key"]["type"] == "str"


def test_manage_fabric_group_vxlan_00140():
    """
    # Summary

    Verify a secret parsed from an API response is still masked in config output.

    ## Test

    - from_response() accepts cloudSecKey, to_config() masks it
    """
    model = FabricGroupVxlanModel.from_response(
        {
            "name": "MSD1",
            "category": "fabricGroup",
            "management": {"type": "vxlan", "cloudSecKey": VALID_CS_KEY_128},
        }
    )
    assert model.to_config()["management"]["cloud_sec_key"] == MASK
    assert model.to_payload()["management"]["cloudSecKey"] == VALID_CS_KEY_128


# =============================================================================
# Format validation — valid inputs
# =============================================================================


@pytest.mark.parametrize(
    "management",
    [
        {"multisite_loopback_ip_range": "10.1.0.0/24", "multisite_underlay_subnet_range": "10.2.0.0/24"},
        {"multisite_loopback_ipv6_range": "fd00::1:0/120", "multisite_underlay_ipv6_subnet_range": "fd00::2:0/120"},
        {"security_group_tag_prefix": "SG-1_"},
        {"scheduled_backup_time": "00:00"},
        {"scheduled_backup_time": "23:59"},
        {"cloud_sec_key": VALID_CS_KEY_128},
        {"cloud_sec_algorithm": "AES_256_CMAC", "cloud_sec_key": VALID_CS_KEY_256},
        {"multisite_overlay_inter_connect_type": "routeServer", "route_server_collection": [{"route_server_ip": "1.2.3.4", "route_server_asn": "65001"}]},
        {"multisite_overlay_inter_connect_type": "routeServer", "route_server_collection": [{"route_server_ip": "2001:db8::1", "route_server_asn": "65001"}]},
    ],
)
def test_manage_fabric_group_vxlan_00200(management):
    """
    # Summary

    Verify valid IP/CIDR/pattern/secret inputs are accepted.

    ## Test

    - Model construction succeeds for each valid management fragment
    """
    assert _model(management) is not None


# =============================================================================
# Format validation — invalid inputs
# =============================================================================


@pytest.mark.parametrize(
    "management",
    [
        {"multisite_loopback_ip_range": "not-an-ip"},
        {"multisite_underlay_subnet_range": "10.1.1.1/33"},  # invalid prefix length
        {"multisite_loopback_ipv6_range": "10.1.0.0/24"},  # IPv4 in IPv6 field
        {"multisite_underlay_ipv6_subnet_range": "zzzz::/120"},
        {"security_group_tag_prefix": "SG!"},  # illegal char
        {"scheduled_backup_time": "24:00"},  # hour out of range
        {"scheduled_backup_time": "9:00"},  # not zero-padded
        {"cloud_sec_key": "zz11"},  # non-hex
        {"cloud_sec_key": "abcdef0123"},  # valid hex but wrong length for AES_128_CMAC (needs 66)
        {"cloud_sec_algorithm": "AES_256_CMAC", "cloud_sec_key": VALID_CS_KEY_128},  # 66 too short for AES_256 (needs 130)
        {"multisite_overlay_inter_connect_type": "routeServer", "route_server_collection": [{"route_server_ip": "999.1.1.1", "route_server_asn": "65001"}]},
    ],
)
def test_manage_fabric_group_vxlan_00300(management):
    """
    # Summary

    Verify invalid IP/CIDR/pattern/secret inputs are rejected.

    ## Test

    - Model construction raises ValidationError for each invalid fragment
    """
    with pytest.raises(ValidationError):
        _model(management)


def test_manage_fabric_group_vxlan_00310():
    """
    # Summary

    Verify an invalid CloudSec key never leaks its value in the error message.

    ## Test

    - ValidationError text does not contain the supplied secret
    - hide_input_in_errors suppresses the pydantic input_value echo
    """
    secret = "LEAK_ME_zz"
    with pytest.raises(ValidationError) as exc:
        _model({"cloud_sec_key": secret})
    assert secret not in str(exc.value)
