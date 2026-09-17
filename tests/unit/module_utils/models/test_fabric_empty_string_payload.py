"""Tests that fabric payloads omit fields whose ND schema constraints reject an empty string.

ND 4.3.1 enforces request-body schema validation that 4.2.1 did not. Fields declared with
``minLength``/``pattern``/``format`` reject ``""``, so the models must omit them entirely
when the user has not set them, rather than sending a placeholder empty string.
"""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import FabricAiIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import FabricIbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import FabricGroupVxlanModel

# API field names whose ND schema declares minLength, pattern or format, and therefore
# reject "" on ND 4.3.1. Sourced from docs/openapi/4.3.1/manage.json and confirmed
# against a live 4.3.1 controller's rejected-field list.
CONSTRAINED_KEYS = frozenset(
    {
        "bfdAuthenticationKey",
        "bgpAuthenticationKey",
        "dhcpEndAddress",
        "dhcpStartAddress",
        "isisAuthenticationKey",
        "isisAuthenticationKeychainName",
        "keyManagementEntityServerIp",
        "macsecFallbackKeyString",
        "macsecKeyString",
        "managementGateway",
        "mvpnVrfRouteImportIdRange",
        "ospfAuthenticationKey",
        "pimHelloAuthenticationKey",
        "quantumKeyDistributionProfileName",
        "scheduledBackupTime",
        "trustpointLabel",
        "unNumberedDhcpEndAddress",
        "unNumberedDhcpStartAddress",
        "vrfLiteMacsecFallbackKeyString",
        "vrfLiteMacsecKeyString",
    }
)

# Free-form fields that ND accepts as "" (no minLength/pattern/format). These must keep
# sending "" so that clearing a value stays expressible.
FREEFORM_KEYS = frozenset(
    {
        "banner",
        "domainName",
        "extraConfigAaa",
        "extraConfigFabric",
        "extraConfigIntraFabricLinks",
        "extraConfigLeaf",
        "extraConfigNxosBootstrap",
        "extraConfigSpine",
        "extraConfigTor",
        "extraConfigXeBootstrap",
        "flowletDscp",
        "ibgpPeerTemplate",
        "leafIbgpPeerTemplate",
        "perPacketDscp",
        "preInterfaceConfigLeaf",
        "preInterfaceConfigSpine",
        "preInterfaceConfigTor",
    }
)

VXLAN_MODELS = [FabricIbgpModel, FabricEbgpModel, FabricAiIbgpVxlanModel, FabricAiEbgpVxlanModel]
ALL_FABRIC_MODELS = VXLAN_MODELS + [FabricExternalConnectivityModel]


def management_payload(model_cls, management=None):
    config = {"fabric_name": "test_fabric", "management": {"bgp_asn": "65099", **(management or {})}}
    return model_cls.from_config(config).to_payload()["management"]


@pytest.mark.parametrize("model_cls", ALL_FABRIC_MODELS, ids=lambda c: c.__name__)
def test_constrained_fields_absent_when_unset(model_cls):
    """Unset constrained fields must be omitted, not sent as "", or ND 4.3.1 returns HTTP 400."""
    present = sorted(CONSTRAINED_KEYS & management_payload(model_cls).keys())
    assert present == [], f"{model_cls.__name__} still sends empty-string values for {present}"


@pytest.mark.parametrize("model_cls", ALL_FABRIC_MODELS, ids=lambda c: c.__name__)
def test_no_payload_value_is_an_empty_string_outside_freeform(model_cls):
    """Guards against a new empty-string default being added for a constrained field."""
    empties = {key for key, value in management_payload(model_cls).items() if value == ""}
    assert empties <= FREEFORM_KEYS, f"{model_cls.__name__} sends '' for non-free-form keys {sorted(empties - FREEFORM_KEYS)}"


@pytest.mark.parametrize("model_cls", ALL_FABRIC_MODELS, ids=lambda c: c.__name__)
def test_explicit_empty_string_is_dropped(model_cls):
    """A user (or test fixture) passing "" must not reintroduce the rejected key."""
    payload = management_payload(model_cls, {"dhcp_start_address": "", "scheduled_backup_time": ""})
    assert "dhcpStartAddress" not in payload
    assert "scheduledBackupTime" not in payload


@pytest.mark.parametrize("model_cls", ALL_FABRIC_MODELS, ids=lambda c: c.__name__)
def test_real_values_still_reach_the_payload(model_cls):
    """Omitting the default must not omit values the user actually set."""
    payload = management_payload(model_cls, {"dhcp_start_address": "10.1.1.10", "dhcp_end_address": "10.1.1.20"})
    assert payload["dhcpStartAddress"] == "10.1.1.10"
    assert payload["dhcpEndAddress"] == "10.1.1.20"


@pytest.mark.parametrize("model_cls", VXLAN_MODELS, ids=lambda c: c.__name__)
def test_roce_v2_omitted_so_nd_applies_its_own_default(model_cls):
    """The roceV2 schema default changed between releases ("26" -> "24-31").

    Hardcoding "26" made ND 4.3.1 reject creation with
    "invalid fields [roceV2=26]" whenever aimlQos was disabled.
    """
    assert "roceV2" not in management_payload(model_cls)


@pytest.mark.parametrize("model_cls", VXLAN_MODELS, ids=lambda c: c.__name__)
def test_roce_v2_preserved_when_set(model_cls):
    assert management_payload(model_cls, {"roce_v2": "24-31"})["roceV2"] == "24-31"


@pytest.mark.parametrize("model_cls", ALL_FABRIC_MODELS, ids=lambda c: c.__name__)
def test_free_form_fields_still_send_empty_string(model_cls):
    """These have no schema constraint, so "" remains a valid way to clear them."""
    payload = management_payload(model_cls)
    empties = {key for key, value in payload.items() if value == ""}
    assert empties, f"{model_cls.__name__} sends no free-form empty strings; clearing a value is no longer expressible"
    assert payload.get("extraConfigAaa") == ""
    assert payload.get("extraConfigNxosBootstrap") == ""


def test_fabric_group_payload_has_no_empty_strings():
    payload = FabricGroupVxlanModel.from_config({"fabric_name": "test_group", "management": {}}).to_payload()["management"]
    assert [key for key, value in payload.items() if value == ""] == []
    assert not CONSTRAINED_KEYS & payload.keys()
