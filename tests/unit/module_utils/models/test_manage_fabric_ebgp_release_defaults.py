# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Native eBGP 4.3 defaults remain absent before their product release."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import ManageAiEbgpVxlanFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import ManageEbgpFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

FAMILIES = (
    pytest.param(FabricEbgpModel, ManageEbgpFabricOrchestrator, id="ebgp"),
    pytest.param(FabricAiEbgpVxlanModel, ManageAiEbgpVxlanFabricOrchestrator, id="ai-ebgp"),
)
DEFAULTS = {
    "ai_load_sharing_opcode": False,
    "ai_load_sharing_packet_sequence_number": False,
    "ai_load_sharing_queuepair": False,
    "allow_smart_switch_ha": False,
    "auto_smart_switch_vpc_pair_ha": False,
    "bfd_min_rx_interval": 50,
    "bfd_multiplier": 3,
    "bfd_pim": False,
    "bfd_tx_interval": 50,
    "bgp_allow_as_in": True,
    "dlb_all_interfaces": True,
    "enable_secure_default_vrf": False,
    "hypershield_ha_peer_link_subnet": "10.12.0.0/22",
    "hypershield_ha_peer_link_subnet_granularity": "/30",
    "hypershield_ha_source_intf": "loopback1023",
    "hypershield_ha_source_subnet": "10.11.0.0/23",
    "hypershield_ha_vlan": 3601,
    "ntp_auth_algorithm": "aes128cmac",
    "ntp_auth_enable": False,
    "ntp_auth_key_id": 1,
    "ntp_auth_key_type": "7",
    "per_vrf_unique_loopback_auto_provision": False,
    "per_vrf_unique_loopback_auto_provision_v6": False,
    "per_vrf_unique_loopback_ip_range": "10.6.0.0/22",
    "per_vrf_unique_loopback_ipv6_range": "fd00::a06:0/112",
    "pim_auth_use_keychain": False,
    "use_hypershield_source_loopback_for_ha": False,
}


def _orchestrator(orchestrator, version):
    rest = RestSend({"check_mode": False, "state": "merged"})
    rest.controller_product_version = version
    return orchestrator(rest_send=rest)


@pytest.mark.parametrize(("model_class", "orchestrator"), FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)", "4.3.1", "4.4.1"))
def test_ebgp_omitted_release_defaults_are_filtered_only_on_older_controllers(model_class, orchestrator, version):
    """Every declared newer default uses existing product-version filtering without argspec injection."""
    model = model_class.from_config({"fabric_name": "ebgp_defaults", "management": {"bgp_asn": "65001"}})
    _orchestrator(orchestrator, version).preflight([model])
    payload = model.to_payload()["management"]
    spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]
    for field, expected in DEFAULTS.items():
        alias = type(model.management).model_fields[field].alias
        assert field not in model.management.model_fields_set
        assert "default" not in spec[field]
        if version.startswith("4.2"):
            assert alias not in payload
        else:
            assert payload[alias] == expected


@pytest.mark.parametrize(("model_class", "orchestrator"), FAMILIES)
@pytest.mark.parametrize(("field", "value"), DEFAULTS.items())
def test_ebgp_supplied_newer_values_including_false_defaults_are_rejected_on_4_2(model_class, orchestrator, field, value):
    """Explicit default-equal values remain supplied input and cannot evade their release gate."""
    model = model_class.from_config({"fabric_name": "ebgp_defaults", "management": {"bgp_asn": "65001", field: value}})
    with pytest.raises(RuntimeError, match=rf"management\.{field}.*requires ND 4\.3\.1"):
        _orchestrator(orchestrator, "4.2.1").preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator"), FAMILIES)
def test_ebgp_explicit_empty_newer_collection_is_gated_by_presence(model_class, orchestrator):
    """An empty but supplied keychain collection is still newer-release input."""
    model = model_class.from_config({"fabric_name": "ebgp_defaults", "management": {"bgp_asn": "65001", "pim_keys": []}})
    with pytest.raises(RuntimeError, match=r"management\.pim_keys.*requires ND 4\.3\.1"):
        _orchestrator(orchestrator, "4.2.1").preflight([model])
