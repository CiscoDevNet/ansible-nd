# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import parse_controller_version


IBGP_ND_4_3_FIELDS = frozenset(
    {
        "ai_load_sharing_opcode", "ai_load_sharing_packet_sequence_number", "ai_load_sharing_queuepair",
        "allow_smart_switch_ha", "auto_smart_switch_vpc_pair_ha", "bfd_min_rx_interval", "bfd_multiplier",
        "bfd_tx_interval", "dlb_all_interfaces", "hypershield_ha_peer_link_subnet",
        "hypershield_ha_peer_link_subnet_granularity", "hypershield_ha_source_intf", "hypershield_ha_source_subnet",
        "hypershield_ha_vlan", "use_hypershield_source_loopback_for_ha", "isis_auth_use_key_entries", "isis_border_level12",
        "isis_keys", "ntp_auth_algorithm", "ntp_auth_enable", "ntp_auth_key", "ntp_auth_key_id", "ntp_auth_key_type",
        "ospf_auth_keychain_name", "ospf_auth_use_keychain", "ospf_auto_cost_ref_bw", "ospf_keys", "ospf_log_adj_changes",
        "ospf_max_metric_startup_wait", "pim_auth_keychain_name", "pim_auth_use_keychain", "pim_keys", "system_qos_classification",
    }
)
IBGP_ND_4_2_ONLY_FIELDS = frozenset({"hypershield_connectivity_proxy_server", "hypershield_connectivity_proxy_server_port"})


class ManageFabricIbgpReleaseValidationMixin:
    """Reject iBGP settings outside their observed native-template release."""

    rest_send: Any

    def preflight(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Enforce the ND 4.3.1 boundary for newly exposed iBGP controls."""
        newer_fields: list[str] = []
        legacy_proxy_fields: list[str] = []
        for item in model_instances:
            management = getattr(item, "management", None)
            if management is None:
                continue
            supplied = management.model_fields_set
            if supplied & IBGP_ND_4_3_FIELDS:
                newer_fields.append(str(item.get_identifier_value()))
            if supplied & IBGP_ND_4_2_ONLY_FIELDS:
                legacy_proxy_fields.append(str(item.get_identifier_value()))

        raw_version = self.rest_send.controller_version
        version = parse_controller_version(raw_version)
        if newer_fields and (version is None or version < (4, 3, 1)):
            reported = raw_version or "unknown"
            raise RuntimeError(
                "The newly exposed iBGP VXLAN template settings require ND 4.3.1 or later when supplied; "
                f"controller version is {reported!r} for fabric(s): {', '.join(newer_fields)}"
            )
        if legacy_proxy_fields and (version is None or version < (4, 2, 1) or version >= (4, 3, 1)):
            reported = raw_version or "unknown"
            raise RuntimeError(
                "management.hypershield_connectivity_proxy_server and its port are available only in the ND 4.2.1 native template; "
                f"controller version is {reported!r} for fabric(s): {', '.join(legacy_proxy_fields)}"
            )
        super().preflight(model_instances)
