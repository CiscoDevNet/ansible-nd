# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, ClassVar, Mapping

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

ND_4_3_1 = (4, 3, 1, 0)

IBGP_ND_4_3_FIELDS = frozenset(
    {
        "ai_load_sharing_opcode",
        "ai_load_sharing_packet_sequence_number",
        "ai_load_sharing_queuepair",
        "allow_smart_switch_ha",
        "auto_smart_switch_vpc_pair_ha",
        "bfd_min_rx_interval",
        "bfd_multiplier",
        "bfd_tx_interval",
        "dlb_all_interfaces",
        "hypershield_ha_peer_link_subnet",
        "hypershield_ha_peer_link_subnet_granularity",
        "hypershield_ha_source_intf",
        "hypershield_ha_source_subnet",
        "hypershield_ha_vlan",
        "use_hypershield_source_loopback_for_ha",
        "isis_auth_use_key_entries",
        "isis_border_level12",
        "isis_keys",
        "ntp_auth_algorithm",
        "ntp_auth_enable",
        "ntp_auth_key",
        "ntp_auth_key_id",
        "ntp_auth_key_type",
        "ospf_auth_keychain_name",
        "ospf_auth_use_keychain",
        "ospf_auto_cost_ref_bw",
        "ospf_keys",
        "ospf_log_adj_changes",
        "ospf_max_metric_startup_wait",
        "pim_auth_keychain_name",
        "pim_auth_use_keychain",
        "pim_keys",
        "system_qos_classification",
    }
)

EBGP_ND_4_3_FIELDS = frozenset(
    {
        "ai_load_sharing_opcode",
        "ai_load_sharing_packet_sequence_number",
        "ai_load_sharing_queuepair",
        "allow_smart_switch_ha",
        "auto_smart_switch_vpc_pair_ha",
        "bfd_min_rx_interval",
        "bfd_multiplier",
        "bfd_pim",
        "bfd_tx_interval",
        "bgp_allow_as_in",
        "dlb_all_interfaces",
        "enable_secure_default_vrf",
        "hypershield_ha_peer_link_subnet",
        "hypershield_ha_peer_link_subnet_granularity",
        "hypershield_ha_source_intf",
        "hypershield_ha_source_subnet",
        "hypershield_ha_vlan",
        "ntp_auth_algorithm",
        "ntp_auth_enable",
        "ntp_auth_key",
        "ntp_auth_key_id",
        "ntp_auth_key_type",
        "per_vrf_unique_loopback_auto_provision",
        "per_vrf_unique_loopback_auto_provision_v6",
        "per_vrf_unique_loopback_ip_range",
        "per_vrf_unique_loopback_ipv6_range",
        "pim_auth_keychain_name",
        "pim_auth_use_keychain",
        "pim_keys",
        "use_hypershield_source_loopback_for_ha",
    }
)

EXTERNAL_ND_4_3_FIELDS = frozenset(
    {
        "ai_monitoring",
        "allow_smart_switch_ha",
        "auto_smart_switch_vpc_pair_ha",
        "enable_remote_switch_backup",
        "hypershield_ha_peer_link_subnet",
        "hypershield_ha_peer_link_subnet_granularity",
        "hypershield_ha_source_intf",
        "hypershield_ha_source_subnet",
        "hypershield_ha_vlan",
        "ios_xe_tor_bootstrap_vlan",
        "remote_storage_server",
        "software_update_in_monitored_mode",
        "strict_config_compliance_mode",
        "use_hypershield_source_loopback_for_ha",
    }
)


def parse_controller_product_version(value: object) -> tuple[int, int, int, int] | None:
    """Parse an ND product version, ordering lettered bug-fix releases after the base release."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)([a-z]*)", str(value or "").strip().lower())
    if match is None:
        return None
    major, minor, patch, suffix = match.groups()
    suffix_order = 0
    for character in suffix:
        suffix_order = suffix_order * 26 + ord(character) - ord("a") + 1
    return int(major), int(minor), int(patch), suffix_order


class ManageFabricReleaseValidationMixin:
    """Apply ND release gates declared by each fabric orchestrator."""

    rest_send: Any
    release_gated_fields: ClassVar[frozenset[str]] = frozenset()
    release_gate_family: ClassVar[str] = "fabric"
    release_gate_minimum_version: ClassVar[tuple[int, int, int, int]] = ND_4_3_1
    # Add per-field overrides only when ND confirms a field's later minimum release.
    release_gate_minimum_versions: ClassVar[Mapping[str, tuple[int, int, int, int]]] = {}

    def preflight(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Reject explicitly supplied fields unsupported before ND 4.3.1."""
        affected = []
        raw_version = None
        version = None
        for item in model_instances:
            management = getattr(item, "management", None)
            supplied_fields = management.model_fields_set & self.release_gated_fields if management is not None else set()
            if not supplied_fields:
                continue
            if version is None:
                raw_version = self.rest_send.controller_product_version
                version = parse_controller_product_version(raw_version)
            unsupported_fields = [
                field
                for field in supplied_fields
                if version is None
                or version < self.release_gate_minimum_versions.get(field, self.release_gate_minimum_version)
            ]
            if unsupported_fields:
                affected.append(f"{item.get_identifier_value()} ({', '.join(sorted(unsupported_fields))})")

        if affected:
            reported = raw_version or "unknown"
            raise RuntimeError(
                f"{self.release_gate_family} settings require ND 4.3.1 or later, with field-specific release "
                f"thresholds where configured; controller product version is {reported!r} for fabric(s): "
                f"{', '.join(affected)}"
            )

        super().preflight(model_instances)


class ManageFabricIbgpReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """ND 4.3.1 field disposition for iBGP and AI iBGP VXLAN."""

    release_gated_fields = IBGP_ND_4_3_FIELDS
    release_gate_family = "iBGP VXLAN"


class ManageFabricEbgpReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """ND 4.3.1 field disposition for eBGP and AI eBGP VXLAN."""

    release_gated_fields = EBGP_ND_4_3_FIELDS
    release_gate_family = "eBGP VXLAN"


class ManageFabricExternalReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """ND 4.3.1 field disposition for External Connectivity fabrics."""

    release_gated_fields = EXTERNAL_ND_4_3_FIELDS
    release_gate_family = "External Connectivity"
