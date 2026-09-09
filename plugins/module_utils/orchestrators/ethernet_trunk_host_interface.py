# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet trunkHost interface orchestrator for Nexus Dashboard.

This module provides `EthernetTrunkHostInterfaceOrchestrator`, which manages CRUD operations
for ethernet trunkHost interfaces. It inherits all shared ethernet logic from
`EthernetBaseOrchestrator` and only defines the model class and managed policy types.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import TrunkHostPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import GatheredLuceneSpec
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class EthernetTrunkHostInterfaceOrchestrator(EthernetBaseOrchestrator):
    """
    # Summary

    Orchestrator for ethernet trunkHost interface CRUD operations on Nexus Dashboard.

    Inherits all shared ethernet logic from `EthernetBaseOrchestrator`. Defines `model_class` as
    `EthernetTrunkHostInterfaceModel` and manages the `trunkHost` policy type.

    Unlike the other ethernet orchestrators, normalizing a trunkHost interface produces another
    trunkHost interface (the fabric default policy is `int_trunk_host`), so normalized interfaces
    remain in scope of this orchestrator's policy filter. `query_all` therefore additionally filters
    out interfaces whose policy matches the unconfigured `int_trunk_host` default signature so that
    idempotent re-runs of `state: overridden` do not see already-normalized interfaces as items to
    re-normalize.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `EthernetBaseOrchestrator` for full details.
    """

    model_class: ClassVar[type[NDBaseModel]] = EthernetTrunkHostInterfaceModel

    supports_gathered_server_filtering: ClassVar[bool] = True
    gathered_lucene_spec: ClassVar[GatheredLuceneSpec] = GatheredLuceneSpec(
        base_terms=(
            ("interfaceType", "ethernet"),
            ("policyType", "trunkHost"),
        ),
        field_map={
            ("interface_name",): "interfaceName",
        },
    )

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator.

        ## Raises

        None
        """
        return {e.value for e in TrunkHostPolicyTypeEnum}

    @staticmethod
    def _is_unconfigured_default(iface: dict) -> bool:
        """
        # Summary

        Return `True` if the given interface API response represents an unconfigured `int_trunk_host`
        default — `allowedVlans` is absent or `"none"`, `description` is absent or empty, `nativeVlan`
        is absent or `1`, and none of the Class C fields (`InterfaceDefaultConfig.UNRESETTABLE_FIELDS`)
        are set. Such an interface is indistinguishable from a freshly normalized one and should
        be treated as out-of-scope for `state: overridden` idempotency.

        Class C fields are checked because they survive `interfaceActions/normalize` (ND's validator
        rejects 0/null for them); leaving them out of this filter would hide a configured-but-stuck
        interface from `state: deleted` and prevent the orchestrator from dispatching it to the
        per-interface PUT-as-replace reset path.

        ## Raises

        None
        """
        policy = iface.get("configData", {}).get("networkOS", {}).get("policy", {}) or {}
        allowed_vlans = policy.get("allowedVlans")
        if allowed_vlans not in (None, "none"):
            return False
        description = policy.get("description")
        if description not in (None, ""):
            return False
        native_vlan = policy.get("nativeVlan")
        if native_vlan not in (None, 1):
            return False
        # TODO(4.2.1) normalize-unresettable-policy-fields
        # Class C fields (bandwidth, debounceLinkupTimer, inheritBandwidth) survive interfaceActions/normalize because
        # ND's validator rejects 0/null for them, so a normalized interface still carries any prior value. We must treat
        # such an interface as configured (not an unconfigured default) so `state: deleted` keeps it in scope and routes
        # it to the per-interface PUT-as-replace reset path. See InterfaceDefaultConfig.UNRESETTABLE_FIELDS for the set.
        if any(policy.get(field) is not None for field in InterfaceDefaultConfig.UNRESETTABLE_FIELDS):
            return False
        return True

    def query_all(self, model_instance: NDBaseModel | None = None, gathered_filters: list[dict] | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Query all trunkHost interfaces in the fabric via the base orchestrator, then filter out interfaces
        that match the unconfigured `int_trunk_host` default signature. This keeps default-configured
        interfaces out of `before`, so `state: overridden` idempotency holds across re-runs.

        ## Raises

        ### RuntimeError

        - Propagated from `EthernetBaseOrchestrator.query_all` on query failure.
        """
        result = super().query_all(model_instance=model_instance, gathered_filters=gathered_filters, **kwargs)
        if not isinstance(result, list):
            return result
        return [iface for iface in result if not self._is_unconfigured_default(iface)]
