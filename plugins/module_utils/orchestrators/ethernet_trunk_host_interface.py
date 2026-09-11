# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet trunk-mode host interface orchestrator for Nexus Dashboard (NX-OS `trunkHost`, IOS-XE `iosXeTrunkHost`; issue #535).

This module provides `EthernetTrunkHostInterfaceOrchestrator`, which manages CRUD operations
for ethernet trunk-mode host interfaces. It inherits all shared ethernet logic from
`EthernetBaseOrchestrator` (including the IOS-XE contract: per-(switch, policy_type) bulk grouping, merge-only under
`state: overridden`, per-interface reset PUT to a defaults-only `iosXeTrunkHost` under `state: deleted`), defines the
model class and managed policy types, and filters unconfigured trunk defaults of BOTH network OS families out of `query_all`.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    TrunkHostPolicyTypeEnum,
    XeTrunkHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceModel,
    XeEthernetTrunkHostPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class EthernetTrunkHostInterfaceOrchestrator(EthernetBaseOrchestrator):
    """
    # Summary

    Orchestrator for ethernet trunk-mode host interface CRUD operations on Nexus Dashboard.

    Inherits all shared ethernet logic from `EthernetBaseOrchestrator`. Defines `model_class` as
    `EthernetTrunkHostInterfaceModel` and manages the `trunkHost` (NX-OS) and `iosXeTrunkHost` (IOS-XE) policy types.

    Unlike the other ethernet orchestrators, normalizing a trunkHost interface produces another
    trunkHost interface (the fabric default policy is `int_trunk_host`), so normalized interfaces
    remain in scope of this orchestrator's policy filter. `query_all` therefore additionally filters
    out interfaces whose policy matches the unconfigured `int_trunk_host` default signature so that
    idempotent re-runs of `state: overridden` do not see already-normalized interfaces as items to
    re-normalize. The same holds for IOS-XE: the XE reset PUT lands a Catalyst port on a defaults-only
    `iosXeTrunkHost` (`XeEthernetTrunkHostPolicyModel.reverse_diff_defaults`), which is filtered here by the same rule.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `EthernetBaseOrchestrator` for full details.
    """

    model_class: ClassVar[type[NDBaseModel]] = EthernetTrunkHostInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the union of the NX-OS (`trunkHost`)
        and IOS-XE (`iosXeTrunkHost`) trunk-host policy types.

        ## Raises

        None
        """
        return {e.value for e in TrunkHostPolicyTypeEnum} | {e.value for e in XeTrunkHostPolicyTypeEnum}

    @staticmethod
    def _is_unconfigured_default(iface: dict) -> bool:
        """
        # Summary

        Return `True` if the given interface API response represents an unconfigured `int_trunk_host`
        default — `allowedVlans` is absent or `"none"`, `description` is absent or empty, `nativeVlan`
        is absent or `1`, and none of the Class C fields (`InterfaceDefaultConfig.UNRESETTABLE_FIELDS`)
        are set. Such an interface is indistinguishable from a freshly normalized one and should
        be treated as out-of-scope for `state: overridden` idempotency.

        For an IOS-XE `iosXeTrunkHost` record the signature is the `ios_xe_int_trunk_host` template default echo
        (`XeEthernetTrunkHostPolicyModel.reverse_diff_defaults`): every policy key other than `policyType` must match its
        default (an empty `description` counts as absent); any other key, including a 4.3.1-only field the model does not
        declare, or any non-default value keeps the interface in scope.

        Class C fields are checked because they survive `interfaceActions/normalize` (ND's validator
        rejects 0/null for them); leaving them out of this filter would hide a configured-but-stuck
        interface from `state: deleted` and prevent the orchestrator from dispatching it to the
        per-interface PUT-as-replace reset path.

        ## Raises

        None
        """
        policy = iface.get("configData", {}).get("networkOS", {}).get("policy", {}) or {}
        if policy.get("policyType") == XeTrunkHostPolicyTypeEnum.IOS_XE_TRUNK_HOST.value:
            return EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_xe_default(policy)
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

    @staticmethod
    def _is_unconfigured_xe_default(policy: dict) -> bool:
        """
        # Summary

        Return `True` if an `iosXeTrunkHost` wire policy is the `ios_xe_int_trunk_host` template default echo
        (`XeEthernetTrunkHostPolicyModel.reverse_diff_defaults`): every key other than `policyType` matches its default, an empty
        `description` counting as absent. Any other key (including a 4.3.1-only field the model does not declare) or any
        non-default value means the interface is user-configured.

        ## Raises

        None
        """
        defaults = XeEthernetTrunkHostPolicyModel.reverse_diff_defaults
        for key, value in policy.items():
            if key == "policyType" or (key == "description" and value in (None, "")):
                continue
            if key not in defaults or value != defaults[key]:
                return False
        return True

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Query all trunkHost interfaces in the fabric via the base orchestrator, then filter out interfaces
        that match the unconfigured `int_trunk_host` default signature. This keeps default-configured
        interfaces out of `before`, so `state: overridden` idempotency holds across re-runs.

        ## Raises

        ### RuntimeError

        - Propagated from `EthernetBaseOrchestrator.query_all` on query failure.
        """
        result = super().query_all(model_instance=model_instance, **kwargs)
        if not isinstance(result, list):
            return result
        return [iface for iface in result if not self._is_unconfigured_default(iface)]
