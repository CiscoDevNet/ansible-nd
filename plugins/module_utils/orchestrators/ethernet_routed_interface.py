# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ethernet routed-mode interface orchestrator for Nexus Dashboard (issue #447).

This module provides `EthernetRoutedInterfaceOrchestrator`, which manages CRUD operations for
ethernet routed-mode interfaces. It inherits all shared ethernet logic from `EthernetBaseOrchestrator`
(including the normalize-based delete for physical interfaces and the port-channel-membership guards)
and only defines the model class and managed policy types.

L3 routed IS supported on VXLAN fabrics: the GUI create wizard's "0 capable switches" is the unpublished
`capableSwitches` endpoint's create-wizard semantics surfacing in the UI, not a mode-capability verdict —
both the per-interface PUT and the bulk POST accept `routedHost` on a VXLAN leaf (lab-verified 2026-07-27).
"""

from __future__ import annotations

import logging
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    EthernetRoutedPolicyTypeEnum,
    XeEthernetRoutedPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_routed_interface import (
    EthernetRoutedInterfaceModel,
    normalize_ethernet_interface_name,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

logger = logging.getLogger(__name__)

# Wire-form schema defaults per managed policy type (values as ND dumps them). An interface whose policy
# carries ONLY these keys at these values is an unconfigured fabric default. `ptp` is an ND-injected read
# key (absent from intRoutedHostTemplate) and counts as default. These values converge with the models'
# reverse_diff_defaults tables when this branch rebases past PR #422 - keep the two in sync then.
_UNCONFIGURED_DEFAULT_SIGNATURES: dict[str, dict] = {
    "routedHost": {
        "adminState": True,
        "fec": "auto",
        "ipRedirects": False,
        "mtu": 9216,
        "netflow": False,
        "pfc": False,
        "pimDrPriority": 1,
        "pimSparse": False,
        "ptp": False,
        "qos": False,
        "speed": "auto",
    },
    "iosXeRoutedHost": {
        "adminState": True,
        "mtu": 1500,
        "speed": "auto",
    },
}


class EthernetRoutedInterfaceOrchestrator(EthernetBaseOrchestrator):
    """
    # Summary

    Orchestrator for ethernet routed-mode interface CRUD operations on Nexus Dashboard.

    Inherits all shared ethernet logic from `EthernetBaseOrchestrator`. Defines `model_class` as
    `EthernetRoutedInterfaceModel` and manages the `routedHost` (NX-OS) and `iosXeRoutedHost` (IOS-XE)
    policy types.

    The managed-set filter in `query_all` (via `_managed_policy_types`) is this module's underlay-safety
    boundary: the wire carries many system routed policy types (`numbered` fabric links, `multiSiteLinkMember`,
    `vrfLiteLinkMember`, `vpcPeerKeepAlive`, `mplsUplink`, `csrMultisiteIfcMember`, ...) that share
    `configData.mode: "routed"` with the managed types. Filtering by policy type — never by mode — keeps
    fabric underlay intent out of `before[]`, so `state: overridden` cannot bulldoze it. Treat any loosening
    of this filter as review-blocking.

    Like `EthernetTrunkHostInterfaceOrchestrator`, this orchestrator filters unconfigured fabric defaults out of
    `query_all` - but for the opposite reason. ND's fabric default interface policy is ROLE-DEPENDENT
    (lab-verified 2026-07-27): leaf free ports default to `trunkHost`, while EVERY unused port on a
    borderGateway defaults to a defaults-only `routedHost` (and core-router IOS-XE ports to `iosXeRoutedHost`).
    Without the `_is_unconfigured_default` filter, all of those ports would land in `before[]` and
    `state: overridden` would normalize every unused port on the switch. Treat any loosening of this filter
    as review-blocking, alongside the managed-set filter above.

    A mode flip (trunk -> routed) needs no special handling: a trunk-intent interface is invisible to
    `before[]` (not in the managed set), so the state machine classifies the task as a create, and the
    create POST rewrites the intent to routed (lab-verified 2026-07-27).

    Per-item HTTP 207 result validation is intentionally NOT duplicated here: the known masking trigger
    (mixed policy types in one bulk POST) cannot occur in this module's initial scope — each switch runs one
    network OS, so per-switch bulk groups are single-policy-type by construction. PR #398 adds 207 detection
    centrally in `NdV1Strategy`; the feature-gated follow-up branches (`endPointLocator`, `ipfmL3Port`,
    `dataBrokerL3Host`) must adopt per-(switch, policy_type) grouping when they land.

    ## Raises

    ### RuntimeError

    - Via inherited methods. See `EthernetBaseOrchestrator` for full details.
    """

    model_class: ClassVar[type[NDBaseModel]] = EthernetRoutedInterfaceModel

    # TODO(4.2.1) capable-switches-empty-for-ethernet-on-vxlan
    # Deliberate opt-OUT of the capability preflight (both ClassVars ""): the unpublished capableSwitches
    # endpoint returns an empty switches[] for EVERY ethernet mode (trunk, access, routed) on a VXLAN fabric —
    # it answers "where can the GUI wizard create an interface of this type" (physical ports already exist,
    # so: nowhere), not "which switches support this mode" — while the write paths for routedHost succeed.
    # Opting in with ("ethernet", "routed") would veto every switch for an operation the API accepts.
    interface_type: ClassVar[str] = ""
    interface_mode: ClassVar[str] = ""

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator: the union of the NX-OS
        (`routedHost`) and IOS-XE (`iosXeRoutedHost`) managed routed policy types. System routed policy types and
        `userDefined` are excluded — see the class docstring's underlay-safety note.

        ## Raises

        None
        """
        return {e.value for e in EthernetRoutedPolicyTypeEnum} | {e.value for e in XeEthernetRoutedPolicyTypeEnum}

    def delete_bulk(self, model_instances: list, **kwargs) -> None:
        """
        # Summary

        Queue interfaces for deferred reset, treating IOS-XE interfaces as merge-only under `state: overridden`:
        the fabric-wide overridden delete set never includes an `ios-xe` interface, because IOS-XE fabric links can
        carry plain configured `iosXeRoutedHost` with no intent-side ownership marker (lab-verified 2026-07-27:
        WAN1's multisite link) — a policy-type-scoped delete set would strip real fabric links. Skipped interfaces
        are logged at INFO. Interfaces the user names explicitly under `state: deleted` are always honored.

        NX-OS interfaces delegate unchanged to `EthernetBaseOrchestrator.delete_bulk` (port-channel guards,
        normalize/reset queueing).

        ## Raises

        ### RuntimeError

        - Propagated from `EthernetBaseOrchestrator.delete_bulk` (switch resolution, port-channel restrictions,
          interface-list query failures).
        """
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        if state == "overridden":
            kept: list = []
            for model_instance in model_instances:
                network_os = model_instance.config_data.network_os if model_instance.config_data else None
                if network_os is not None and network_os.network_os_type == "ios-xe":
                    logger.info(
                        "Skipping IOS-XE interface %s on switch %s during state:overridden (IOS-XE interfaces are merge-only)",
                        model_instance.interface_name,
                        model_instance.switch_ip,
                    )
                    continue
                kept.append(model_instance)
            model_instances = kept
        super().delete_bulk(model_instances, **kwargs)

    @staticmethod
    def _is_unconfigured_default(iface: dict) -> bool:
        """
        # Summary

        Return `True` if the given interface API response represents an unconfigured fabric-default routed interface:
        every key in its policy is either `policyType` or matches the wire-form schema default for that policy type
        (`_UNCONFIGURED_DEFAULT_SIGNATURES`). Any other key present (`ip`, `prefix`, `description`, `routingTag`,
        `vrfInterface`, ...) or any non-default value means the interface is user-configured and stays in scope.

        On switches whose fabric default interface policy is routed (borderGateway NX-OS ports, core-router IOS-XE
        ports), this predicate is the only thing keeping every unused port out of `before[]` — see the class docstring.

        ## Raises

        None
        """
        policy = ((iface.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
        policy_type = policy.get("policyType")
        if not isinstance(policy_type, str):
            return False
        defaults = _UNCONFIGURED_DEFAULT_SIGNATURES.get(policy_type)
        if defaults is None:
            return False
        for key, value in policy.items():
            if key == "policyType":
                continue
            if key not in defaults or value != defaults[key]:
                return False
        return True

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Query all managed routed interfaces in the fabric via the base orchestrator, then apply two scope filters:

        1. Drop interfaces matching an unconfigured fabric-default signature, keeping default-routed free ports
           (borderGateway / core-router fabric defaults) out of `before[]` so `state: overridden` converges only
           user-configured interfaces and idempotency holds across re-runs.
        2. Under `state: overridden`, drop IOS-XE interfaces that are not named in the task config (XE merge-only).
           This must happen at query scope — not merely at delete time — so the state machine never computes delete
           intent for them and the module's changed/diff reporting stays truthful. Config names are canonicalized
           with the same normalizer the model uses, so abbreviated or re-cased names match the wire form.

        ## Raises

        ### RuntimeError

        - Propagated from `EthernetBaseOrchestrator.query_all` on query failure.
        """
        result = super().query_all(model_instance=model_instance, **kwargs)
        if not isinstance(result, list):
            return result
        result = [iface for iface in result if not self._is_unconfigured_default(iface)]
        state = self.rest_send.params.get("state") if self.rest_send and self.rest_send.params else None
        if state == "overridden":
            named = {
                (item.get("switch_ip"), normalize_ethernet_interface_name(item.get("interface_name")))
                for item in (self.rest_send.params.get("config") or [])
                if isinstance(item, dict)
            }
            result = [
                iface
                for iface in result
                if ((iface.get("configData") or {}).get("networkOS") or {}).get("networkOSType") != "ios-xe"
                or (iface.get("switchIp"), iface.get("interfaceName")) in named
            ]
        return result
