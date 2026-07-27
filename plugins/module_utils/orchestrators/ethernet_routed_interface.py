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

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    EthernetRoutedPolicyTypeEnum,
    XeEthernetRoutedPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_routed_interface import (
    EthernetRoutedInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator


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

    Unlike `EthernetTrunkHostInterfaceOrchestrator`, no unconfigured-default filter is needed: normalizing a
    routed interface (the delete path) produces a `trunkHost` interface, which leaves this orchestrator's
    policy filter entirely, so `state: overridden` idempotency holds without a default-signature check.

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
