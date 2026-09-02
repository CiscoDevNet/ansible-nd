# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Authoritative interface-family bindings for the aggregate workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.interface_config_normalizer import expand_ethernet_config
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import LoopbackPolicyTypeEnum, XeLoopbackPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlan, NDStatePlanner, SUPPORTED_STATES
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import EthernetAccessInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_access_interface import PortChannelAccessInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_managed_interface import (
    SubinterfaceManagedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_unmanaged_interface import (
    SubinterfaceUnmanagedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import SviInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_access_interface import AccessVpcHostInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_trunk_host_interface import TrunkVpcHostInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results

ConfigNormalizer = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
IMPLICIT_TRANSITION_STATES = frozenset({"merged", "replaced"})
LOOPBACK_POLICY_TYPES = frozenset(policy_type.value for policy_type in LoopbackPolicyTypeEnum) | frozenset(
    policy_type.value for policy_type in XeLoopbackPolicyTypeEnum
)


class InterfaceWorkflowValidationError(ValueError):
    """Raised when a resource group cannot be validated by its standalone family contract."""


class InterfaceTransitionStrategy(str, Enum):
    """Mutation method used when an interface changes policy family."""

    UPDATE = "update"


class InterfaceDeleteStrategy(str, Enum):
    """Controller operation used to remove or reset an interface."""

    NORMALIZE = "normalize"
    REMOVE = "remove"
    DELETE = "delete"


@dataclass(frozen=True)
class InterfaceFamilySafety:
    """Structural dependency guards required by an interface family."""

    requires_pair_consistency: bool = False
    owns_physical_members: bool = False
    guards_child_subinterfaces: bool = False


@dataclass(frozen=True)
class InterfaceFamilyAdapter:
    """Connect one workflow resource type to its existing model and orchestrator."""

    resource_type: str
    module_name: str
    orchestrator_class: type[NDBaseInterfaceOrchestrator]
    ownership_domain: str
    interface_types: frozenset[str]
    policy_types: frozenset[str]
    delete_strategy: InterfaceDeleteStrategy
    supports_intra_family_policy_transitions: bool = False
    transition_strategy: InterfaceTransitionStrategy = InterfaceTransitionStrategy.UPDATE
    transition_states: frozenset[str] = IMPLICIT_TRANSITION_STATES
    safety: InterfaceFamilySafety = InterfaceFamilySafety()
    config_normalizer: ConfigNormalizer | None = None
    supported_states: frozenset[str] = SUPPORTED_STATES

    @property
    def model_class(self) -> type[NDBaseModel]:
        """Return the concrete model already owned by the standalone orchestrator."""
        return self.orchestrator_class.model_class

    def validate_config(self, config: list[dict[str, Any]], state: str, resource_index: int) -> NDConfigCollection:
        """Normalize and validate config through the existing family model."""
        if state not in self.supported_states:
            choices = ", ".join(sorted(self.supported_states))
            raise InterfaceWorkflowValidationError(
                f"resources[{resource_index}] type '{self.resource_type}' does not support state '{state}'; supported states: {choices}."
            )
        if not isinstance(config, list):
            raise InterfaceWorkflowValidationError(
                f"resources[{resource_index}] type '{self.resource_type}' config must be a list using {self.module_name} input."
            )
        try:
            normalized = self.config_normalizer(config) if self.config_normalizer is not None else config
            return NDConfigCollection.from_ansible_config(data=normalized, model_class=self.model_class, context={"state": state})
        except Exception as exc:
            raise InterfaceWorkflowValidationError(
                f"resources[{resource_index}] type '{self.resource_type}' validation failed using {self.module_name} "
                f"({self.model_class.__name__}, state={state!r}): {exc}"
            ) from exc

    def build_orchestrator(
        self,
        *,
        rest_send: RestSend,
        snapshot: InterfaceStateSnapshot,
        results: Results | None = None,
    ) -> NDBaseInterfaceOrchestrator:
        """Construct the existing family orchestrator with the shared snapshot."""
        return self.orchestrator_class(rest_send=rest_send, results=results, interface_state_snapshot=snapshot)

    def existing_collection(self, orchestrator: NDBaseInterfaceOrchestrator) -> NDConfigCollection:
        """Select and deserialize existing family state through the existing query implementation."""
        try:
            response = orchestrator.query_all()
            return NDConfigCollection.from_api_response(response_data=response, model_class=self.model_class)
        except Exception as exc:
            raise InterfaceWorkflowValidationError(
                f"Existing-state selection for type '{self.resource_type}' failed through {self.module_name}: {exc}"
            ) from exc

    def plan(self, *, before: NDConfigCollection, proposed: NDConfigCollection, state: str) -> NDStatePlan:
        """Calculate operations using the shared pure state planner."""
        return NDStatePlanner.plan(state=state, before=before, proposed=proposed)


_ADAPTER_DEFINITIONS = (
    {
        "resource_type": "ethernet_access",
        "module_name": "cisco.nd.nd_interface_ethernet_access",
        "orchestrator_class": EthernetAccessInterfaceOrchestrator,
        "ownership_domain": "ethernet",
        "interface_types": frozenset({"ethernet"}),
        "policy_types": frozenset({"accessHost"}),
        "delete_strategy": InterfaceDeleteStrategy.NORMALIZE,
        "safety": InterfaceFamilySafety(guards_child_subinterfaces=True),
        "config_normalizer": expand_ethernet_config,
    },
    {
        "resource_type": "ethernet_trunk_host",
        "module_name": "cisco.nd.nd_interface_ethernet_trunk_host",
        "orchestrator_class": EthernetTrunkHostInterfaceOrchestrator,
        "ownership_domain": "ethernet",
        "interface_types": frozenset({"ethernet"}),
        "policy_types": frozenset({"trunkHost"}),
        "delete_strategy": InterfaceDeleteStrategy.NORMALIZE,
        "safety": InterfaceFamilySafety(guards_child_subinterfaces=True),
        "config_normalizer": expand_ethernet_config,
    },
    {
        "resource_type": "loopback",
        "module_name": "cisco.nd.nd_interface_loopback",
        "orchestrator_class": LoopbackInterfaceOrchestrator,
        "ownership_domain": "loopback",
        "interface_types": frozenset({"loopback"}),
        "policy_types": LOOPBACK_POLICY_TYPES,
        "delete_strategy": InterfaceDeleteStrategy.REMOVE,
        "supports_intra_family_policy_transitions": True,
    },
    {
        "resource_type": "port_channel_access",
        "module_name": "cisco.nd.nd_interface_port_channel_access",
        "orchestrator_class": PortChannelAccessInterfaceOrchestrator,
        "ownership_domain": "port_channel",
        "interface_types": frozenset({"portChannel"}),
        "policy_types": frozenset({"accessPoHost"}),
        "delete_strategy": InterfaceDeleteStrategy.REMOVE,
        "safety": InterfaceFamilySafety(owns_physical_members=True, guards_child_subinterfaces=True),
    },
    {
        "resource_type": "port_channel_trunk_host",
        "module_name": "cisco.nd.nd_interface_port_channel_trunk_host",
        "orchestrator_class": PortChannelTrunkHostInterfaceOrchestrator,
        "ownership_domain": "port_channel",
        "interface_types": frozenset({"portChannel"}),
        "policy_types": frozenset({"trunkPoHost"}),
        "delete_strategy": InterfaceDeleteStrategy.REMOVE,
        "safety": InterfaceFamilySafety(owns_physical_members=True, guards_child_subinterfaces=True),
    },
    {
        "resource_type": "subinterface_managed",
        "module_name": "cisco.nd.nd_interface_subinterface_managed",
        "orchestrator_class": SubinterfaceManagedInterfaceOrchestrator,
        "ownership_domain": "subinterface",
        "interface_types": frozenset({"subInterface"}),
        "policy_types": frozenset({"subinterface"}),
        "delete_strategy": InterfaceDeleteStrategy.REMOVE,
    },
    {
        "resource_type": "subinterface_unmanaged",
        "module_name": "cisco.nd.nd_interface_subinterface_unmanaged",
        "orchestrator_class": SubinterfaceUnmanagedInterfaceOrchestrator,
        "ownership_domain": "subinterface",
        "interface_types": frozenset({"subInterface"}),
        "policy_types": frozenset({"monitorSubinterface"}),
        "delete_strategy": InterfaceDeleteStrategy.REMOVE,
    },
    {
        "resource_type": "svi",
        "module_name": "cisco.nd.nd_interface_svi",
        "orchestrator_class": SviInterfaceOrchestrator,
        "ownership_domain": "svi",
        "interface_types": frozenset({"svi"}),
        "policy_types": frozenset({"svi"}),
        "delete_strategy": InterfaceDeleteStrategy.REMOVE,
    },
    {
        "resource_type": "vpc_access",
        "module_name": "cisco.nd.nd_interface_vpc_access",
        "orchestrator_class": AccessVpcHostInterfaceOrchestrator,
        "ownership_domain": "vpc",
        "interface_types": frozenset({"vpc"}),
        "policy_types": frozenset({"accessVpcHost"}),
        "delete_strategy": InterfaceDeleteStrategy.DELETE,
        "safety": InterfaceFamilySafety(requires_pair_consistency=True, owns_physical_members=True),
    },
    {
        "resource_type": "vpc_trunk_host",
        "module_name": "cisco.nd.nd_interface_vpc_trunk_host",
        "orchestrator_class": TrunkVpcHostInterfaceOrchestrator,
        "ownership_domain": "vpc",
        "interface_types": frozenset({"vpc"}),
        "policy_types": frozenset({"trunkVpcHost"}),
        "delete_strategy": InterfaceDeleteStrategy.DELETE,
        "safety": InterfaceFamilySafety(requires_pair_consistency=True, owns_physical_members=True),
    },
)

INTERFACE_FAMILY_ADAPTERS: dict[str, InterfaceFamilyAdapter] = {
    definition["resource_type"]: InterfaceFamilyAdapter(**definition) for definition in _ADAPTER_DEFINITIONS
}


def get_interface_family_adapter(resource_type: str) -> InterfaceFamilyAdapter:
    """Return a registered family adapter or raise a workflow-oriented validation error."""
    try:
        return INTERFACE_FAMILY_ADAPTERS[resource_type]
    except KeyError as exc:
        choices = ", ".join(INTERFACE_FAMILY_ADAPTERS)
        raise InterfaceWorkflowValidationError(f"Unsupported interface resource type '{resource_type}'; supported types: {choices}.") from exc
