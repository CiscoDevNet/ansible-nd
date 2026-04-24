# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import (
    NDBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_model import (
    VpcPairModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.actions import (
    custom_vpc_create,
    custom_vpc_delete,
    custom_vpc_update,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.query import (
    custom_vpc_query_all,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import (
    EpVpcPairGet,
    EpVpcPairPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vpc_pairs import (
    EpVpcPairsListGet,
)


class _VpcPairQueryContext:
    """
    Minimal context object for query_all during NDStateMachine initialization.

    Provides a .module attribute so custom_vpc_query_all can access module params
    before the full state machine is constructed.
    """

    def __init__(self, module: Any) -> None:
        """
        Initialize query context.

        Args:
            module: Module-like object with .params / .warn
        """
        self.module = module


class VpcPairOrchestrator(NDBaseOrchestrator[VpcPairModel]):
    """
    VPC orchestrator implementation for NDStateMachine.

    Delegates CRUD operations to vPC handlers while staying compatible with
    sender/module constructor styles used by shared NDStateMachine variants.
    """

    model_class: ClassVar[type[NDBaseModel]] = VpcPairModel
    create_endpoint: type[NDEndpointBaseModel] = EpVpcPairPut
    update_endpoint: type[NDEndpointBaseModel] = EpVpcPairPut
    delete_endpoint: type[NDEndpointBaseModel] = EpVpcPairPut
    query_one_endpoint: type[NDEndpointBaseModel] = EpVpcPairGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpVpcPairsListGet
    state_machine: Any | None = None

    def bind_state_machine(self, state_machine: Any) -> None:
        """
        Link orchestrator to its parent state machine.

        Args:
            state_machine: VpcPairStateMachine instance for CRUD handler access
        """
        self.state_machine = state_machine

    def query_all(self) -> list[dict[str, Any]]:
        """
        Query all existing vPC pairs from the controller.

        Delegates to custom_vpc_query_all for discovery and runtime context.

        Returns:
            List of existing pair dicts for NDConfigCollection initialization.
        """
        if self.state_machine is not None:
            context = self.state_machine
        else:
            context = _VpcPairQueryContext(self.sender.module)
        return custom_vpc_query_all(context)

    def create(self, model_instance: Any, **kwargs: Any) -> dict[str, Any] | None:
        """
        Create a new vPC pair via custom_vpc_create handler.

        Args:
            model_instance: VpcPairModel instance (unused, context from state machine)
            **kwargs: Ignored

        Returns:
            API response from create operation.

        Raises:
            RuntimeError: If orchestrator is not bound to a state machine
        """
        del model_instance, kwargs
        if self.state_machine is None:
            raise RuntimeError("VpcPairOrchestrator is not bound to a state machine")
        return custom_vpc_create(self.state_machine)

    def update(self, model_instance: Any, **kwargs: Any) -> dict[str, Any] | None:
        """
        Update an existing vPC pair via custom_vpc_update handler.

        Args:
            model_instance: VpcPairModel instance (unused, context from state machine)
            **kwargs: Ignored

        Returns:
            API response from update operation.

        Raises:
            RuntimeError: If orchestrator is not bound to a state machine
        """
        del model_instance, kwargs
        if self.state_machine is None:
            raise RuntimeError("VpcPairOrchestrator is not bound to a state machine")
        return custom_vpc_update(self.state_machine)

    def delete(self, model_instance: Any, **kwargs: Any) -> bool:
        """
        Delete a vPC pair via custom_vpc_delete handler.

        Args:
            model_instance: VpcPairModel instance (unused, context from state machine)
            **kwargs: Ignored

        Returns:
            API response from delete operation, or False if already unpaired.

        Raises:
            RuntimeError: If orchestrator is not bound to a state machine
        """
        del model_instance, kwargs
        if self.state_machine is None:
            raise RuntimeError("VpcPairOrchestrator is not bound to a state machine")
        return custom_vpc_delete(self.state_machine)
