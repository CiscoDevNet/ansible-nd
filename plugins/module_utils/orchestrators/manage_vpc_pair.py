# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, Optional
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


class VpcPairOrchestrator:
    """
    VPC orchestrator implementation for NDStateMachine.

    Delegates CRUD operations to vPC handlers while staying compatible with
    sender/module constructor styles used by shared NDStateMachine variants.
    """

    model_class = VpcPairModel

    def __init__(
        self,
        module: Optional[Any] = None,
        sender: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize VpcPairOrchestrator.

        Args:
            module: Module-like object with .params / .warn (preferred)
            sender: Optional NDModule/NDModuleV2 with .module attribute
            **kwargs: Ignored (for framework compatibility)

        Raises:
            ValueError: If neither module nor sender provides a module object
        """
        # TODO: Decouple module_utils orchestration from AnsibleModule by passing
        # a lightweight runtime context from main() (e.g., params + warning sink)
        # instead of module/sender objects with framework-specific attributes.
        del kwargs
        if module is None and sender is not None:
            module = getattr(sender, "module", None)
        if module is None:
            raise ValueError("VpcPairOrchestrator requires either module=AnsibleModule or sender=<NDModule with .module>.")

        self.module = module
        self.sender = sender
        self.state_machine = None

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
        context = self.state_machine if self.state_machine is not None else _VpcPairQueryContext(self.module)
        return custom_vpc_query_all(context)

    def create(self, model_instance: Any, **kwargs: Any) -> Optional[dict[str, Any]]:
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

    def update(self, model_instance: Any, **kwargs: Any) -> Optional[dict[str, Any]]:
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
