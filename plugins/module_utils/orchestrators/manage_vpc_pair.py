# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from typing import Any, Optional

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.model import (
    VpcPairModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_manage_vpc_pair_actions import (
    custom_vpc_create,
    custom_vpc_delete,
    custom_vpc_update,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_manage_vpc_pair_query import (
    custom_vpc_query_all,
)


class _VpcPairQueryContext:
    """Minimal context object for query_all during NDStateMachine initialization."""

    def __init__(self, module: AnsibleModule):
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
        module: Optional[AnsibleModule] = None,
        sender: Optional[Any] = None,
        **kwargs,
    ):
        _ = kwargs
        if module is None and sender is not None:
            module = getattr(sender, "module", None)
        if module is None:
            raise ValueError(
                "VpcPairOrchestrator requires either module=AnsibleModule "
                "or sender=<NDModule with .module>."
            )

        self.module = module
        self.sender = sender
        self.state_machine = None

    def bind_state_machine(self, state_machine: Any) -> None:
        self.state_machine = state_machine

    def query_all(self):
        # Optional performance knob: skip initial query used to build "before"
        # state and baseline diff in NDStateMachine initialization.
        if self.state_machine is None and self.module.params.get("suppress_previous", False):
            return []

        context = (
            self.state_machine
            if self.state_machine is not None
            else _VpcPairQueryContext(self.module)
        )
        return custom_vpc_query_all(context)

    def create(self, model_instance, **kwargs):
        _ = (model_instance, kwargs)
        if self.state_machine is None:
            raise RuntimeError("VpcPairOrchestrator is not bound to a state machine")
        return custom_vpc_create(self.state_machine)

    def update(self, model_instance, **kwargs):
        _ = (model_instance, kwargs)
        if self.state_machine is None:
            raise RuntimeError("VpcPairOrchestrator is not bound to a state machine")
        return custom_vpc_update(self.state_machine)

    def delete(self, model_instance, **kwargs):
        _ = (model_instance, kwargs)
        if self.state_machine is None:
            raise RuntimeError("VpcPairOrchestrator is not bound to a state machine")
        return custom_vpc_delete(self.state_machine)
