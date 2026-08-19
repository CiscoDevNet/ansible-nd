# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import LuceneQueryParams
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
    VpcPairsListEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule as NDModuleV2
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import FinalizationContext
from ansible_collections.cisco.nd.plugins.module_utils.rest.retry_policy import RestRetryPolicy


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
    FINAL_READBACK_PAGE_SIZE: ClassVar[int] = 100

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
            # During NDStateMachine init, orchestrator is created with rest_send.
            # Use sender.ansible_module from RestSend for pre-bind query context.
            context = _VpcPairQueryContext(self.rest_send.sender.ansible_module)
        return custom_vpc_query_all(context)

    def query_final_state(self, context: FinalizationContext, retry_policy: RestRetryPolicy) -> list[dict[str, Any]]:
        """Read intended vPC pairs with pagination and authoritative per-pair details."""
        del context
        if self.state_machine is not None:
            module = self.state_machine.module
        else:
            module = self.rest_send.sender.ansible_module

        fabric_name = module.params.get("fabric_name")
        if not isinstance(fabric_name, str) or not fabric_name.strip():
            raise ValueError("fabric_name must be a non-empty string for vPC final readback")

        nd_v2 = NDModuleV2(module)
        rest_send = nd_v2.get_rest_send()
        with rest_send.use_retry_policy(retry_policy):
            pairs = self._query_intended_pairs(nd_v2, fabric_name)
            return self._query_pair_details(nd_v2, fabric_name, pairs)

    def _query_intended_pairs(self, nd_v2: NDModuleV2, fabric_name: str) -> list[tuple[str, str]]:
        """Return unique intended pair identifiers from every list page."""
        offset = 0
        pairs: dict[tuple[str, str], tuple[str, str]] = {}

        while True:
            endpoint = EpVpcPairsListGet(
                fabric_name=fabric_name,
                endpoint_params=VpcPairsListEndpointParams(view="intendedPairs"),
                lucene_params=LuceneQueryParams(max=self.FINAL_READBACK_PAGE_SIZE, offset=offset),
            )
            response = nd_v2.request(endpoint.path, HttpVerbEnum.GET)
            if not isinstance(response, dict):
                raise ValueError(f"vPC intended-pairs list returned {type(response).__name__}, expected dict")
            page = response.get("vpcPairs")
            if not isinstance(page, list):
                raise ValueError("vPC intended-pairs list response is missing vpcPairs")

            previous_count = len(pairs)
            for item in page:
                if not isinstance(item, dict):
                    raise ValueError("vPC intended-pairs list contains a non-dictionary record")
                switch_id = item.get("switchId")
                peer_switch_id = item.get("peerSwitchId")
                if not isinstance(switch_id, str) or not isinstance(peer_switch_id, str):
                    raise ValueError("vPC intended-pairs record is missing switchId or peerSwitchId")
                key = tuple(sorted((switch_id, peer_switch_id)))
                pairs.setdefault(key, (switch_id, peer_switch_id))

            counts = response.get("meta", {}).get("counts", {}) if isinstance(response.get("meta"), dict) else {}
            remaining = counts.get("remaining") if isinstance(counts, dict) else None
            total = counts.get("total") if isinstance(counts, dict) else None
            offset += len(page)

            if isinstance(remaining, int):
                if remaining <= 0:
                    break
                if not page:
                    raise ValueError("vPC intended-pairs pagination reported remaining records without progress")
                continue
            if isinstance(total, int):
                if offset >= total:
                    break
                if not page:
                    raise ValueError("vPC intended-pairs pagination did not advance toward total")
                continue
            if len(page) < self.FINAL_READBACK_PAGE_SIZE:
                break
            if len(pairs) == previous_count:
                raise ValueError("vPC intended-pairs pagination repeated a full page")

        return list(pairs.values())

    @staticmethod
    def _query_pair_details(nd_v2: NDModuleV2, fabric_name: str, pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
        """Return one complete detail record per unique intended pair."""
        details: list[dict[str, Any]] = []
        for switch_id, peer_switch_id in pairs:
            endpoint = EpVpcPairGet(fabric_name=fabric_name, switch_id=switch_id)
            detail = nd_v2.request(endpoint.path, HttpVerbEnum.GET)
            if not isinstance(detail, dict):
                raise ValueError(f"vPC pair detail for {switch_id} returned {type(detail).__name__}, expected dict")
            detail_switch_id = detail.get("switchId")
            detail_peer_switch_id = detail.get("peerSwitchId")
            if not isinstance(detail_switch_id, str) or not isinstance(detail_peer_switch_id, str):
                raise ValueError(f"vPC pair detail for {switch_id} is missing switchId or peerSwitchId")
            if tuple(sorted((detail_switch_id, detail_peer_switch_id))) != tuple(sorted((switch_id, peer_switch_id))):
                raise ValueError(f"vPC intended list and detail endpoints disagree for pair {switch_id}/{peer_switch_id}")
            details.append(detail)
        return details

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
