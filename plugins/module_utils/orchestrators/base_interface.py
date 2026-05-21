# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Base interface orchestrator for Nexus Dashboard.

Provides `NDBaseInterfaceOrchestrator`, an intermediate base class between `NDBaseOrchestrator` and
concrete interface orchestrators (loopback, ethernet, port-channel, etc.). Encapsulates shared
interface lifecycle operations: deploy queuing, bulk deploy/remove via `interfaceActions` endpoints,
switch IP-to-serial resolution, and fabric pre-flight validation via `FabricContext`.

Concrete interface orchestrators inherit from this class and implement their own CRUD methods
with interface-type-specific payload construction and query filtering.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDeploy,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_capability_preflight import InterfaceCapabilityPreflight
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import ModelType, NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class NDBaseInterfaceOrchestrator(NDBaseOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for interface CRUD operations on Nexus Dashboard.

    Provides shared infrastructure for all interface types: deploy/remove queuing, bulk deploy/remove
    via `interfaceActions` endpoints, switch IP-to-serial resolution via `FabricContext`, and fabric
    pre-flight validation.

    Concrete interface orchestrators (loopback, ethernet, port-channel, etc.) inherit from this class
    and implement their own CRUD methods with interface-type-specific payload construction and query filtering.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    """

    deploy: bool = True

    # Subclasses override to enable capability preflight (e.g. `interface_type: ClassVar[str] = "loopback"`).
    # An empty string opts out — used by interface types with no capability endpoint (e.g. future breakout).
    interface_type: ClassVar[str] = ""

    _fabric_context: FabricContext | None = None
    _capability_preflight: InterfaceCapabilityPreflight | None = None

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize mutable private state after Pydantic model construction. Pydantic disallows `Field()` on
        underscore-prefixed names, so these are set here to ensure each instance gets its own list.

        ## Raises

        None
        """
        self._pending_deploys: list[tuple[str, str]] = []
        self._pending_removes: list[tuple[str, str]] = []

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return `fabric_name` from module params.

        ## Raises

        None
        """
        return self.rest_send.params.get("fabric_name")

    @property
    def fabric_context(self) -> FabricContext:
        """
        # Summary

        Return a lazily-initialized `FabricContext` for this orchestrator's fabric.

        ## Raises

        None
        """
        if self._fabric_context is None:
            self._fabric_context = FabricContext(rest_send=self.rest_send, fabric_name=self.fabric_name)
        return self._fabric_context

    def _resolve_switch_id(self, switch_ip: str) -> str:
        """
        # Summary

        Resolve a `switch_ip` to its `switchId` via `FabricContext`.

        ## Raises

        ### RuntimeError

        - If no switch matches the given IP in the fabric.
        """
        return self.fabric_context.get_switch_id(switch_ip)

    @property
    def capability_preflight(self) -> InterfaceCapabilityPreflight:
        """
        # Summary

        Return a lazily-initialized `InterfaceCapabilityPreflight` for this orchestrator's fabric. Shares the orchestrator's
        `FabricContext` so error messages for incapable switches are enriched with `switch_ip`.

        ## Raises

        None
        """
        if self._capability_preflight is None:
            self._capability_preflight = InterfaceCapabilityPreflight(
                rest_send=self.rest_send,
                fabric_name=self.fabric_name,
                fabric_context=self.fabric_context,
            )
        return self._capability_preflight

    def _resolve_mode(self, model_instance: ModelType) -> str:
        """
        # Summary

        Return the `mode` string for a model instance, used to key the capability preflight cache. Defaults to
        `model_instance.mode`. Subclasses override only when the model has no `mode` attribute or the mapping is non-trivial.

        ## Raises

        ### AttributeError

        - If the model has no `mode` attribute and the subclass has not overridden this method.
        """
        # getattr (not direct access): ModelType is bound to NDBaseModel, which has no `mode`. The
        # attribute is duck-typed -- present on most interface models, absent on some (e.g. loopback).
        return getattr(model_instance, "mode")

    def validate_switches_capable(self, model_instances: Iterable[ModelType]) -> None:
        """
        # Summary

        Pre-flight the set of target switches against the ND `capableSwitches` endpoint for this orchestrator's
        `interface_type` and the per-instance `mode`. Groups instances by `(interface_type, mode)` so a single GET covers
        all instances sharing the same pair. On failure, raises a single aggregate `RuntimeError` naming every offending
        switch across all groups.

        When `interface_type` is `""` (default on the base class) this method is a no-op — subclasses opt in by setting
        the `ClassVar`.

        ## Raises

        ### RuntimeError

        - If one or more switches are not capable of hosting the requested `(interface_type, mode)` pair.
        - If no switch matches a given `switch_ip` in the fabric.
        - If the underlying capability GET request fails.
        """
        if not self.interface_type:
            return
        groups: dict[tuple[str, str], set[str]] = defaultdict(set)
        for model_instance in model_instances:
            mode = self._resolve_mode(model_instance)
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            groups[(self.interface_type, mode)].add(switch_id)

        errors: list[str] = []
        for (interface_type, mode), switch_ids in groups.items():
            try:
                self.capability_preflight.validate(interface_type, mode, switch_ids)
            except RuntimeError as e:
                errors.append(str(e))
        if errors:
            raise RuntimeError(" | ".join(errors))

    def validate_prerequisites(self) -> None:
        """
        # Summary

        Run pre-flight validation before any CRUD operations. Checks that the fabric exists and is modifiable.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode.
        """
        self.fabric_context.validate_for_mutation()

    def _configure_endpoint(self, api_endpoint, switch_sn: str):
        """
        # Summary

        Set `fabric_name` and `switch_sn` on an endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_sn = switch_sn
        return api_endpoint

    def _queue_deploy(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred deployment. Call `deploy_pending` after all mutations
        are complete to deploy in bulk.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_deploys:
            self._pending_deploys.append(pair)

    def _queue_remove(self, interface_name: str, switch_id: str) -> None:
        """
        # Summary

        Queue an `(interface_name, switch_id)` pair for deferred bulk removal. Call `remove_pending` after all mutations
        are complete to remove in bulk.

        ## Raises

        None
        """
        pair = (interface_name, switch_id)
        if pair not in self._pending_removes:
            self._pending_removes.append(pair)

    def deploy_pending(self) -> ResponseType | None:
        """
        # Summary

        Deploy all queued interface configurations in a single API call via `interfaceActions/deploy`. Clears the pending
        queue after deployment.

        When `deploy` is `False`, returns `None` without making any API call.

        ## Raises

        ### RuntimeError

        - If the deploy API request fails.
        """
        if not self.deploy or not self._pending_deploys:
            return None
        try:
            result = self._deploy_interfaces()
            self._pending_deploys = []
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk deploy failed for interfaces {self._pending_deploys}: {e}") from e

    def _deploy_interfaces(self) -> ResponseType:
        """
        # Summary

        Deploy queued interfaces via `interfaceActions/deploy`. Sends the explicit list of `{interfaceName, switchId}` pairs.

        ## Raises

        ### Exception

        - If the deploy API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesDeploy()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in self._pending_deploys]}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

    def remove_pending(self) -> ResponseType | None:
        """
        # Summary

        Remove all queued interfaces in a single API call via `interfaceActions/remove`. Clears the pending queue after removal.

        Returns `None` without making any API call if the queue is empty.

        ## Raises

        ### RuntimeError

        - If the remove API request fails.
        """
        if not self._pending_removes:
            return None
        try:
            result = self._remove_interfaces()
            self._pending_removes = []
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk remove failed for interfaces {self._pending_removes}: {e}") from e

    def _remove_interfaces(self) -> ResponseType:
        """
        # Summary

        Remove queued interfaces via `interfaceActions/remove`. Sends the explicit list of `{interfaceName, switchId}` pairs.

        ## Raises

        ### Exception

        - If the remove API request fails (propagated to caller).
        """
        api_endpoint = EpManageInterfacesRemove()
        api_endpoint.fabric_name = self.fabric_name
        payload = {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in self._pending_removes]}
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
