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

from collections.abc import Sequence
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

    # Subclasses opt in to capability preflight by setting BOTH ClassVars (e.g. loopback sets
    # `interface_type = "loopback"` and `interface_mode = "managed"`). Leaving `interface_type` as ""
    # opts out — used by interface types with no capability endpoint (e.g. future breakout).
    interface_type: ClassVar[str] = ""
    interface_mode: ClassVar[str] = ""

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

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Run capability preflight for the proposed interfaces. Delegates to `validate_switches_capable`, which is a
        no-op unless the orchestrator opts in via the `interface_type`/`interface_mode` ClassVars. Invoked by
        `NDStateMachine.manage_state` before create/update operations so the check runs in `--check` mode, where the
        underlying mutations are skipped.

        ## Raises

        ### RuntimeError

        - Propagated from `validate_switches_capable` (see its docstring).
        """
        self.validate_switches_capable(model_instances)

    def validate_switches_capable(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-flight the set of target switches against the ND `capableSwitches` endpoint for this orchestrator's
        `interface_type` and `interface_mode` ClassVars. A single GET covers every target switch. On failure, raises a
        `RuntimeError` naming every offending switch.

        When `interface_type` is `""` (default on the base class) this method is a no-op — subclasses opt in by setting
        both the `interface_type` and `interface_mode` ClassVars.

        All `switch_ip` values are resolved before the capability check runs; if any are unresolvable, a single aggregate
        `RuntimeError` names every unknown IP so a typo on one entry does not mask resolution or capability problems on
        the remaining entries (issue #301).

        In `--check` mode the capability GET is still issued, but a failure of the capability check itself — whether an
        endpoint outage or one or more incapable switches — is downgraded to a warning rather than re-raised, so dry-runs
        stay green when the unpublished endpoint is unavailable (issue #302). Unresolvable `switch_ip` values are always
        raised, including in check mode, because they reflect user input errors rather than environmental flakiness.

        ## Raises

        ### RuntimeError

        - If one or more switches are not capable of hosting the requested `(interface_type, interface_mode)` pair
          (outside `--check` mode).
        - If the orchestrator sets `interface_type` but leaves `interface_mode` empty.
        - If one or more `switch_ip` values do not match any switch in the fabric (aggregated into a single message).
        - If the underlying capability GET request fails (outside `--check` mode).
        """
        if not self.interface_type:
            return
        if not self.interface_mode:
            raise RuntimeError(
                f"{type(self).__name__} sets interface_type but not interface_mode; both ClassVars are required to enable capability preflight."
            )
        switch_ids: set[str] = set()
        unresolved: list[str] = []
        for model_instance in model_instances:
            switch_ip = model_instance.switch_ip
            try:
                switch_ids.add(self._resolve_switch_id(switch_ip))
            except RuntimeError:
                unresolved.append(switch_ip)
        if unresolved:
            raise RuntimeError(f"Cannot resolve switch_ip to switchId in fabric '{self.fabric_name}' for: {', '.join(sorted(set(unresolved)))}.")
        if not switch_ids:
            return
        try:
            self.capability_preflight.validate(self.interface_type, self.interface_mode, switch_ids)
        except RuntimeError as e:
            if not self.rest_send.check_mode:
                raise
            self.rest_send.warn(f"Capability preflight skipped in check mode: {e}")

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
