# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
vPC pair orchestrator for Nexus Dashboard.

Direct subclass of `NDBaseOrchestrator` (a vPC pair is not an interface, so this orchestrator does NOT inherit
from `NDBaseInterfaceOrchestrator` or `PortChannelBaseOrchestrator`).

## Two-stage lifecycle

ND models pair lifecycle as a two-stage operation:

1. **Intent**: `PUT /api/v1/manage/fabrics/{fabric}/switches/{switch_sn}/vpcPair` — sets the pair config (or unpair).
   Returns 204 No Content. Visible at the per-switch GET endpoint immediately.
2. **Deploy**: `POST /api/v1/manage/fabrics/{fabric}/switchActions/deploy` body `{"switchIds":[le1,le2]}` — pushes the
   intent to the wire. Returns 207 multi-status. ND switch poller propagates discovery state ~30-40s later.

This orchestrator queues both peer serials for deploy after every mutation (`create` / `update` / `delete`) and
flushes the queue via `deploy_pending` at the end of the module run.

## 207 status parsing

The `switchActions/deploy` response key is `switchIds` (NOT `results` — that key is reserved for `interfaceActions/remove`).
Per-switch `status` is compared case-insensitively because lab observation showed mixed casing across endpoints.
"""

from __future__ import annotations

from typing import ClassVar, List, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_switch_actions_deploy import (
    EpManageFabricSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_switch_vpc_pair import (
    EpManageFabricSwitchVpcPairGet,
    EpManageFabricSwitchVpcPairPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_vpc_pairs import (
    EpManageFabricVpcPairsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.vpc.vpc_pair import VpcPairModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class VpcPairOrchestrator(NDBaseOrchestrator[VpcPairModel]):
    """
    # Summary

    Orchestrator for vPC pair CRUD on Nexus Dashboard. PUT vpcPair sets intent; switchActions/deploy pushes to the wire.
    Both peer serials are queued for deploy after every mutation and flushed via `deploy_pending` at module-end.

    ## Raises

    ### RuntimeError

    - Via `_resolve_switch_id` if `switch_ip` or `peer_switch_ip` cannot be mapped to a switch in the fabric.
    - Via `create` / `update` / `delete` if the underlying API request fails.
    - Via `query_one` if the per-switch GET fails (404 maps to `None`, not an error).
    - Via `query_all` if the fabric-wide list GET fails.
    - Via `deploy_pending` if the deploy POST fails or any per-switch status is not "success" (case-insensitive).
    """

    model_class: ClassVar[Type[NDBaseModel]] = VpcPairModel

    create_endpoint: Type[NDEndpointBaseModel] = EpManageFabricSwitchVpcPairPut
    update_endpoint: Type[NDEndpointBaseModel] = EpManageFabricSwitchVpcPairPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageFabricSwitchVpcPairPut
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageFabricSwitchVpcPairGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageFabricVpcPairsListGet

    deploy_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpManageFabricSwitchActionsDeployPost

    deploy: bool = True

    _fabric_context: FabricContext | None = None

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize per-instance mutable state after Pydantic construction. Pydantic disallows `Field()` on
        underscore-prefixed names, so private state is set here.

        ## Raises

        None
        """
        self._pending_deploy_switch_ids: List[str] = []

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return `fabric_name` from module params (sourced via the `RestSend` `params` dict).

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

    def _configure_switch_endpoint(self, api_endpoint, switch_sn: str):
        """
        # Summary

        Set `fabric_name` and `switch_sn` on a per-switch endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_sn = switch_sn
        return api_endpoint

    def _queue_deploy_switch(self, switch_id: str) -> None:
        """
        # Summary

        Queue a `switch_id` for deferred deployment. Idempotent — re-queueing the same serial is a no-op.

        ## Raises

        None
        """
        if switch_id not in self._pending_deploy_switch_ids:
            self._pending_deploy_switch_ids.append(switch_id)

    def _resolve_and_queue_pair(self, model_instance: VpcPairModel) -> tuple[str, str]:
        """
        # Summary

        Resolve both peer IPs to serials, populate them on the model (so `to_payload()` emits the correct
        `switchId` / `peerSwitchId` values), and queue both for deploy. Returns the resolved (peer1, peer2) serials.

        ## Raises

        ### RuntimeError

        - If either peer IP cannot be resolved to a switch in the fabric.
        """
        switch_id = self._resolve_switch_id(model_instance.switch_ip)
        peer_switch_id = self._resolve_switch_id(model_instance.peer_switch_ip)
        model_instance.switch_id = switch_id
        model_instance.peer_switch_id = peer_switch_id
        self._queue_deploy_switch(switch_id)
        self._queue_deploy_switch(peer_switch_id)
        return switch_id, peer_switch_id

    def create(self, model_instance: VpcPairModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a vPC pair via PUT vpcPair (vpcAction=pair). Resolves both peer IPs to serials, configures the
        per-switch endpoint, and queues both serials for deferred deploy.

        ## Raises

        ### RuntimeError

        - If the create API request fails or peer resolution fails.
        """
        try:
            model_instance.vpc_action = "pair"
            switch_id, _ = self._resolve_and_queue_pair(model_instance)
            api_endpoint = self._configure_switch_endpoint(self.create_endpoint(), switch_sn=switch_id)
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: VpcPairModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update an existing vPC pair via PUT vpcPair (vpcAction=pair). PUT is idempotent at the intent layer.

        ## Raises

        ### RuntimeError

        - If the update API request fails or peer resolution fails.
        """
        try:
            model_instance.vpc_action = "pair"
            switch_id, _ = self._resolve_and_queue_pair(model_instance)
            api_endpoint = self._configure_switch_endpoint(self.update_endpoint(), switch_sn=switch_id)
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: VpcPairModel, **kwargs) -> ResponseType:
        """
        # Summary

        Tear down a vPC pair via PUT vpcPair with `{"vpcAction": "unPair"}`. ND cascades the unpair to all member
        vPC interfaces — the orchestrator does NOT need to pre-delete `nd_interface_vpc_*` members.

        ## Raises

        ### RuntimeError

        - If the delete API request fails or peer resolution fails.
        """
        try:
            model_instance.vpc_action = "unPair"
            switch_id, _ = self._resolve_and_queue_pair(model_instance)
            api_endpoint = self._configure_switch_endpoint(self.delete_endpoint(), switch_sn=switch_id)
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data={"vpcAction": "unPair"})
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: VpcPairModel, **kwargs) -> VpcPairModel | None:
        """
        # Summary

        Query the per-switch vPC pair intent for the model's `switch_ip`. Returns `None` when ND returns 404
        (no pair exists). Otherwise returns a populated `VpcPairModel`.

        ## Raises

        ### RuntimeError

        - If the query API request fails for any reason other than 404.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_switch_endpoint(self.query_one_endpoint(), switch_sn=switch_id)
            response = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            if not response:
                return None
            enriched = dict(response)
            enriched["fabric_name"] = self.fabric_name
            enriched["switch_ip"] = model_instance.switch_ip
            enriched["peer_switch_ip"] = model_instance.peer_switch_ip
            return VpcPairModel.from_response(enriched)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Walk the user-proposed `config` items and call the per-switch vPC pair GET endpoint for each unique
        peer pair. Each existing pair's wire response is enriched with `fabric_name`, `switch_ip`, and
        `peer_switch_ip` so that `VpcPairModel.from_response()` can populate the composite identifier.

        The fabric-wide `vpcPairs` list endpoint is intentionally NOT used here — it lags or omits recently
        deployed pairs in practice. The per-switch GET is authoritative.

        Returns an empty list when `config` is empty (e.g. `state=query` with no specified peers).

        ## Raises

        ### RuntimeError

        - If a per-switch query API request fails (404 from the GET is treated as "no pair", not an error).
        """
        try:
            config_items = self.rest_send.params.get("config") or []
            pairs: List[dict] = []
            seen_keys: set[tuple[str, str]] = set()
            for item in config_items:
                if not isinstance(item, dict):
                    continue
                switch_ip = item.get("switch_ip")
                peer_switch_ip = item.get("peer_switch_ip")
                if not switch_ip or not peer_switch_ip:
                    continue
                key = tuple(sorted([switch_ip, peer_switch_ip]))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                switch_id = self._resolve_switch_id(switch_ip)
                api_endpoint = self._configure_switch_endpoint(self.query_one_endpoint(), switch_sn=switch_id)
                response = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                if not response:
                    continue
                enriched = dict(response)
                enriched["fabric_name"] = self.fabric_name
                enriched["switch_ip"] = switch_ip
                enriched["peer_switch_ip"] = peer_switch_ip
                pairs.append(enriched)
            return pairs
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    def deploy_pending(self) -> ResponseType | None:
        """
        # Summary

        Flush queued switch deploys via `switchActions/deploy`. Parses the 207 multi-status response under the
        `switchIds` key (not `results`); per-switch status is compared case-insensitively because ND returns
        mixed casing across deploy endpoints.

        Returns `None` (without making any API call) when the queue is empty or `deploy` is False.

        ## Raises

        ### RuntimeError

        - If the deploy POST fails.
        - If any per-switch entry has `status != "success"` (case-insensitive); the failed switch's `message`
          is included in the exception text.
        """
        if not self.deploy or not self._pending_deploy_switch_ids:
            return None
        try:
            api_endpoint = self.deploy_endpoint()
            api_endpoint.fabric_name = self.fabric_name
            payload = {"switchIds": list(self._pending_deploy_switch_ids)}
            response = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            self._validate_deploy_response(response)
            self._pending_deploy_switch_ids = []
            return response
        except Exception as e:
            raise RuntimeError(f"Bulk deploy failed for switches {self._pending_deploy_switch_ids}: {e}") from e

    # Deploy-response messages that ND uses for idempotent no-op deploys. These do not indicate a deploy
    # failure — ND just had nothing to push because the intent already matches the switch state.
    _BENIGN_DEPLOY_MESSAGE_FRAGMENTS: ClassVar[tuple[str, ...]] = ("no commands to execute",)

    @classmethod
    def _validate_deploy_response(cls, response: ResponseType) -> None:
        """
        # Summary

        Inspect the 207 multi-status response from `switchActions/deploy`. Raise on any per-switch entry whose
        status is not `"success"` (case-insensitive), EXCEPT entries whose `message` matches one of
        `_BENIGN_DEPLOY_MESSAGE_FRAGMENTS` — those represent ND no-ops (already in sync) and are treated as
        success.

        ## Raises

        ### RuntimeError

        - If any per-switch entry under the `switchIds` key has a non-success status and the message is not
          a known benign no-op.
        """
        if not isinstance(response, dict):
            return
        entries = response.get("switchIds", []) or []
        failures = []
        for entry in entries:
            status = str(entry.get("status", "")).lower()
            if status == "success":
                continue
            message = str(entry.get("message", ""))
            if any(fragment in message.lower() for fragment in cls._BENIGN_DEPLOY_MESSAGE_FRAGMENTS):
                continue
            failures.append(f"{entry.get('switchId', '<unknown>')}: {message or '<no message>'}")
        if failures:
            raise RuntimeError("; ".join(failures))
