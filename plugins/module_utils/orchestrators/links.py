# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import copy
import logging
from typing import Any, ClassVar, Sequence

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import model_validator
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_link import BaseLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory import FabricSwitchInventory
from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory_helpers import (
    by_name as inventory_by_name,
    inventory_for_fabric,
)


class NDLinkOrchestrator(NDBaseOrchestrator["NDLinkModel"]):
    """Orchestrator for ND Link operations.

    Delegates endpoint selection to a BaseLinkStrategy so the same orchestrator
    works with single-cluster and multi-cluster scopes. Endpoint classes are
    derived from the strategy at construction time, so callers only need to
    pass ``sender`` and ``strategy``.
    """

    model_class: ClassVar[type[NDBaseModel]] = NDLinkModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    bulk_payload_key: ClassVar[str] = "links"

    strategy: BaseLinkStrategy | None = None

    @model_validator(mode="before")
    @classmethod
    def _wire_endpoints_from_strategy(cls, data: Any) -> Any:
        """Populate required endpoint fields from the strategy before validation."""
        if not isinstance(data, dict):
            return data
        strategy = data.get("strategy")
        if strategy is None:
            return data
        data.setdefault("create_endpoint", strategy.links_post_cls)
        data.setdefault("update_endpoint", strategy.link_put_cls)
        data.setdefault("delete_endpoint", strategy.link_actions_remove_post_cls)
        data.setdefault("query_one_endpoint", strategy.links_get_cls)
        data.setdefault("query_all_endpoint", strategy.links_get_cls)
        data.setdefault("create_bulk_endpoint", strategy.links_post_cls)
        data.setdefault("delete_bulk_endpoint", strategy.link_actions_remove_post_cls)
        return data

    def model_post_init(self, __context: Any) -> None:
        """Initialize per instance caches after Pydantic construction."""
        if self.strategy is None:
            raise ValueError("NDLinkOrchestrator requires a strategy instance")
        object.__setattr__(self, "_link_id_map", {})
        object.__setattr__(self, "_link_ids_by_key", {})
        object.__setattr__(self, "_existing_by_key", {})
        object.__setattr__(self, "_switch_index_by_fabric", {})
        object.__setattr__(self, "_log", logging.getLogger("nd.LinkOrchestrator"))

    def _index_for_fabric(self, fabric_name: str) -> FabricSwitchInventory:
        if fabric_name not in self._switch_index_by_fabric:
            self._switch_index_by_fabric[fabric_name] = inventory_for_fabric(self.rest_send, fabric_name, self._log)
        return self._switch_index_by_fabric[fabric_name]

    def prepare_config_data(self, raw_config: Any) -> Any:
        """Backfill switch_name and switch_id on each entry.

        Identity uses switch_name, so callers who only supplied IP or serial need it
        populated before the proposed collection is built.

        Operates on a copy: ``raw_config`` is a reference into ``module.params``,
        so backfilling in place would leak the resolved switch_name/switch_id
        back into the invocation echo.
        """
        if not isinstance(raw_config, list):
            return raw_config
        raw_config = copy.deepcopy(raw_config)
        for entry in raw_config:
            if not isinstance(entry, dict):
                continue
            self._backfill_switch_for_side(entry, "src")
            self._backfill_switch_for_side(entry, "dst")
        return raw_config

    def _backfill_switch_for_side(self, entry: dict[str, Any], side: str) -> None:
        """Resolve every supplied selector, require consistency, then apply priority.

        Priority remains ``switch_id > switch_ip > switch_name``, but lower-priority
        selectors are no longer silently ignored: if they identify another switch,
        fail before targeting a link different from the visible declaration.
        """
        name_key = "{0}_switch_name".format(side)
        ip_key = "{0}_switch_ip".format(side)
        id_key = "{0}_switch_id".format(side)
        fabric_key = "{0}_fabric_name".format(side)

        sid = entry.get(id_key)
        ip = entry.get(ip_key)
        name = entry.get(name_key)

        if not (sid or ip or name):
            return

        fabric = entry.get(fabric_key)
        if not fabric:
            return

        index = self._index_for_fabric(fabric)

        resolved = {}
        if sid:
            switch = index.by_id().get(sid)
            if not switch:
                raise Exception("Could not find switch with {0}_switch_id='{1}' in fabric '{2}'.".format(side, sid, fabric))
            resolved["switch_id"] = switch

        if ip:
            switch = index.by_ip().get(ip)
            if not switch:
                raise Exception(
                    "Could not resolve {0}_switch_ip='{1}' in fabric '{2}'. " "No switch with that management IP was found.".format(side, ip, fabric)
                )
            resolved["switch_ip"] = switch

        if name:
            matches = inventory_by_name(index).get(name, [])
            if len(matches) == 1:
                resolved["switch_name"] = matches[0]
            elif len(matches) > 1:
                higher_priority = resolved.get("switch_id") or resolved.get("switch_ip")
                if higher_priority and any(match.switch_id == higher_priority.switch_id for match in matches):
                    resolved["switch_name"] = higher_priority
                else:
                    ids = [match.switch_id for match in matches]
                    raise Exception(
                        "{0}_switch_name='{1}' is ambiguous in fabric '{2}' "
                        "(matches {3} switches: {4}). Use {0}_switch_ip or "
                        "{0}_switch_id to disambiguate.".format(side, name, fabric, len(matches), ", ".join(ids))
                    )
            else:
                raise Exception(
                    "Could not resolve {0}_switch_name='{1}' in fabric '{2}'. " "No switch with that hostname was found.".format(side, name, fabric)
                )

        resolved_ids = {switch.switch_id for switch in resolved.values()}
        if len(resolved_ids) > 1:
            supplied = ", ".join(
                "{0}_{1}='{2}'".format(side, selector, value) for selector, value in (("switch_id", sid), ("switch_ip", ip), ("switch_name", name)) if value
            )
            raise Exception("Switch selectors {0} do not resolve to the same switch in fabric '{1}'.".format(supplied, fabric))

        switch = resolved.get("switch_id") or resolved.get("switch_ip") or resolved.get("switch_name")
        if switch is None:
            return
        entry[id_key] = switch.switch_id
        if switch.hostname:
            entry[name_key] = switch.hostname

    def query_all(self, model_instance: NDLinkModel | None = None, **kwargs: Any) -> ResponseType:
        """GET all links in scope and populate linkId / policy_type caches."""
        try:
            endpoint = self.strategy.links_get_cls()
            self.strategy.configure_read(endpoint, **kwargs)
            result = self._request(endpoint.path, HttpVerbEnum.GET, not_found_ok=True)

            if isinstance(result, dict):
                links_list = result.get("items", result.get("links", []))
            elif isinstance(result, list):
                links_list = result
            else:
                links_list = []

            self._build_caches(links_list)
            return links_list
        except Exception as e:
            raise Exception("Query all links failed: {0}".format(e)) from e

    def _build_caches(self, links_list: list[dict[str, Any]]) -> None:
        """Populate ``_link_id_map`` (for PUT and DELETE) and ``_existing_by_key`` (for policy change detection)."""
        link_ids_by_key = {}
        existing_by_key = {}
        for link_data in links_list:
            try:
                model = NDLinkModel.from_response(link_data)
                composite_key = model.get_identifier_value()
                link_id = link_data.get("linkId")
                if composite_key:
                    link_ids_by_key.setdefault(composite_key, []).append(link_id or "<missing linkId>")
                    existing_policy = (link_data.get("configData") or {}).get("policyType")
                    if existing_policy and composite_key not in existing_by_key:
                        existing_by_key[composite_key] = existing_policy
            except (ValueError, KeyError):
                continue
        link_id_map = {key: values[0] for key, values in link_ids_by_key.items() if len(values) == 1 and values[0] != "<missing linkId>"}
        object.__setattr__(self, "_link_ids_by_key", link_ids_by_key)
        object.__setattr__(self, "_link_id_map", link_id_map)
        object.__setattr__(self, "_existing_by_key", existing_by_key)

    def _raise_if_ambiguous(self, model_instance: NDLinkModel, action: str) -> None:
        """Reject a mutation when one endpoint tuple maps to multiple ND records."""
        composite_key = model_instance.get_identifier_value()
        link_ids = self._link_ids_by_key.get(composite_key, [])
        if len(link_ids) <= 1:
            return
        raise ValueError(
            "Cannot {0} link {1}: ND returned {2} records with the same endpoint identity (linkIds: {3}). "
            "Disambiguate or remove the duplicate controller records first.".format(action, composite_key, len(link_ids), ", ".join(link_ids))
        )

    def _resolve_link_id(self, model_instance: NDLinkModel, action: str = "modify") -> str:
        """Look up the API generated linkId for a model's composite identity."""
        try:
            composite_key = model_instance.get_identifier_value()
        except ValueError as e:
            raise ValueError("Cannot resolve linkId - invalid composite key: {0}".format(e)) from e

        self._raise_if_ambiguous(model_instance, action)
        link_id = self._link_id_map.get(composite_key)
        if not link_id:
            raise ValueError("Cannot resolve linkId for {0}. Link may not exist on ND or " "query_all() wasn't called.".format(composite_key))
        return link_id

    def _is_policy_type_change(self, model_instance: NDLinkModel) -> bool:
        """Return True if this update would change policy_type on an existing link."""
        try:
            composite_key = model_instance.get_identifier_value()
        except ValueError:
            return False

        existing_policy = self._existing_by_key.get(composite_key)
        if not existing_policy:
            return False

        proposed_policy = None
        if model_instance.config_data and model_instance.config_data.policy_type:
            proposed_policy = model_instance.config_data.policy_type

        if proposed_policy is None or proposed_policy == existing_policy:
            return False

        # Realized preprovision is not a policy change: ND converts a planned
        # preprovision link to numbered, and reapplying the preprovision declaration
        # keeps it numbered (persistent intent, updating only the user-managed
        # interface fields). Allow it through instead of rejecting the update.
        if existing_policy == "numbered" and proposed_policy == "preprovision":
            return False

        return True

    def _raise_if_policy_type_change(self, model_instance: NDLinkModel) -> None:
        """Raise if this update would change ``policy_type`` on an existing link.

        ND rejects a cross-policy PUT (the link must be deleted and recreated), so
        this must fail before any mutation. Called from :meth:`preflight` (which the
        state machine runs in BOTH check and normal mode) so a dry-run cannot report
        a transition as a valid change; also kept in :meth:`update` as defense in
        depth for direct callers.
        """
        if not self._is_policy_type_change(model_instance):
            return
        composite_key = model_instance.get_identifier_value()
        existing_policy = self._existing_by_key.get(composite_key)
        proposed_policy = model_instance.config_data.policy_type
        raise Exception(
            "Cannot change policy_type from '{0}' to '{1}' on existing link {2}. "
            "ND requires deleting the link first and recreating with the new "
            "policy_type. Run this module with state=deleted for this link, "
            "then re-run with state=merged.".format(existing_policy, proposed_policy, composite_key)
        )

    def preflight(self, model_instances: Sequence[NDLinkModel]) -> None:
        """Pre-mutation validation run by the state machine in both check and normal
        mode. Rejects cross-policy transitions here so check mode is a reliable
        preflight gate rather than approving a change that normal mode will reject.
        """
        state = self.rest_send.params.get("state")
        if state == "overridden":
            ambiguous = {key: values for key, values in self._link_ids_by_key.items() if len(values) > 1}
            if ambiguous:
                details = "; ".join("{0}: {1}".format(key, ", ".join(values)) for key, values in ambiguous.items())
                raise ValueError("Cannot override link scope while duplicate endpoint identities exist: {0}.".format(details))
        for model_instance in model_instances:
            self._raise_if_ambiguous(model_instance, "modify")
            self._raise_if_policy_type_change(model_instance)

    def preflight_delete(self, model_instances: Sequence[NDLinkModel]) -> None:
        """Reject ambiguous endpoint identities before check mode predicts delete."""
        for model_instance in model_instances:
            self._raise_if_ambiguous(model_instance, "delete")

    def create(self, model_instance: NDLinkModel, **kwargs: Any) -> ResponseType:
        """Single create delegates to the bulk path (ND only exposes bulk POST)."""
        return self.create_bulk([model_instance])

    def create_bulk(self, model_instances: list[NDLinkModel], **kwargs: Any) -> ResponseType:
        """Bulk POST with 207 body failure surfacing. Switch ids are backfilled in prepare_config_data.

        Items are sent in a single POST through the RestSend pipeline
        (see ``NDBaseOrchestrator._post_bulk``).
        """
        if not model_instances:
            return {}
        try:
            endpoint = self.strategy.links_post_cls()
            self.strategy.configure_mutation(endpoint)
            items = [inst.to_payload() for inst in model_instances]
            response = self._post_bulk(endpoint, items, operation_type=OperationType.CREATE)
            self._raise_on_bulk_failures(response, op="create")
            return response
        except Exception as e:
            raise Exception("Bulk create failed: {0}".format(e)) from e

    def update(self, model_instance: NDLinkModel, **kwargs: Any) -> ResponseType:
        """PUT /links/{linkId}; rejects cross policy updates (needs delete and recreate)."""
        # Primary enforcement is in preflight (runs in both modes); this is defense
        # in depth for any direct caller that bypasses the state machine.
        self._raise_if_policy_type_change(model_instance)

        try:
            link_id = self._resolve_link_id(model_instance, action="update")
            endpoint = self.strategy.link_put_cls()
            endpoint.link_uuid = link_id
            self.strategy.configure_mutation(endpoint)

            return self._request(endpoint.path, endpoint.verb, data=model_instance.to_payload(), operation_type=OperationType.UPDATE)
        except Exception as e:
            raise Exception("Update failed for {0}: {1}".format(model_instance.get_identifier_value(), e)) from e

    def delete(self, model_instance: NDLinkModel, **kwargs: Any) -> ResponseType:
        """Single delete delegates to the bulk path (ND only exposes bulk remove)."""
        return self.delete_bulk([model_instance])

    def delete_bulk(self, model_instances: list[NDLinkModel], **kwargs: Any) -> ResponseType:
        """Bulk POST /linkActions/remove with 207 body failure surfacing.

        Items are sent in a single POST through the RestSend pipeline
        (see ``NDBaseOrchestrator._post_bulk``).
        """
        if not model_instances:
            return {}
        try:
            link_ids = [self._resolve_link_id(inst, action="delete") for inst in model_instances]
            endpoint = self.strategy.link_actions_remove_post_cls()
            self.strategy.configure_mutation(endpoint)
            response = self._post_bulk(endpoint, link_ids, operation_type=OperationType.DELETE)
            self._raise_on_bulk_failures(response, op="delete")
            return response
        except Exception as e:
            raise Exception("Bulk delete failed: {0}".format(e)) from e

    @staticmethod
    def _raise_on_bulk_failures(response: Any, op: str) -> None:
        """Raise if ND's 207 multi-status body reports any per-item failures.

        ND treats 207 as success at the HTTP layer, so partial failures only show
        up in the body. The OpenAPI contract for bulk create (POST /links) and
        delete (POST /linkActions/remove) is ``{"links": [{"linkId", "message",
        "status"}]}`` with ``status`` in ``{"success", "failure"}`` -- the
        ``links`` + ``status`` path below matches that exactly. The remaining
        containers/signals are a defensive superset kept until the shape is
        confirmed against a broader set of live responses.

        # TODO(4.2.1) TBD
        # Workaround for an ND API discrepancy: bulk link create/delete returns
        # HTTP 207 with per-item failures only in the body, but ResponseHandler
        # classifies 207 as success. Remove this body scan once the central
        # NdV1Strategy multi-status detector (PR #398) covers the links envelope;
        # that detector needs "links" added to _MULTISTATUS_ITEM_KEYS and "linkId"
        # to _MULTISTATUS_ITEM_LABEL_KEYS ("failure"/"message" already covered).
        """
        if not isinstance(response, dict):
            return

        def _is_failure(item: dict) -> bool:
            status = str(item.get("status") or item.get("result") or "").lower()
            if status in ("failure", "failed", "error"):
                return True
            if item.get("success") is False:
                return True
            return bool(item.get("error") or item.get("errorMessage"))

        def _detail(item: dict) -> str:
            ident = item.get("linkId") or item.get("id") or item.get("uuid") or "<no linkId>"
            message = item.get("message") or item.get("errorMessage") or item.get("error") or item.get("msg") or "unknown error"
            return "{0}: {1}".format(ident, message)

        failures = []
        # Result containers whose items must be inspected for a failure signal.
        for key in ("links", "items", "results"):
            value = response.get(key)
            if isinstance(value, list):
                failures.extend(item for item in value if isinstance(item, dict) and _is_failure(item))
        # Containers whose mere presence means the listed items failed.
        for key in ("failed", "failures", "errors"):
            value = response.get(key)
            if isinstance(value, list):
                failures.extend(item for item in value if isinstance(item, dict))

        if not failures:
            return
        details = "; ".join(_detail(item) for item in failures)
        raise Exception("ND reported {0} per-item {1} failure(s): {2}".format(len(failures), op, details))
