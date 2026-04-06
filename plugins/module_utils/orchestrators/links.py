# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import ClassVar, Dict, List, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_link import BaseLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class NDLinkOrchestrator(NDBaseOrchestrator["NDLinkModel"]):
    """Orchestrator for ND Link operations.

    Delegates endpoint selection to a BaseLinkStrategy so the same orchestrator
    works with single-cluster and multi-cluster scopes. Endpoint classes are
    derived from the strategy at construction time, so callers only need to
    pass ``sender`` and ``strategy``.
    """

    model_class: ClassVar[Type[NDBaseModel]] = NDLinkModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    strategy: Optional[BaseLinkStrategy] = None

    @model_validator(mode="before")
    @classmethod
    def _wire_endpoints_from_strategy(cls, data):
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

    def model_post_init(self, __context) -> None:
        """Initialize per instance caches after Pydantic construction."""
        if self.strategy is None:
            raise ValueError("NDLinkOrchestrator requires a strategy instance")
        object.__setattr__(self, "_link_id_map", {})
        object.__setattr__(self, "_existing_by_key", {})
        object.__setattr__(self, "_switch_id_by_fabric", {})

    def _fetch_switches_for_fabric(self, fabric_name: str) -> Dict[str, str]:
        """Return ``{switch_name: switch_id}`` for a fabric via GET /manage/fabrics/.../switches."""
        path = "/api/v1/manage/fabrics/{0}/switches".format(fabric_name)
        try:
            response = self.sender.query_obj(path)
        except Exception:
            return {}

        if isinstance(response, dict):
            items = response.get("switches", response.get("items", []))
        elif isinstance(response, list):
            items = response
        else:
            items = []

        result: Dict[str, str] = {}
        for sw in items:
            if not isinstance(sw, dict):
                continue
            name = sw.get("hostname") or sw.get("switchName") or sw.get("name")
            sid = sw.get("switchId") or sw.get("serialNumber") or sw.get("id")
            if name and sid:
                result[name] = sid
        return result

    def _resolve_switch_ids(self, model_instances: List[NDLinkModel]) -> None:
        """Fill missing src/dst switch_id on proposed items (user supplied IDs untouched)."""
        fabrics_to_lookup = set()
        for item in model_instances:
            if not item.src_switch_id and item.src_switch_name and item.src_fabric_name:
                fabrics_to_lookup.add(item.src_fabric_name)
            if not item.dst_switch_id and item.dst_switch_name and item.dst_fabric_name:
                fabrics_to_lookup.add(item.dst_fabric_name)

        for fabric_name in fabrics_to_lookup:
            if fabric_name in self._switch_id_by_fabric:
                continue
            self._switch_id_by_fabric[fabric_name] = self._fetch_switches_for_fabric(fabric_name)

        for item in model_instances:
            if not item.src_switch_id and item.src_switch_name:
                sid = self._switch_id_by_fabric.get(item.src_fabric_name, {}).get(item.src_switch_name)
                if sid:
                    item.src_switch_id = sid
            if not item.dst_switch_id and item.dst_switch_name:
                sid = self._switch_id_by_fabric.get(item.dst_fabric_name, {}).get(item.dst_switch_name)
                if sid:
                    item.dst_switch_id = sid

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """GET all links in scope and populate linkId / policy_type caches."""
        try:
            endpoint = self.strategy.links_get_cls()
            params = self.strategy.build_query_all_params(**kwargs)

            path = endpoint.path
            if params:
                qs = "&".join("{0}={1}".format(k, v) for k, v in params.items())
                path = "{0}?{1}".format(path, qs)

            result = self.sender.query_obj(path)

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

    def _build_caches(self, links_list: List[Dict]) -> None:
        """Populate ``_link_id_map`` (for PUT and DELETE) and ``_existing_by_key`` (for policy change detection)."""
        link_id_map = {}
        existing_by_key = {}
        for link_data in links_list:
            try:
                model = NDLinkModel.from_response(link_data)
                composite_key = model.get_identifier_value()
                link_id = link_data.get("linkId")
                if composite_key and link_id:
                    link_id_map[composite_key] = link_id
                    existing_policy = (link_data.get("configData") or {}).get("policyType")
                    if existing_policy:
                        existing_by_key[composite_key] = existing_policy
            except (ValueError, KeyError):
                continue
        object.__setattr__(self, "_link_id_map", link_id_map)
        object.__setattr__(self, "_existing_by_key", existing_by_key)

    def _resolve_link_id(self, model_instance: NDLinkModel) -> str:
        """Look up the API generated linkId for a model's composite identity."""
        try:
            composite_key = model_instance.get_identifier_value()
        except ValueError as e:
            raise ValueError("Cannot resolve linkId - invalid composite key: {0}".format(e)) from e

        link_id = self._link_id_map.get(composite_key)
        if not link_id:
            raise ValueError(
                "Cannot resolve linkId for {0}. Link may not exist on ND or "
                "query_all() wasn't called.".format(composite_key)
            )
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

        return proposed_policy is not None and proposed_policy != existing_policy

    def create(self, model_instance: NDLinkModel, **kwargs) -> ResponseType:
        """Single create delegates to the bulk path (ND only exposes bulk POST)."""
        return self.create_bulk([model_instance])

    def create_bulk(self, model_instances: List[NDLinkModel], **kwargs) -> ResponseType:
        """Bulk POST with switch id resolution and 207 body failure surfacing."""
        if not model_instances:
            return {}
        try:
            self._resolve_switch_ids(model_instances)
            endpoint = self.strategy.links_post_cls()
            payload = {"links": [inst.to_payload() for inst in model_instances]}
            response = self.sender.request(
                path=endpoint.path,
                method=endpoint.verb,
                data=payload,
            )
            self._raise_on_bulk_failures(response, op="create")
            return response
        except Exception as e:
            raise Exception("Bulk create failed: {0}".format(e)) from e

    def update(self, model_instance: NDLinkModel, **kwargs) -> ResponseType:
        """PUT /links/{linkId}; rejects cross policy updates (needs delete and recreate)."""
        if self._is_policy_type_change(model_instance):
            composite_key = model_instance.get_identifier_value()
            existing_policy = self._existing_by_key.get(composite_key)
            proposed_policy = model_instance.config_data.policy_type
            raise Exception(
                "Cannot change policy_type from '{0}' to '{1}' on existing link {2}. "
                "ND requires deleting the link first and recreating with the new "
                "policy_type. Run this module with state=deleted for this link, "
                "then re-run with state=merged.".format(existing_policy, proposed_policy, composite_key)
            )

        try:
            self._resolve_switch_ids([model_instance])
            link_id = self._resolve_link_id(model_instance)
            endpoint = self.strategy.link_put_cls()
            path = "{0}/{1}".format(endpoint.path, link_id)

            return self.sender.request(
                path=path,
                method=endpoint.verb,
                data=model_instance.to_payload(),
            )
        except Exception as e:
            raise Exception(
                "Update failed for {0}: {1}".format(model_instance.get_identifier_value(), e)
            ) from e

    def delete(self, model_instance: NDLinkModel, **kwargs) -> ResponseType:
        """Single delete delegates to the bulk path (ND only exposes bulk remove)."""
        return self.delete_bulk([model_instance])

    def delete_bulk(self, model_instances: List[NDLinkModel], **kwargs) -> ResponseType:
        """Bulk POST /linkActions/remove with 207 body failure surfacing."""
        if not model_instances:
            return {}
        try:
            link_ids = [self._resolve_link_id(inst) for inst in model_instances]
            endpoint = self.strategy.link_actions_remove_post_cls()
            payload = {"links": link_ids}
            response = self.sender.request(
                path=endpoint.path,
                method=endpoint.verb,
                data=payload,
            )
            self._raise_on_bulk_failures(response, op="delete")
            return response
        except Exception as e:
            raise Exception("Bulk delete failed: {0}".format(e)) from e

    @staticmethod
    def _raise_on_bulk_failures(response, op: str) -> None:
        """Raise if ND's 207 body reports any per item failures for this bulk call."""
        if not isinstance(response, dict):
            return
        items = response.get("links")
        if not isinstance(items, list):
            return
        failures = [item for item in items if isinstance(item, dict) and item.get("status") == "failure"]
        if not failures:
            return
        details = "; ".join(
            "{0}: {1}".format(item.get("linkId") or "<no linkId>", item.get("message") or "unknown error")
            for item in failures
        )
        raise Exception("ND reported {0} per-item {1} failure(s): {2}".format(len(failures), op, details))
