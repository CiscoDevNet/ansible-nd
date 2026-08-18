# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

from typing import ClassVar
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions_mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
    EpManageFabricsDelete,
)
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import GatheredLuceneSpec, build_lucene_expressions


class ManageAiEbgpVxlanFabricOrchestrator(ConfigActionsMixin, NDBaseOrchestrator):
    model_class: ClassVar[type[NDBaseModel]] = FabricAiEbgpVxlanModel

    supports_gathered_server_filtering: ClassVar[bool] = True
    gathered_lucene_spec: ClassVar[GatheredLuceneSpec] = GatheredLuceneSpec(
        base_terms=(("type", "aimlVxlanEbgp"),),
        field_map={
            ("fabric_name",): "name",
            ("license_tier",): "licenseTier",
            ("security_domain",): "securityDomain",
            ("alert_suspend",): "alertSuspend",
            ("telemetry_collection",): "telemetryCollection",
        },
    )

    _FABRIC_TYPE_FILTER: ClassVar[str] = "aimlVxlanEbgp"
    _MAX_LUCENE_EXPRESSIONS: ClassVar[int] = 3

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageFabricsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageFabricsListGet

    def query_all(self, model_instance=None, gathered_filters=None, **kwargs) -> ResponseType:
        """Query fabrics, optionally narrowing via server-side Lucene filters."""
        try:
            if gathered_filters is not None and self.gathered_lucene_spec is not None:
                return self._query_all_for_gathered(gathered_filters)
            return self._query_all_for_management_states()
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def _query_all_for_management_states(self) -> ResponseType:
        """Fetch all fabrics and filter to aimlVxlanEbgp client-side."""
        api_endpoint = self.query_all_endpoint()
        result = self._request(
            path=api_endpoint.path,
            verb=api_endpoint.verb,
            not_found_ok=True,
        )
        fabrics = result.get("fabrics", []) or []
        return [fabric for fabric in fabrics if fabric.get("management", {}).get("type") == self._FABRIC_TYPE_FILTER]

    def _fetch_fabrics_paginated(self, expression: str | None = None) -> list[dict]:
        """Fetch fabrics with bounded pagination, optionally filtered by a Lucene expression."""
        page_size = 500
        max_pages = 100
        offset = 0
        all_results: list[dict] = []

        for _page in range(max_pages):
            api_endpoint = self.query_all_endpoint()
            api_endpoint.endpoint_params.max = page_size
            api_endpoint.endpoint_params.offset = offset
            if expression:
                api_endpoint.endpoint_params.filter = expression

            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            if not isinstance(result, dict):
                break

            page = result.get("fabrics", []) or []
            all_results.extend(page)

            if not page:
                break

            counts = (result.get("meta") or {}).get("counts") or {}
            remaining_raw = counts.get("remaining")

            try:
                remaining = int(remaining_raw) if remaining_raw is not None else None
            except (TypeError, ValueError):
                remaining = None

            if remaining is not None and remaining <= 0:
                break
            if remaining is None and len(page) < page_size:
                break

            offset += len(page)
        else:
            raise RuntimeError(f"Fabric pagination exceeded {max_pages} pages ({len(all_results)} fabrics). " "Results may be incomplete.")
        return all_results

    def _query_one_by_name(self, fabric_name: str) -> list[dict]:
        """Fetch a single fabric by exact name via the resource endpoint."""
        api_endpoint = self.query_one_endpoint()
        api_endpoint.set_identifiers(fabric_name)
        result = self._request(
            path=api_endpoint.path,
            verb=api_endpoint.verb,
            not_found_ok=True,
        )
        if not result or not isinstance(result, dict):
            return []
        if result.get("management", {}).get("type") != self._FABRIC_TYPE_FILTER:
            return []
        return [result]

    def _query_all_for_gathered(self, gathered_filters) -> ResponseType:
        """Use server-side Lucene to narrow fabric results before client-side type check."""
        all_fabrics = []
        seen_names: set[str] = set()

        lucene_filters = []
        for filter_item in gathered_filters or [{}]:
            fabric_name = filter_item.get("fabric_name")
            other_keys = {k for k, v in filter_item.items() if v not in (None, "") and k != "fabric_name"}
            if fabric_name and not other_keys:
                for fabric in self._query_one_by_name(fabric_name):
                    name = fabric.get("name")
                    if name and name not in seen_names:
                        seen_names.add(name)
                        all_fabrics.append(fabric)
            else:
                lucene_filters.append(filter_item)

        if not lucene_filters:
            return all_fabrics

        expressions = build_lucene_expressions(
            lucene_filters,
            spec=self.gathered_lucene_spec,
        )

        if not expressions or len(expressions) > self._MAX_LUCENE_EXPRESSIONS or any('"' in expression for expression in expressions):
            expressions = build_lucene_expressions(filters=[], spec=self.gathered_lucene_spec)

        for expression in expressions:
            fabrics = self._fetch_fabrics_paginated(expression)
            for fabric in fabrics:
                if fabric.get("management", {}).get("type") != self._FABRIC_TYPE_FILTER:
                    continue

                name = fabric.get("name")
                if not name or name in seen_names:
                    continue

                seen_names.add(name)
                all_fabrics.append(fabric)

        return all_fabrics
