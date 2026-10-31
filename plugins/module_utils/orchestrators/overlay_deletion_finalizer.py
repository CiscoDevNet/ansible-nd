# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Finalize exact detached overlay definitions without another deployment.

The ordinary deleted workflow deliberately owns detach/deploy/delete.  This
opt-in continuation is for callers that already staged and deployed the
detach.  Fresh, complete controller observations are required; a boolean
assertion from the caller is never accepted as deployment evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_attachments import (
    EpManageFabricsNetworkAttachmentsQueryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_attachments import EpManageFabricsVrfAttachmentsQueryPost
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator

NETWORK_DELETE_FINALIZE_VERSION = 1
VRF_DELETE_FINALIZE_VERSION = 1


class OverlayDeletionFinalizer:
    """Read, validate and delete an explicit standalone Network or VRF set."""

    page_size = 500
    max_pages = 1000
    _DETACHED = frozenset(("na", "notapplicable", "notdeployed", "deleted"))
    _SAFE_ATTACHMENT_STATUS = _DETACHED | frozenset(("insync", "success"))

    def __init__(self, coordinator: Any, resource: str):
        if resource not in ("network", "vrf"):
            raise ValueError("Overlay finalization resource must be network or vrf")
        self.coordinator = coordinator
        self.resource = resource
        self.plural = resource + "s"
        self.name_key = resource + "Name"
        self.status_key = resource + "Status"

    def validate_scope(self, module_args: dict, strategy: Any) -> list[str]:
        """Reject implicit or unsupported authority before any workflow writes."""
        if module_args.get("state") != "deleted":
            raise ValueError("deletion_mode=finalize requires state=deleted")
        if strategy.is_parent or strategy.is_child or strategy.is_multicluster or strategy.is_multisite:
            raise ValueError("deletion_mode=finalize supports standalone Manage fabrics only")
        config = module_args.get("config")
        if not isinstance(config, list) or not config:
            raise ValueError("deletion_mode=finalize requires explicit non-empty config")
        names = []
        for index, item in enumerate(config):
            name = item.get(self.resource + "_name") if isinstance(item, dict) else None
            if not isinstance(name, str) or not name or name != name.strip():
                raise ValueError(f"config[{index}] requires an exact {self.resource}_name for finalization")
            if name in names:
                raise ValueError(f"Duplicate finalization target {name!r}")
            if item.get("attach") or item.get("detach") or item.get("child_fabric_config"):
                raise ValueError("deletion_mode=finalize accepts definition selectors without attachment or child operations")
            names.append(name)
        return names

    @staticmethod
    def _status(value: Any) -> str:
        return str(getattr(value, "value", value) or "").strip().lower()

    @staticmethod
    def _count(value: Any, label: str) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool):
            raise ValueError(f"Invalid finalization pagination {label}")
        if isinstance(value, str) and value.isdecimal():
            value = int(value)
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"Invalid finalization pagination {label}")
        return value

    def _collect(self, fetch: Callable[[int, int], Any], key: str, identity: Callable[[dict], Any]) -> list[dict]:
        """Validate pagination instead of interpreting malformed state as empty."""
        records: list[dict] = []
        seen = set()
        expected_total = None
        offset = 0
        for _page in range(self.max_pages):
            response = fetch(offset, self.page_size)
            if not isinstance(response, Mapping):
                raise ValueError(f"Finalization {key} response must be a collection object")
            present = [candidate for candidate in (key, "items") if candidate in response]
            if len(present) != 1 or not isinstance(response[present[0]], list):
                raise ValueError(f"Finalization response requires one valid {key} collection")
            page = response[present[0]]
            for item in page:
                if not isinstance(item, dict):
                    raise ValueError(f"Finalization {key} contains a malformed row")
                item_id = identity(item)
                if item_id in seen:
                    raise ValueError(f"Finalization {key} has a duplicate or repeated-page identity {item_id!r}")
                seen.add(item_id)
                records.append(item)
            if "meta" in response and "metadata" in response:
                raise ValueError("Finalization response has conflicting pagination metadata")
            metadata = response.get("meta", response.get("metadata", {}))
            if not isinstance(metadata, Mapping):
                raise ValueError("Finalization response has invalid pagination metadata")
            counts = metadata.get("counts", {})
            if not isinstance(counts, Mapping):
                raise ValueError("Finalization response has invalid pagination counts")
            total = self._count(counts.get("total", metadata.get("total")), "total")
            remaining = self._count(counts.get("remaining", metadata.get("remaining")), "remaining")
            after = offset + len(page)
            if total is not None and (total < after or expected_total is not None and total != expected_total):
                raise ValueError("Finalization pagination total changed or contradicts returned rows")
            if total is not None:
                expected_total = total
            if remaining is not None:
                inferred_total = after + remaining
                if expected_total is not None and inferred_total != expected_total:
                    raise ValueError("Finalization pagination remaining contradicts total")
                expected_total = inferred_total
            links = metadata.get("links", {})
            if not isinstance(links, Mapping):
                raise ValueError("Finalization response has invalid pagination links")
            next_link = links.get("next")
            if next_link is not None and not isinstance(next_link, str):
                raise ValueError("Finalization response has invalid pagination continuation")
            more = after < expected_total if expected_total is not None else bool(next_link) or len(page) >= self.page_size
            if next_link:
                offsets = parse_qs(urlsplit(next_link).query).get("offset", [])
                if len(offsets) != 1 or not offsets[0].isdecimal() or int(offsets[0]) != after or not more:
                    raise ValueError("Finalization pagination next link contradicts actual offset")
            elif "next" in links and more:
                raise ValueError("Finalization pagination terminal link contradicts remaining rows")
            if not more:
                return records
            if not page:
                raise ValueError("Finalization pagination is incomplete and made no progress")
            offset = after
        raise ValueError("Finalization pagination exceeded the page limit")

    def _definition_identity(self, item: dict) -> str:
        name = item.get(self.name_key)
        if not isinstance(name, str) or not name:
            raise ValueError(f"Finalization definition lacks {self.name_key}")
        return name

    def _attachment_identity(self, item: dict) -> tuple[str, str]:
        name = self._definition_identity(item)
        serial = item.get("switchId")
        if not isinstance(serial, str) or not serial:
            raise ValueError("Finalization attachment lacks switchId")
        return name, serial

    def _definitions(self, orchestrator: Any, strategy: Any, names: list[str]) -> list[dict]:
        endpoint_type = getattr(strategy, self.plural + "_get_cls")()
        selector = getattr(self.coordinator, "_" + self.resource + "_name_filter")(names)
        # Use the same multi-Network search as CRUD discovery. ND can return
        # zero rows for a fielded OR even when those definitions exist. Keep
        # complete pagination and exact local name selection authoritative.
        if self.resource == "network" and len(names) > 1:
            selector = NDNetworkOrchestrator._network_names_unfielded_filter(names)
        elif self.resource == "vrf" and len(names) > 1:
            # Match VRF CRUD discovery: ND's fielded multi-name OR can return
            # no rows for existing VRFs. Page the complete collection and keep
            # the exact requested-name selection below authoritative.
            selector = None

        def fetch(offset, size):
            endpoint = orchestrator._make_endpoint(endpoint_type)
            endpoint.endpoint_params.filter = selector
            endpoint.endpoint_params.max = size
            endpoint.endpoint_params.offset = offset
            return orchestrator._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=False, operation_type=OperationType.QUERY)

        wanted = set(names)
        return [row for row in self._collect(fetch, self.plural, self._definition_identity) if row[self.name_key] in wanted]

    def _attachments(self, orchestrator: Any, strategy: Any, names: list[str]) -> list[dict]:
        if not names:
            return []
        endpoint_type = self.coordinator.attachments._attachments_query_endpoint_cls(strategy)

        def fetch(offset, size):
            endpoint = orchestrator._make_endpoint(endpoint_type)
            endpoint.endpoint_params.include_all = True
            endpoint.endpoint_params.max = size
            endpoint.endpoint_params.offset = offset
            path, verb = endpoint.path, endpoint.verb
            payload = {self.plural[:-1] + "Names": names}
            runtime = getattr(orchestrator, "rest_send", None)
            original_check_mode = getattr(runtime, "check_mode", False)
            if original_check_mode is True:
                # RestSend simulates non-GET verbs in check mode. Only this
                # exact, read-only query may bypass simulation; module and CRUD
                # state-machine check mode remain unchanged.
                query_class = EpManageFabricsNetworkAttachmentsQueryPost if self.resource == "network" else EpManageFabricsVrfAttachmentsQueryPost
                expected = query_class()
                expected.fabric_name = strategy.fabric_name
                if type(endpoint) is not query_class or verb != HttpVerbEnum.POST or urlsplit(path).path != urlsplit(expected.path).path:
                    raise ValueError("Check-mode finalization requires a recognized read-only attachment query")
                runtime.check_mode = False
            try:
                return orchestrator._request(path=path, verb=verb, data=payload, not_found_ok=False, operation_type=OperationType.QUERY)
            finally:
                if original_check_mode is True:
                    runtime.check_mode = original_check_mode

        wanted = set(names)
        return [row for row in self._collect(fetch, "attachments", self._attachment_identity) if row[self.name_key] in wanted]

    def _require_detached(self, definitions: list[dict], attachments: list[dict]) -> None:
        for row in definitions:
            if self._status(row.get(self.status_key)) not in self._DETACHED:
                raise ValueError(f"Cannot finalize {row[self.name_key]!r}: fresh {self.status_key} is not detached/deployed-terminal")
        for row in attachments:
            statuses = [self._status(row[key]) for key in ("status", "configStatus", "deploymentStatus", self.status_key, "attachmentStatus") if key in row]
            if (
                row.get("attach") is not False
                or not statuses
                or any(value not in self._SAFE_ATTACHMENT_STATUS for value in statuses)
                or not any(value in self._DETACHED for value in statuses)
            ):
                raise ValueError(f"Cannot finalize {row[self.name_key]!r}/{row['switchId']}: attachment is not explicitly detached and deployed-terminal")

    def run(self, module_args: dict, strategy: Any) -> dict[str, Any]:
        """Finalize definitions without invoking detach, wait/redeploy or deploy."""
        names = self.validate_scope(module_args, strategy)
        # Initialize CRUD before proving readiness.  The ordinary wrapper would
        # otherwise gather again after the guard and could admit a newly seen
        # definition that was not covered by the readiness observation.
        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            return self._run_initialized(sm, module_args, strategy, names)
        finally:
            self.coordinator._restore_state_machine_params(original_config, original_state)

    def _run_initialized(self, sm: Any, module_args: dict, strategy: Any, names: list[str]) -> dict[str, Any]:
        """Guard the loaded deletion set immediately before generic CRUD."""
        factory = getattr(self.coordinator, "_new_" + self.resource + "_orchestrator")
        orchestrator, results = factory(module_args, strategy)
        definitions = self._definitions(orchestrator, strategy, names)
        existing = [row[self.name_key] for row in definitions]
        requested = set(names)
        loaded = []
        for model in sm.existing:
            name = getattr(model, self.resource + "_name", None)
            if not isinstance(name, str):
                value = model.get_identifier_value()
                name = value[0] if isinstance(value, (list, tuple)) else value
            if name in requested:
                if name in loaded:
                    raise ValueError("Finalization CRUD snapshot contains duplicate target identities")
                loaded.append(name)
        if set(loaded) != set(existing):
            raise ValueError("Finalization target set changed between CRUD discovery and fresh readiness; retry observation")
        attachments = self._attachments(orchestrator, strategy, existing)
        self._require_detached(definitions, attachments)
        getattr(self.coordinator, "_ensure_" + self.plural + "_have_no_networks")(module_args, strategy, existing)
        request = {"fabric_name": strategy.fabric_name, "resource": self.resource, "names": names}
        receipt = {
            "version": 1,
            "proof": "fresh_detached_overlay_finalization_v1",
            **request,
            "request_sha256": hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "existing_before": existing,
            "attachments_verified_detached": True,
            "detach_attempts": 0,
            "deployment_attempts": 0,
            "definition_absence_verified": None,
        }
        sm.manage_state()
        result = self.coordinator._format_state_machine_output(sm)
        result.setdefault("fabric_type", strategy.fabric_type)
        result.setdefault("workflow", f"Standalone Fabric {self.resource.capitalize()} Definition Finalization")
        if not self.coordinator.module.check_mode and not result.get("failed"):
            try:
                remaining = self._definitions(orchestrator, strategy, names)
                if remaining:
                    raise ValueError("Target definitions remain present: " + ", ".join(row[self.name_key] for row in remaining))
                receipt["definition_absence_verified"] = True
            except Exception as error:  # Preserve accepted deletion evidence when observation fails.
                receipt["definition_absence_verified"] = False
                result["failed"] = True
                result["msg"] = f"{self.resource.capitalize()} deletion returned but fresh definition absence was not verified: {error}"
        result["deletion_finalization"] = receipt
        trace = self.coordinator._finalize_api_trace(results)
        self.coordinator._merge_api_trace(result, trace, prepend=True)
        return result
