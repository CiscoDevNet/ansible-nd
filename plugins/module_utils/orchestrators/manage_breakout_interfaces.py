# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Response-first breakout actions, with scoped discovery and optional verification."""

from __future__ import annotations

import copy
import json
import re
import time
from collections import defaultdict
from os.path import commonprefix
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    PrivateAttr,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesBreakout,
    EpManageInterfacesRemove,
    EpManageInterfacesSummaryGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
    PlatformType,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_breakout_interfaces.breakout_interface import (
    BreakoutInterfaceModel,
    validate_module_params,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_strategies.nd_v1_strategy import (
    NdV1Strategy,
    _failed_multistatus_items,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

_PAGE_SIZE = 1000
_MAX_PAGES = 100
_DISCOVERY_WAIT_SECONDS = 90
_DISCOVERY_POLL_INTERVAL = 2
_PARENT = re.compile(r"^Ethernet(?P<slot>[1-9]\d*)/(?P<port>[1-9]\d*)$", re.IGNORECASE)
_PHYSICAL = re.compile(r"Ethernet([1-9]\d*)/([1-9]\d*)(?:/([1-9]\d*))?", re.IGNORECASE)
_SPEED = re.compile(r"([1-9]\d*)(?:\.0+)?\s*(?:Gb|Gbps|G)", re.IGNORECASE)


def _diagnostic_text(value: Any) -> str:
    """Keep controller diagnostics printable without changing their raw response."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _join_errors(errors) -> str:
    """Deduplicate diagnostic text, not potentially unhashable controller values."""
    return "; ".join(dict.fromkeys(_diagnostic_text(error) for error in errors))


def _confirmed_initial_empty_page(data: Any, collection: str, offset: int) -> bool:
    """Accept an omitted optional array only with explicit initial-zero evidence.

    Manage can omit ``interfaces`` when a filtered first page has no matches.
    Missing data without both integer zero counts, explicit
    null/wrong-type arrays, and missing later pages remain incomplete evidence.
    """
    if offset != 0 or not isinstance(data, dict) or collection in data:
        return False
    meta = data.get("meta")
    counts = meta.get("counts") if isinstance(meta, dict) else None
    return isinstance(counts, dict) and all(
        isinstance(counts.get(name), int) and not isinstance(counts[name], bool) and counts[name] == 0 for name in ("remaining", "total")
    )


class ManageBreakoutInterfacesOrchestrator(NDBaseOrchestrator[BreakoutInterfaceModel]):
    """Ensure requested parents are broken out or native, without mandatory GET-after-POST.

    Initial discovery is needed for idempotency and child selection. Action results
    describe API acknowledgements, not independently verified topology or running
    configuration. Missing results remain unknown. The orchestrator does not
    replay actions; requests use the standard RestSend retry behavior.
    """

    model_class: ClassVar[type] = BreakoutInterfaceModel
    create_endpoint: type = EpManageInterfacesBreakout
    update_endpoint: type = EpManageInterfacesBreakout
    delete_endpoint: type = EpManageInterfacesRemove
    query_one_endpoint: type = EpManageInterfacesSummaryGet
    query_all_endpoint: type = EpManageInterfacesSummaryGet
    _fabric_context: FabricContext | None = PrivateAttr(default=None)
    _api_calls: list[dict[str, Any]] = PrivateAttr(default_factory=list)
    _action_changed: bool = PrivateAttr(default=False)
    _last_action_completed: bool = PrivateAttr(default=False)
    _write_attempted: bool = PrivateAttr(default=False)
    _report: dict[str, Any] = PrivateAttr(default_factory=dict)

    @property
    def report_snapshot(self) -> dict[str, Any]:
        """Preserve workflow evidence when an unexpected exception reaches main.

        A write attempt establishes uncertainty, not a confirmed change. Each
        action invalidates older final-state evidence before transport starts.
        """
        report = copy.deepcopy(self._report)
        report["changed"] = bool(report.get("changed", False) or self._action_changed)
        report["may_have_changed"] = bool(
            report.get("may_have_changed", False) or (self._write_attempted and not self.rest_send.params.get("check_mode", False))
        )
        report["api_calls"] = copy.deepcopy(self._api_calls)
        return report

    @property
    def fabric_name(self) -> str:
        """Return the caller's standalone fabric name."""
        return self.rest_send.params["fabric_name"]

    @property
    def fabric_context(self) -> FabricContext:
        """Lazily create the shared, targeted switch identity/platform cache."""
        if self._fabric_context is None:
            self._fabric_context = FabricContext(
                rest_send=self.rest_send,
                fabric_name=self.fabric_name,
                query_observer=self._observe_resolution_query,
                query_error_observer=self._observe_resolution_error,
            )
        return self._fabric_context

    def _validate_switch_platforms(self, models: list[BreakoutInterfaceModel]) -> None:
        """Require NX-OS for every selected switch before topology reads or writes.

        Campus fabrics may contain both NX-OS and IOS-XE switches. The fabric
        type is therefore not a proxy for breakout support. Reuse IP-resolution
        metadata and query only serials whose platform has not been fetched.
        Missing/unknown metadata cannot establish that an operation is supported.
        """
        self._validate_platform_ids(dict.fromkeys(model.switch_id for model in models))

    def _validate_platform_ids(self, switch_ids) -> None:
        """Reuse shared platform evidence, including explicitly empty switch scopes."""
        platforms = self.fabric_context.get_switch_platform_types(switch_ids)
        errors = []
        for switch_id, platform in platforms.items():
            if platform == PlatformType.NX_OS:
                continue
            if platform is None:
                errors.append(f"Cannot verify the platform of switch '{switch_id}': additionalData.platformType is missing or unrecognized.")
            elif platform == PlatformType.IOS_XE:
                errors.append(f"Switch '{switch_id}' reports platformType 'ios-xe'; Nexus Dashboard does not support breakout interfaces on IOS-XE.")
            else:
                errors.append(f"Switch '{switch_id}' reports unsupported platformType '{platform.value}'.")
        if errors:
            raise RuntimeError(" ".join(errors) + " This module requires NX-OS switches; no breakout or unbreakout request was sent.")

    def _observe_resolution_query(self, path: str) -> None:
        """Record shared switch metadata reads without copying response history."""
        self._register_api_call(path, HttpVerbEnum.GET, OperationType.QUERY)
        self._api_calls.append(
            {
                "method": "GET",
                "path": path,
                "http_status": self.rest_send.return_code,
                "elapsed_seconds": self.fabric_context.last_query_elapsed_seconds,
                "response_received": True,
                "purpose": "switch_metadata",
            }
        )

    def _observe_resolution_error(self, path: str, error: Exception, response_received: bool) -> None:
        """Include failed shared IP lookups without reusing an older query's response."""
        self._register_unanswered_request(
            path,
            HttpVerbEnum.GET,
            OperationType.QUERY,
            None,
            error,
            self.rest_send.response_current if response_received else None,
        )
        self._api_calls.append(
            {
                "method": "GET",
                "path": path,
                "http_status": (self.rest_send.return_code if response_received else None),
                "elapsed_seconds": self.fabric_context.last_query_elapsed_seconds,
                "response_received": response_received,
                "purpose": "switch_metadata",
                "transport_error": str(error),
            }
        )

    def _register_api_call(self, path, verb, operation_type, payload=None):
        """Preserve module context after Results resets its per-call staging."""
        if self.results is not None:
            self.results.state = self.rest_send.params.get("state", "merged")
            self.results.check_mode = bool(self.rest_send.params.get("check_mode", False))
        super()._register_api_call(path, verb, operation_type, payload)

    def _register_unanswered_request(self, path, verb, operation_type, payload, error, response=None):
        """Record incomplete requests, retaining only replies received by this request."""
        if self.results is None:
            return
        self.results.state = self.rest_send.params.get("state", "merged")
        self.results.check_mode = bool(self.rest_send.params.get("check_mode", False))
        self.results.action = operation_type.value
        self.results.operation_type = operation_type
        self.results.path_current = path
        self.results.verb_current = verb
        self.results.payload_current = payload
        self.results.response_current = (
            {**response, "completion_error": str(error), "response_received": True}
            if response is not None
            else {
                "RETURN_CODE": -1,
                "MESSAGE": str(error),
                "DATA": {},
                "response_received": False,
            }
        )
        self.results.result_current = {
            "success": False,
            "found": False,
            "changed": False,
        }
        self.results.diff_current = {}
        self.results.verbosity_level_current = 3 if operation_type == OperationType.QUERY else 2
        self.results.register_api_call()

    def _request(
        self,
        path,
        verb,
        data=None,
        not_found_ok=False,
        operation_type=OperationType.QUERY,
    ):
        """Keep standard transport behavior and trace only completed responses."""
        response_count = self.rest_send.response_count
        registered_before = self.results.task_sequence_number if self.results is not None else None
        started = time.monotonic()
        try:
            return super()._request(path, verb, data, not_found_ok, operation_type)
        except Exception as error:
            if self.results is not None and self.results.task_sequence_number == registered_before:
                self._register_unanswered_request(
                    path,
                    verb,
                    operation_type,
                    data,
                    error,
                    (self.rest_send.response_current if self.rest_send.response_count > response_count else None),
                )
            raise
        finally:
            fresh = self.rest_send.response_count > response_count
            self._api_calls.append(
                {
                    "method": verb.value,
                    "path": path,
                    "http_status": self.rest_send.return_code if fresh else None,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "response_received": fresh,
                }
            )

    @staticmethod
    def discovery_groups(
        models: list[BreakoutInterfaceModel],
    ) -> list[tuple[str, str, list[BreakoutInterfaceModel]]]:
        """Batch families only when a nonempty port-number prefix narrows the GET.

        For example, 50/51/52 share *Ethernet1/5*. Unrelated number ranges
        are queried separately rather than widening to the entire switch.
        """
        groups = defaultdict(list)
        for model in models:
            match = _PARENT.fullmatch(model.interface_name)
            if match is None:
                raise ValueError(f"Invalid breakout parent '{model.interface_name}'.")
            groups[(model.switch_id, match["slot"])].append(model)
        queries = []
        for (switch_id, slot), targets in groups.items():
            # Disjoint ranges do not prevent batching within each selective
            # leading-digit bucket: 21/50/51 needs two GETs, not three.
            buckets = defaultdict(list)
            for model in targets:
                buckets[model.interface_name.rsplit("/", 1)[1][0]].append(model)
            for bucket in buckets.values():
                prefix = commonprefix([model.interface_name.rsplit("/", 1)[1] for model in bucket])
                queries.append((switch_id, f"interfaceName:*Ethernet{slot}/{prefix}*", bucket))
        return queries

    def _query_group(self, switch_id: str | None, filter_text: str) -> list[dict[str, Any]]:
        """Use a body-free GET transport even after an aborted mutation."""
        writer = self.rest_send
        if writer.payload is not None:
            reader = RestSend(dict(writer.params))
            reader.sender = writer.sender
            reader.response_handler = writer.response_handler
            reader.check_mode = False
            reader.unit_test = writer.unit_test
            reader.timeout = writer.timeout
            reader.send_interval = writer.send_interval
            self.rest_send = reader
        try:
            return self._query_group_pages(switch_id, filter_text)
        finally:
            self.rest_send = writer

    def _query_group_pages(self, switch_id: str | None, filter_text: str) -> list[dict[str, Any]]:
        """Read a filtered interface family/group, following bounded pagination."""
        rows = []
        offset = 0
        fingerprints = set()
        initial_total = None
        for _ in range(_MAX_PAGES):
            endpoint = EpManageInterfacesSummaryGet(fabric_name=self.fabric_name)
            endpoint.endpoint_params.switch_id = switch_id
            endpoint.endpoint_params.include_all = True
            endpoint.endpoint_params.filter = filter_text
            endpoint.endpoint_params.max = _PAGE_SIZE
            endpoint.endpoint_params.offset = offset
            body = self._request(endpoint.path, endpoint.verb)
            page = body.get("interfaces") if isinstance(body, dict) else None
            if _confirmed_initial_empty_page(body, "interfaces", offset):
                page = []
            if not isinstance(page, list) or any(not isinstance(row, dict) for row in page):
                raise RuntimeError("Filtered interfacesSummary did not return an interfaces array of objects.")
            fingerprint = tuple(
                (
                    row.get("switchId"),
                    row.get("interfaceName"),
                    row.get("physicalInterface"),
                )
                for row in page
            )
            if page and fingerprint in fingerprints:
                raise RuntimeError("Filtered interfacesSummary repeated a page; discovery is incomplete.")
            fingerprints.add(fingerprint)
            rows.extend(page)
            meta = body.get("meta", {})
            if not isinstance(meta, dict):
                raise RuntimeError("Invalid interfacesSummary pagination metadata.")
            counts = meta.get("counts", {})
            if not isinstance(counts, dict):
                raise RuntimeError("Invalid interfacesSummary pagination counts.")
            for name in ("remaining", "total"):
                if name in counts and (isinstance(counts[name], bool) or not isinstance(counts[name], int) or counts[name] < 0):
                    raise RuntimeError(f"Invalid interfacesSummary pagination {name}.")
            if "total" in counts:
                if initial_total is not None and counts["total"] != initial_total:
                    raise RuntimeError("interfacesSummary total changed during pagination; discovery is incomplete.")
                initial_total = counts["total"]
                if offset + len(page) > counts["total"]:
                    raise RuntimeError("interfacesSummary returned more rows than its declared total.")
                if "remaining" in counts and counts["total"] != offset + len(page) + counts["remaining"]:
                    raise RuntimeError("Inconsistent interfacesSummary pagination counts; discovery is incomplete.")
            has_more = (
                counts["remaining"] > 0 if "remaining" in counts else (offset + len(page) < counts["total"] if "total" in counts else len(page) >= _PAGE_SIZE)
            )
            if not has_more:
                return rows
            if not page:
                raise RuntimeError("Filtered interfacesSummary ended before pagination completed.")
            offset += len(page)
        raise RuntimeError("Filtered interface discovery exceeded the pagination limit.")

    @staticmethod
    def _classify(model: BreakoutInterfaceModel, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Match exact requested families, excluding prefix lookalikes and subinterfaces."""
        parent = model.interface_name
        parent_key = parent.casefold()
        fex_namespace = int(_PARENT.fullmatch(parent)["slot"]) >= 100
        children = []
        native = []
        seen = set()
        child_re = re.compile(re.escape(parent) + r"/([1-9]\d*)$", re.IGNORECASE)
        for row in rows:
            name = row.get("interfaceName")
            if not isinstance(name, str):
                continue
            is_parent = name.casefold() == parent_key
            child = child_re.fullmatch(name)
            if not is_parent and child is None:
                continue
            if child is not None and fex_namespace:
                raise RuntimeError(f"FEX interface '{name}' cannot be safely classified as a breakout resource.")
            if row.get("switchId") != model.switch_id:
                raise RuntimeError(f"Unexpected switch identity for requested interface '{parent}'.")
            key = name.casefold()
            if key in seen:
                raise RuntimeError(f"Duplicate inventory identity '{model.switch_id}/{name}'.")
            seen.add(key)
            if row.get("physicalInterface") is False:
                continue  # A config-only ghost parent is not native device topology.
            if row.get("fex") is True:
                raise RuntimeError(f"FEX interface '{name}' cannot be safely classified as a breakout resource.")
            if row.get("physicalInterface") is not True or row.get("fex") is not False:
                raise RuntimeError(f"Incomplete physicalInterface/fex evidence for '{name}'; topology cannot be classified safely.")
            if is_parent:
                native.append(name)
            elif child is not None:
                children.append(name)
        if native and children:
            raise RuntimeError(f"Ambiguous topology for '{parent}': native parent and breakout children both exist.")
        if not native and not children:
            raise RuntimeError(f"Neither native parent nor breakout children found for '{model.switch_id}/{parent}'.")
        return {
            "switch_id": model.switch_id,
            "interface_name": parent,
            "broken_out": bool(children),
            "children": sorted(children, key=lambda name: int(name.rsplit("/", 1)[1])),
            "evidence": "initial_discovery",
        }

    def discover(self, models: list[BreakoutInterfaceModel]) -> dict[tuple[str, str], dict[str, Any]]:
        """Fetch only requested groups and return normalized logical parent resources."""
        found = {}
        for switch_id, filter_text, targets in self.discovery_groups(models):
            rows = self._query_group(switch_id, filter_text)
            requested = {model.interface_name.casefold() for model in targets}
            families = defaultdict(list)
            # Index once instead of scanning the full filtered group for each
            # requested parent. The classifier still checks exact identities.
            for row in rows:
                name = row.get("interfaceName")
                if not isinstance(name, str):
                    continue
                key = name.casefold()
                if key in requested:
                    families[key].append(row)
                    continue
                parent, _, lane = key.rpartition("/")
                if parent in requested and re.fullmatch(r"[1-9]\d*", lane):
                    families[parent].append(row)
            for model in targets:
                found[(model.switch_id, model.interface_name)] = self._classify(model, families[model.interface_name.casefold()])
        return found

    @staticmethod
    def format_config(models: list[BreakoutInterfaceModel]) -> list[dict[str, Any]]:
        """Group normalized input intent without inventing an observed map.

        Used for NDOutput's proposed and planned-delta fields, not topology
        snapshots. The public plural interface_names contract is preserved.
        """
        groups = {}
        for model in models:
            key = (model.switch_id, model.breakout_map)
            if key not in groups:
                groups[key] = {"switch_id": model.switch_id, "interface_names": []}
                if model.breakout_map is not None:
                    groups[key]["breakout_map"] = model.breakout_map
            groups[key]["interface_names"].append(model.requested_child or model.interface_name)
        return list(groups.values())

    @staticmethod
    def match_action_results(response: dict[str, Any], submitted: list[dict[str, Any]], action: str) -> tuple[list[dict[str, Any]], list[str]]:
        """Correlate wire identities locally; status decisions come from NdV1Strategy.

        Each submitted object retains its logical parent and actual API name.
        Missing/duplicate/foreign identities do not become successful by position.
        """
        expected = {(item["switch_id"], item["api_interface_name"].casefold()): item for item in submitted}
        matched = defaultdict(list)
        errors = []
        data = response.get("DATA")
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or not results:
            errors.append("Action response must contain a nonempty results array.")
            results = []
        for row in results:
            if not isinstance(row, dict):
                errors.append("Action response contains a non-object result.")
                continue
            switch_id, name = row.get("switchId"), row.get("interfaceName")
            if not isinstance(switch_id, str) or not switch_id.strip() or not isinstance(name, str) or not name.strip():
                errors.append("Action result is missing a usable switchId/interfaceName identity.")
                continue
            key = (switch_id.strip(), name.strip().casefold())
            if key not in expected:
                errors.append(f"Action response contains an unrequested identity '{switch_id}/{name}'.")
                continue
            matched[key].append(row)
        strategy = NdV1Strategy()
        outcomes = []
        for item in submitted:
            key = (item["switch_id"], item["api_interface_name"].casefold())
            rows = matched[key]
            outcome = {
                **item,
                "action": action,
                "outcome": "unknown",
                "message": "No identifiable result was returned for this action.",
            }
            if len(rows) > 1:
                outcome["message"] = "Duplicate results make this action outcome ambiguous."
                errors.append(f"Duplicate action results for '{key[0]}/{item['api_interface_name']}'.")
            elif len(rows) == 1:
                row = rows[0]
                # Keep the shared strict per-item vocabulary even if ND returns
                # the envelope on 200. Plain-200 generic handlers are deliberately
                # permissive; these action results must explicitly say success.
                one_item = {"RETURN_CODE": 207, "DATA": {"results": [row]}}
                status = row.get("status")
                if not isinstance(status, str) or not status.strip():
                    outcome["message"] = "Identified action result has no usable status."
                elif response.get("RETURN_CODE") not in strategy.success_codes or response.get("RETURN_CODE") == 202:
                    outcome["message"] = "Transport did not report a completed successful action response."
                elif strategy.is_success(one_item):
                    outcome.update(
                        outcome="success",
                        message=_diagnostic_text(row.get("message") or "Action reported success."),
                    )
                elif _failed_multistatus_items(one_item):
                    outcome.update(
                        outcome="failed",
                        message=_diagnostic_text(row.get("message") or "Action reported failure."),
                    )
                else:
                    outcome["message"] = _diagnostic_text(row.get("message") or f"Unrecognized action status '{status}'.")
            if outcome["outcome"] == "unknown":
                errors.append(f"Outcome unresolved for '{item['switch_id']}/{item['interface_name']}': {outcome['message']}")
            outcomes.append(outcome)
        return outcomes, errors

    @classmethod
    def _match_recovery_results(cls, response, submitted, action):
        """Accept one same-switch success receipt without guessing a name alias.

        Coupled execution can rewrite the returned parent. This exception only
        acknowledges a single inverse request; it never verifies restoration or
        assigns an unmatched success to multiple independent inverse targets.
        """
        outcomes, errors = cls.match_action_results(response, submitted, action)
        if len(submitted) != 1 or outcomes[0]["outcome"] != "unknown":
            return outcomes, errors
        data = response.get("DATA")
        rows = data.get("results") if isinstance(data, dict) else None
        if response.get("RETURN_CODE") not in {200, 201, 207} or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            return outcomes, errors
        item, row = submitted[0], rows[0]
        serial, name = row.get("switchId"), row.get("interfaceName")
        if not isinstance(serial, str) or serial.strip() != item["switch_id"] or not isinstance(name, str) or not name.strip():
            return outcomes, errors
        if name.strip().casefold() == item["api_interface_name"].casefold():
            return outcomes, errors
        if not NdV1Strategy().is_success({"RETURN_CODE": 207, "DATA": {"results": [row]}}):
            return outcomes, errors
        return [
            {
                **item,
                "action": action,
                "outcome": "success",
                "message": _diagnostic_text(row.get("message") or "Controller reported success for the single recovery request."),
                "reported_interface_name": name.strip(),
                "identity_matched": False,
            }
        ], []

    def _execute_action(self, submitted: list[dict[str, Any]], state: str, *, recovery=False) -> tuple[list[dict[str, Any]], list[str]]:
        """Submit a bulk action using standard transport and match completed replies."""
        action = "breakout" if state == "merged" else "unbreakout"
        endpoint_class = EpManageInterfacesBreakout if state == "merged" else EpManageInterfacesRemove
        endpoint = endpoint_class(fabric_name=self.fabric_name)
        interfaces = []
        for item in submitted:
            wire_item = {
                "switchId": item["switch_id"],
                "interfaceName": item["api_interface_name"],
            }
            if state == "merged":
                wire_item["breakoutMap"] = item["breakout_map"]
            interfaces.append(wire_item)
        before_count = self.rest_send.response_count
        self._last_action_completed = False
        request_error = None
        try:
            self._write_attempted = True
            self._report.pop("after", None)
            self._report["after_status"] = "unknown"
            self._request(
                endpoint.path,
                endpoint.verb,
                {"interfaces": interfaces},
                operation_type=(OperationType.CREATE if state == "merged" else OperationType.DELETE),
            )
        except Exception as exc:  # Retain completed responses without an orchestrator-level replay.
            request_error = str(exc)
        if self.rest_send.response_count == before_count:
            message = request_error or "No completed controller response is available."
            return [{**item, "action": action, "outcome": "unknown", "message": message} for item in submitted], [message]
        response = self.rest_send.response_current
        self._last_action_completed = response.get("RETURN_CODE") in {
            200,
            201,
            204,
            207,
        }
        matcher = self._match_recovery_results if recovery else self.match_action_results
        outcomes, errors = matcher(response, submitted, action)
        # Only strict forward matches or explicitly accepted recovery receipts
        # feed the shared mutation-evidence rule.
        self._action_changed = self._action_changed or NdV1Strategy().is_changed_on_failure(
            {
                "modified": response.get("modified"),
                "DATA": {"results": [{"status": "success"} for item in outcomes if item["outcome"] == "success"]},
            }
        )
        if request_error:
            errors.insert(0, request_error)
        return outcomes, errors

    def run(self) -> dict[str, Any]:
        """Select response-only or guarded planning without changing shared transport."""
        self._report = {}
        self._action_changed = False
        self._write_attempted = False
        self._last_action_completed = False
        self._api_calls.clear()
        params = self.rest_send.params
        if params.get("state", "merged") not in {"merged", "deleted", "overridden"}:
            return {
                "changed": False,
                "failed": True,
                "may_have_changed": False,
                "before": [],
                "diff": [],
                "proposed": [],
                "api_calls": [],
                "after_status": "unknown",
                "api_outcomes": [],
                "recovery": [],
                "msg": f"Unsupported state '{params.get('state')}'; only merged, deleted, and overridden are supported.",
            }
        verify = params.get("verify")
        enabled = verify.get("enabled", True) if isinstance(verify, dict) else True
        if params.get("state", "merged") != "overridden" and not enabled:
            return self._run_response_only()
        return self._run_topology(enabled)

    @staticmethod
    def _index_topology(rows, switch_id=None, *, allow_intent=False):
        """Index physical topology and explicitly active intent separately from readiness."""
        indexed, seen = {}, set()
        for row in rows:
            serial, name = row.get("switchId"), row.get("interfaceName")
            if not isinstance(serial, str) or not serial.strip() or not isinstance(name, str):
                raise RuntimeError("Topology response is missing a switch/interface identity.")
            if switch_id is not None and serial != switch_id:
                raise RuntimeError("Topology response contains an unexpected switch identity.")
            identity = (serial, name.casefold())
            if identity in seen:
                raise RuntimeError("Topology response contains a duplicate switch/interface identity.")
            seen.add(identity)
            physical = row.get("physicalInterface")
            if row.get("fex") is True or "." in name:
                continue
            if physical is False and not allow_intent:
                continue
            if not isinstance(physical, bool) or row.get("fex") is not False:
                raise RuntimeError("Incomplete physicalInterface/fex evidence; topology cannot be classified safely.")
            match = _PHYSICAL.fullmatch(name)
            if match is None:
                raise RuntimeError(f"Unrecognized physical Ethernet identity '{name}'.")
            slot, port, lane = match.groups()
            # NX-OS reserves three-part names with slots >= 100 for FEX.
            # Intent-only records may still report fex=false before discovery.
            if lane is not None and int(slot) >= 100:
                continue
            policy_id = row.get("policyId")
            active_intent = allow_intent and isinstance(policy_id, str) and bool(policy_id.strip()) and row.get("markDeleted") is False
            if lane is not None and not physical and not active_intent:
                continue
            parent = f"Ethernet{int(slot)}/{int(port)}"
            key = (serial, parent)
            resource = indexed.get(key)
            if resource is None:
                resource = indexed[key] = {
                    "switch_id": serial,
                    "interface_name": parent,
                    "broken_out": False,
                    "children": [],
                    "child_speeds": {},
                    "native": False,
                    "parent_available": False,
                    "child_readiness": {},
                    "has_physical_children": False,
                    "physical_native": False,
                    "intent_native": False,
                }
            if lane is None:
                resource["parent_available"] = True
                resource["physical_native"] = physical
                resource["intent_native"] = active_intent
            else:
                child = parent + "/" + str(int(lane))
                if child in resource["child_speeds"]:
                    raise RuntimeError(f"Duplicate canonical child '{serial}/{child}'.")
                resource["children"].append(child)
                resource["child_speeds"][child] = row.get("speed")
                resource["child_readiness"][child] = physical and row.get("discovered") is True
                if physical:
                    resource["has_physical_children"] = True
        for resource in indexed.values():
            if resource["physical_native"] and resource["has_physical_children"]:
                raise RuntimeError("Ambiguous topology: physical parent and breakout children coexist.")
            resource["broken_out"] = bool(resource["children"])
            resource["native"] = not resource["broken_out"] and (resource["physical_native"] or resource["intent_native"])
            if resource["broken_out"]:
                if not all(resource["child_readiness"].values()):
                    resource["evidence"] = "controller_intent"
            elif resource["native"] and not resource["physical_native"]:
                resource["evidence"] = "controller_intent"
            resource["children"].sort(key=lambda child: int(child.rsplit("/", 1)[1]))
        return indexed

    def _topology_snapshot(self, switch_ids=None, evidence="post_action_discovery"):
        """Read complete Ethernet scope once; active intent does not prove discovery."""
        snapshot = {}
        for serial in list(switch_ids) if switch_ids is not None else [None]:
            snapshot.update(self._index_topology(self._query_group(serial, "interfaceType:ethernet"), serial, allow_intent=True))
        for resource in snapshot.values():
            resource.setdefault("evidence", evidence)
            resource["snapshot_phase"] = evidence
        return snapshot

    def _wait_for_inverse(self, submitted, state, snapshot, *, require_map=False, settle_removal=False):
        """Reuse observed readiness, polling only unresolved families with GETs.

        Unbreakout needs a discovered physical child. Breakout needs an explicit
        parent record, including an intent-only one. No mutation is retried and
        the returned snapshot is not a post-recovery verification.
        """
        observed = dict(snapshot)
        pending = {(item["switch_id"], item["interface_name"]): item for item in submitted}
        ready = {}
        deadline = time.monotonic() + _DISCOVERY_WAIT_SECONDS
        while pending:
            for key, item in list(pending.items()):
                resource = observed.get(key)
                if resource is None:
                    continue
                if state == "merged":
                    if settle_removal and resource["broken_out"]:
                        if not all(resource["child_readiness"].values()):
                            continue
                    elif not resource["parent_available"]:
                        continue
                    ready[key] = dict(item)
                else:
                    child = next((name for name in resource["children"] if resource["child_readiness"].get(name)), None)
                    if child is None:
                        continue
                    if require_map:
                        try:
                            self._recovery_map(resource)
                        except ValueError:
                            # Known discovered interfaces with invalid speeds
                            # are invalid baselines, not a discovery delay.
                            known_speeds = {
                                int(match.group(1))
                                for value in resource["child_speeds"].values()
                                if isinstance(value, str) and (match := _SPEED.fullmatch(value.strip()))
                            }
                            if len(known_speeds) > 1 or all(resource["child_readiness"].values()):
                                raise
                            continue
                    ready[key] = {**item, "api_interface_name": child}
                del pending[key]
            if not pending:
                return [ready[(item["switch_id"], item["interface_name"])] for item in submitted], observed
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                names = ", ".join(f"{serial}/{parent}" for serial, parent in sorted(pending))
                prerequisite = (
                    "a resolved unbreakout observation"
                    if settle_removal
                    else (
                        "an available parent record"
                        if state == "merged"
                        else "discovered breakout children with a usable recovery map" if require_map else "a discovered physical breakout child"
                    )
                )
                raise RuntimeError(
                    f"Discovery did not provide {prerequisite} for {names} within {_DISCOVERY_WAIT_SECONDS} seconds; "
                    "no inverse or unbreakout request was sent for these targets."
                )
            time.sleep(min(_DISCOVERY_POLL_INTERVAL, remaining))
            if time.monotonic() >= deadline:
                continue
            models = [BreakoutInterfaceModel(switch_id=serial, interface_name=parent) for serial, parent in pending]
            for serial, filter_text, targets in self.discovery_groups(models):
                fresh = self._index_topology(self._query_group(serial, filter_text), serial, allow_intent=True)
                # Prefix filters can return unrelated families. Replace only
                # pending exact identities; absence never reuses an older row.
                for model in targets:
                    key = (serial, model.interface_name)
                    observed.pop(key, None)
                    if key in fresh:
                        fresh[key].setdefault("evidence", "post_action_discovery")
                        fresh[key]["snapshot_phase"] = snapshot.get(key, {}).get("snapshot_phase", "post_action_discovery")
                        observed[key] = fresh[key]
        return [], observed

    @staticmethod
    def _families(snapshot, serial=None):
        return {key: tuple(row["children"]) for key, row in snapshot.items() if row["broken_out"] and (serial is None or key[0] == serial)}

    @staticmethod
    def _export_topology(snapshot, requested=()):
        """Expose families/selectors, not every unrelated native row or private speeds."""
        requested = set(requested)
        exported = ((key, row) for key, row in snapshot.items() if row["broken_out"] or key in requested)
        return [
            {
                name: copy.deepcopy(row[name])
                for name in ("switch_id", "interface_name", "broken_out", "children", "evidence", "requested_breakout_map")
                if name in row
            }
            for key, row in sorted(exported)
        ]

    @staticmethod
    def _observed_after_status(snapshot, requested):
        """Keep read freshness independent of intent versus discovered evidence."""
        return (
            "partially_observed"
            if any(row.get("snapshot_phase") == "initial_discovery" for key, row in snapshot.items() if row["broken_out"] or key in requested)
            else "observed"
        )

    @staticmethod
    def _recovery_map(resource):
        """Infer a recovery-only profile from complete, uniform observed child speeds."""
        speeds = []
        for child in resource["children"]:
            value = resource["child_speeds"].get(child)
            match = _SPEED.fullmatch(value.strip()) if isinstance(value, str) else None
            if match is None:
                raise ValueError(f"Cannot infer recovery map for '{resource['interface_name']}': missing or unrecognized child speed.")
            speeds.append(int(match.group(1)))
        if not speeds or len(set(speeds)) != 1:
            raise ValueError(f"Cannot infer recovery map for '{resource['interface_name']}': child speeds are not uniform.")
        return f"{speeds[0]}g-{len(speeds)}x"

    @staticmethod
    def _submitted(model, snapshot, state):
        key = (model.switch_id, model.interface_name)
        item = {
            "switch_id": key[0],
            "interface_name": key[1],
            "api_interface_name": key[1],
        }
        if model.requested_child:
            item["requested_interface_name"] = model.requested_child
        if state == "merged":
            item["breakout_map"] = model.breakout_map
        else:
            resource = snapshot[key]
            item["api_interface_name"] = next(
                (name for name in resource["children"] if resource["child_readiness"].get(name)),
                resource["children"][0],
            )
        return item

    @staticmethod
    def _guard(before, after, submitted, state, requested_state=None):
        """Compare indexed families with set operations, preserving exact child identities."""
        original_by_switch, observed_by_switch, targets_by_switch = defaultdict(dict), defaultdict(dict), defaultdict(set)
        for key, row in before.items():
            if row["broken_out"]:
                original_by_switch[key[0]][key] = row["children"]
        for key, row in after.items():
            if row["broken_out"]:
                observed_by_switch[key[0]][key] = row["children"]
        for item in submitted:
            targets_by_switch[item["switch_id"]].add((item["switch_id"], item["interface_name"]))
        reports = []
        for serial, targets in targets_by_switch.items():
            original = original_by_switch[serial]
            observed = observed_by_switch[serial]
            original_keys, observed_keys = original.keys(), observed.keys()
            retained = original_keys if state == "merged" else original_keys - targets
            unexpected = observed_keys - original_keys
            if state == "merged":
                unexpected.difference_update(targets)
            missing = retained - observed_keys
            changed = {key for key in retained & observed_keys if original[key] != observed[key]}
            target_names = ", ".join(key[1] for key in sorted(targets))
            intended_names = ", ".join(key[1] for key in sorted(targets | unexpected))
            reasons = [
                f"Unexpected breakout family '{key[1]}' on switch '{serial}' after the request for {target_names}. "
                + (
                    f"If these coupled breakouts are intended, include all affected parents ({intended_names}) in config."
                    if state == "merged"
                    else "Unbreakout created an unrequested breakout family; review the coupled-interface scope."
                )
                for key in sorted(unexpected)
            ]
            for key in sorted(missing):
                guidance = (
                    "Creating the requested breakout also removed an existing family; review the coupled-interface scope."
                    if state == "merged"
                    else (
                        "The overridden desired topology cannot be maintained while this coupled sibling is omitted; "
                        "include every coupled parent intended to remain broken out in config."
                        if requested_state == "overridden"
                        else f"If unbreaking this coupled family is intended, include '{key[1]}' in the deleted config too."
                    )
                )
                operation = "breaking out" if state == "merged" else "unbreaking"
                reasons.append(f"Retained breakout family '{key[1]}' disappeared on switch '{serial}' after {operation} {target_names}. {guidance}")
            reasons += [
                f"Retained child identities changed for '{key[1]}' on switch '{serial}' after the request for {target_names}." for key in sorted(changed)
            ]
            requested_match = (
                targets.issubset(observed)
                if state == "merged"
                else all(key in after and after[key]["native"] and not after[key]["broken_out"] for key in targets)
            )
            reports.append(
                {
                    "switch_id": serial,
                    "phase": "breakout" if state == "merged" else "unbreakout",
                    "collateral": reasons,
                    "topology_matches": requested_match and not reasons,
                }
            )
        return reports

    def _compensate(self, result, submitted, before, after, state, maps, offenders, completed):
        """Invert changed original entries on violating switches, without any recovery GET."""
        submitted_by_switch = defaultdict(list)
        if completed:
            for item in submitted:
                if item["switch_id"] in offenders:
                    submitted_by_switch[item["switch_id"]].append(item)
        for serial in sorted(offenders):
            recovery = {
                "switch_id": serial,
                "phase": "breakout" if state == "merged" else "unbreakout",
                "action": "unbreakout" if state == "merged" else "breakout",
                "api_outcomes": [],
                "status": "not_attempted",
                "topology_verified": False,
            }
            result["recovery"].append(recovery)
            if not completed:
                recovery["msg"] = "The forward request did not report synchronous completion; no inverse request was guessed."
                continue
            switch_after = {key: after[key] for item in submitted_by_switch[serial] if (key := (serial, item["interface_name"])) in after}
            if state == "deleted":
                pending_removals = [
                    item
                    for item in submitted_by_switch[serial]
                    if (before.get((serial, item["interface_name"])) or {}).get("broken_out")
                    and (after.get((serial, item["interface_name"])) or {}).get("broken_out")
                    and after[(serial, item["interface_name"])].get("evidence") == "controller_intent"
                ]
                if pending_removals:
                    try:
                        _, resolved_after = self._wait_for_inverse(pending_removals, "merged", switch_after, settle_removal=True)
                        switch_after.update(resolved_after)
                    except Exception as error:
                        recovery["msg"] = f"Unbreakout observation remained unresolved: {error}"
                        continue
            inverse = []
            for item in submitted_by_switch[serial]:
                key = (serial, item["interface_name"])
                original, observed = before.get(key), switch_after.get(key)
                was_broken = bool(original and original["broken_out"])
                is_broken = bool(observed and observed["broken_out"])
                if was_broken == is_broken:
                    continue
                entry = {
                    "switch_id": serial,
                    "interface_name": key[1],
                    "api_interface_name": key[1],
                }
                if state == "merged":
                    entry["api_interface_name"] = switch_after[key]["children"][0]
                else:
                    entry["breakout_map"] = maps[key]
                inverse.append(entry)
            if not inverse:
                recovery["msg"] = "No changed original parent with a usable inverse target was observed."
                continue
            inverse_state = "deleted" if state == "merged" else "merged"
            try:
                inverse, _ = self._wait_for_inverse(inverse, inverse_state, switch_after)
            except Exception as error:
                recovery["msg"] = f"Inverse prerequisite could not be established: {error}"
                continue
            outcomes, errors = self._execute_action(inverse, inverse_state, recovery=True)
            recovery["api_outcomes"] = outcomes
            recovery["status"] = (
                "unknown"
                if any(item["outcome"] == "unknown" for item in outcomes)
                else ("failed" if errors or any(item["outcome"] == "failed" for item in outcomes) else "response_confirmed")
            )
            if errors:
                recovery["msg"] = _join_errors(errors)
            elif recovery["status"] == "response_confirmed":
                recovery["msg"] = "The inverse API reported success; original topology and configuration were not independently verified."

    def _run_topology(self, guarded):
        """Create first, validate each changed phase, and preserve earlier validated progress."""
        params = self.rest_send.params
        state, check_mode = params.get("state", "merged"), bool(params.get("check_mode", False))
        self._api_calls.clear()
        self._action_changed = False
        result = {
            "changed": False,
            "failed": False,
            "may_have_changed": False,
            "before": [],
            "after_status": "unknown",
            "proposed": [],
            "diff": [],
            "api_outcomes": [],
            "recovery": [],
        }
        self._report = result
        errors, maps = [], {}
        current = {}
        try:
            models = validate_module_params(params)
            raw = params.get("config")
            fabric_wide = state == "overridden" and not raw
            selectors = [] if fabric_wide else [entry["switch_id"].strip() for entry in raw]
            resolved = self.fabric_context.resolve_switch_identifiers(selectors)
            models = [model.model_copy(update={"switch_id": resolved[model.switch_id]}) for model in models]
            selected = list(dict.fromkeys(resolved[selector] for selector in selectors))
            keys = [(model.switch_id, model.interface_name) for model in models]
            requested_keys = set(keys)
            if len(keys) != len(requested_keys):
                raise ValueError("Duplicate switch/interface after IP-to-serial resolution.")
            result["proposed"] = self.format_config(models)
            if state == "overridden" and not fabric_wide:
                desired_switches = {model.switch_id for model in models}
                result["proposed"].extend({"switch_id": serial, "interface_names": []} for serial in selected if serial not in desired_switches)
            if selected:
                self._validate_platform_ids(selected)
            current = self._topology_snapshot(None if fabric_wide else selected, evidence="initial_discovery")
            if fabric_wide:
                selected = sorted({key[0] for key in self._families(current)})
                self._validate_platform_ids(selected)
            for model in models:
                key = (model.switch_id, model.interface_name)
                if key not in current or not (current[key]["native"] or current[key]["broken_out"]):
                    raise ValueError(f"Neither native parent nor breakout children found for '{key[0]}/{key[1]}'.")
                if model.requested_child and current[key]["broken_out"] and model.requested_child not in current[key]["children"]:
                    raise ValueError(f"Requested child '{model.requested_child}' is not an existing physical breakout child; no request was sent.")
            result["before"] = self._export_topology(current, keys)
            creates = [model for model in models if not current[(model.switch_id, model.interface_name)]["broken_out"]] if state != "deleted" else []
            if state == "overridden":
                remove_keys = sorted(self._families(current).keys() - requested_keys)
                removals = [BreakoutInterfaceModel(switch_id=serial, interface_name=parent) for serial, parent in remove_keys]
            else:
                removals = [model for model in models if current[(model.switch_id, model.interface_name)]["broken_out"]] if state == "deleted" else []
            # A cold previous breakout can be visible as intent before it is a
            # usable remove target. Reuse this read and wait only when required.
            # Check mode predicts intent without waiting for device discovery.
            if guarded and removals and not check_mode:
                _, current = self._wait_for_inverse([self._submitted(model, current, "deleted") for model in removals], "deleted", current, require_map=True)
            # Only original unbreakout targets need a recovery MAP. An unrelated
            # family's unreadable speed must not block a merged breakout.
            if guarded and not check_mode:
                maps = {(model.switch_id, model.interface_name): self._recovery_map(current[(model.switch_id, model.interface_name)]) for model in removals}
            result["diff"] = self.format_config(creates + removals)
            actionable = {(model.switch_id, model.interface_name) for model in creates + removals}
            output_keys = requested_keys | actionable
            result["api_outcomes"] = [
                {
                    "switch_id": model.switch_id,
                    "interface_name": model.interface_name,
                    **({"requested_interface_name": model.requested_child} if model.requested_child is not None else {}),
                    "api_interface_name": None,
                    "action": "unbreakout" if state == "deleted" else "breakout",
                    "outcome": "noop",
                    "message": ("Parent is already native." if state == "deleted" else "Parent is already broken out; the existing map is not compared."),
                }
                for model in models
                if (model.switch_id, model.interface_name) not in actionable
            ]
            if check_mode:
                predicted = dict(current)
                for phase, planned in (("merged", creates), ("deleted", removals)):
                    for model in planned:
                        key = (model.switch_id, model.interface_name)
                        item = self._submitted(model, current, phase)
                        result["api_outcomes"].append(
                            {
                                **item,
                                "action": ("breakout" if phase == "merged" else "unbreakout"),
                                "outcome": "planned",
                            }
                        )
                        predicted[key] = {
                            "switch_id": key[0],
                            "interface_name": key[1],
                            "broken_out": phase == "merged",
                            "evidence": "prediction",
                        }
                        if phase == "merged":
                            predicted[key]["requested_breakout_map"] = model.breakout_map
                        else:
                            predicted[key]["children"] = []
                result.update(
                    changed=bool(actionable),
                    after=self._export_topology(predicted, output_keys),
                    after_status="predicted",
                )
                return result
            for phase, planned in (("merged", creates), ("deleted", removals)):
                if not planned:
                    continue
                # Indexed rows are immutable after discovery; phases replace
                # dictionary entries, never mutate the prior family's data.
                before = dict(current)
                submitted = [self._submitted(model, before, phase) for model in planned]
                outcomes, action_errors = self._execute_action(submitted, phase)
                completed = self._last_action_completed
                result["api_outcomes"].extend(outcomes)
                result["changed"] = result["changed"] or self._action_changed
                errors.extend(action_errors)
                phase_failed = bool(action_errors) or any(item["outcome"] != "success" for item in outcomes)
                errors.extend(item["message"] for item in outcomes if item["outcome"] == "failed")
                if guarded:
                    verification = result.setdefault(
                        "verification",
                        {"enabled": True, "complete": True, "phases": []},
                    )
                    serials = list(dict.fromkeys(item["switch_id"] for item in submitted))
                    mutated_switches = set(serials)
                    try:
                        observed = self._topology_snapshot(serials)
                    except Exception as error:
                        verification["complete"] = False
                        errors.append(f"Topology guard could not obtain a complete snapshot: {error}")
                        result.update(failed=True, may_have_changed=True)
                        return result
                    current = {key: row for key, row in before.items() if key[0] not in mutated_switches}
                    current.update(observed)
                    result["changed"] = result["changed"] or self._families(before) != self._families(current)
                    reports = self._guard(before, current, submitted, phase, requested_state=state)
                    verification["phases"].extend(reports)
                    offenders = {report["switch_id"] for report in reports if report["collateral"]}
                    for report in reports:
                        errors.extend(report["collateral"])
                        if not report["topology_matches"] and not report["collateral"]:
                            errors.append(f"Requested {report['phase']} topology was not observed on '{report['switch_id']}'.")
                    if offenders:
                        result["observed_before_recovery"] = self._export_topology(current, keys)
                        self._compensate(
                            result,
                            submitted,
                            before,
                            current,
                            phase,
                            maps,
                            offenders,
                            completed,
                        )
                        errors.extend(
                            f"Inverse {entry['action']} on switch '{entry['switch_id']}': {entry['status']}; "
                            "recovery topology was not independently verified."
                            for entry in result["recovery"]
                        )
                        result.update(failed=True, may_have_changed=True)
                        return result
                    if phase_failed or any(not report["topology_matches"] for report in reports):
                        last_observed = self._export_topology(current, output_keys)
                        result.update(
                            failed=True,
                            may_have_changed=any(item["outcome"] == "unknown" for item in outcomes),
                            after=last_observed,
                            after_status=self._observed_after_status(current, output_keys),
                        )
                        return result
                else:
                    if phase_failed:
                        result.update(failed=True, may_have_changed=True)
                        return result
                    for item in submitted:
                        key = (item["switch_id"], item["interface_name"])
                        current[key] = {
                            "switch_id": key[0],
                            "interface_name": key[1],
                            "broken_out": phase == "merged",
                            "evidence": "api_response",
                        }
                        if phase == "merged":
                            current[key]["requested_breakout_map"] = item["breakout_map"]
                        else:
                            current[key]["children"] = []
            result["after"] = self._export_topology(current, output_keys)
            result["after_status"] = (
                self._observed_after_status(current, output_keys) if guarded and actionable else "response_confirmed" if actionable else "unchanged"
            )
            return result
        except Exception as error:
            errors.append(str(error))
            result.update(
                failed=True,
                changed=result["changed"] or self._action_changed,
                may_have_changed=result["may_have_changed"] or (self._write_attempted and not check_mode),
            )
            return result
        finally:
            if errors:
                result["msg"] = _join_errors(errors)
            result["api_calls"] = list(self._api_calls)

    def _run_response_only(self) -> dict[str, Any]:
        """Run merged/deleted with response-based and optional observed results."""
        params = self.rest_send.params
        self._action_changed = False
        self._api_calls.clear()
        state = params.get("state", "merged")
        check_mode = bool(params.get("check_mode", False))
        result = {
            "changed": False,
            "failed": False,
            "may_have_changed": False,
            "api_outcomes": [],
            "after_status": "unknown",
            "proposed": [],
            "diff": [],
        }
        self._report = result
        errors = []
        try:
            if state not in {"merged", "deleted"}:
                raise ValueError(f"Unsupported state '{state}'; only merged and deleted are supported.")
            models = validate_module_params(params)
            result["proposed"] = self.format_config(models)
            selectors = self.fabric_context.resolve_switch_identifiers(model.switch_id for model in models)
            models = [model.model_copy(update={"switch_id": selectors[model.switch_id]}) for model in models]
            result["proposed"] = self.format_config(models)
            keys = [(model.switch_id, model.interface_name) for model in models]
            if len(keys) != len(set(keys)):
                raise ValueError("Duplicate switch/interface after IP-to-serial resolution.")
            self._validate_switch_platforms(models)
            before = self.discover(models)
            result["before"] = [copy.deepcopy(before[key]) for key in keys]
            # A child is a selector for its whole parent family, not a separate
            # deletable resource. Validate it only before an action: after a
            # successful unbreakout (or on a repeated run) it no longer exists.
            if state == "deleted":
                for model in models:
                    current = before[(model.switch_id, model.interface_name)]
                    if (
                        model.requested_child is not None
                        and current["broken_out"]
                        and model.requested_child.casefold() not in {name.casefold() for name in current["children"]}
                    ):
                        raise ValueError(
                            f"Requested child '{model.requested_child}' is not an existing physical breakout child of "
                            f"'{model.switch_id}/{model.interface_name}'; no unbreakout request was sent."
                        )
        except Exception as exc:
            result.update(failed=True, msg=str(exc), api_calls=list(self._api_calls))
            return result

        action = "breakout" if state == "merged" else "unbreakout"
        submitted = []
        outcomes = {}
        for model in models:
            key = (model.switch_id, model.interface_name)
            current = before[key]
            item = {
                "switch_id": model.switch_id,
                "interface_name": model.interface_name,
                "action": action,
            }
            if model.requested_child is not None:
                item["requested_interface_name"] = model.requested_child
            needs_action = not current["broken_out"] if state == "merged" else current["broken_out"]
            if not needs_action:
                outcomes[key] = {
                    **item,
                    "api_interface_name": None,
                    "outcome": "noop",
                    "message": (
                        "Parent is already broken out; the existing map is not compared."
                        if state == "merged"
                        else "Parent is already native; no unbreakout request is needed."
                    ),
                }
                continue
            item["api_interface_name"] = model.interface_name if state == "merged" else current["children"][0]
            if state == "merged":
                item["breakout_map"] = model.breakout_map
            submitted.append(item)

        submitted_keys = {(item["switch_id"], item["interface_name"]) for item in submitted}
        result["diff"] = self.format_config([model for model in models if (model.switch_id, model.interface_name) in submitted_keys])
        if check_mode:
            action_outcomes = [
                {
                    **item,
                    "outcome": "planned",
                    "message": "Immediate topology action would be submitted.",
                }
                for item in submitted
            ]
        elif submitted:
            action_outcomes, errors = self._execute_action(submitted, state)
        else:
            action_outcomes = []
        outcomes.update({(item["switch_id"], item["interface_name"]): item for item in action_outcomes})
        result["api_outcomes"] = [outcomes[key] for key in keys]
        unknown = any(item["outcome"] == "unknown" for item in action_outcomes)
        failed = bool(errors) or any(item["outcome"] in {"failed", "unknown"} for item in action_outcomes)
        result["changed"] = any(item["outcome"] == "planned" for item in action_outcomes) if check_mode else self._action_changed
        result["may_have_changed"] = failed and not check_mode
        after = copy.deepcopy(before)
        for item in action_outcomes:
            if item["outcome"] not in {"success", "planned"}:
                continue
            key = (item["switch_id"], item["interface_name"])
            after[key] = {
                "switch_id": key[0],
                "interface_name": key[1],
                "broken_out": state == "merged",
                "evidence": "prediction" if check_mode else "api_response",
            }
            if state == "merged":
                after[key]["requested_breakout_map"] = item["breakout_map"]
        if unknown or failed:
            result["after_status"] = "unknown"
        else:
            result["after_status"] = "predicted" if check_mode else "response_confirmed" if submitted else "unchanged"
            result["after"] = [after[key] for key in keys]

        result["failed"] = failed
        if failed:
            result["msg"] = _join_errors(errors) or "One or more topology actions failed."
        result["api_calls"] = list(self._api_calls)
        return result
