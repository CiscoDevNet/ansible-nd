# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Response-first breakout actions, with scoped discovery and optional verification."""

from __future__ import annotations

import copy
import re
import time
from collections import defaultdict
from os.path import commonprefix
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import PrivateAttr
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesBreakout,
    EpManageInterfacesRemove,
    EpManageInterfacesSummaryGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType, PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_breakout_interfaces.breakout_interface import (
    BreakoutInterfaceModel,
    validate_module_params,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_strategies.nd_v1_strategy import NdV1Strategy, _failed_multistatus_items

_PAGE_SIZE = 1000
_MAX_PAGES = 100
_PARENT = re.compile(r"^Ethernet(?P<slot>[1-9]\d*)/(?P<port>[1-9]\d*)$", re.IGNORECASE)


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
    configuration. Missing results remain unknown. No mutation is replayed.
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
        platforms = self.fabric_context.get_switch_platform_types(dict.fromkeys(model.switch_id for model in models))
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
            path, HttpVerbEnum.GET, OperationType.QUERY, None, error, self.rest_send.response_current if response_received else None
        )
        self._api_calls.append(
            {
                "method": "GET",
                "path": path,
                "http_status": self.rest_send.return_code if response_received else None,
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
            else {"RETURN_CODE": -1, "MESSAGE": str(error), "DATA": {}, "response_received": False}
        )
        self.results.result_current = {"success": False, "found": False, "changed": False}
        self.results.diff_current = {}
        self.results.verbosity_level_current = 3 if operation_type == OperationType.QUERY else 2
        self.results.register_api_call()

    def _request(self, path, verb, data=None, not_found_ok=False, operation_type=OperationType.QUERY):
        """Keep the standard response handler; cap action requests at one send."""
        previous_limit = self.rest_send.max_attempts
        generation = self.rest_send.response_generation
        registered_before = self.results.task_sequence_number if self.results is not None else None
        started = time.monotonic()
        if data is None:
            self.rest_send.clear_payload()
        if verb != HttpVerbEnum.GET:
            self.rest_send.max_attempts = 1
        try:
            return super()._request(path, verb, data, not_found_ok, operation_type)
        except Exception as error:
            if self.results is not None and self.results.task_sequence_number == registered_before:
                self._register_unanswered_request(
                    path, verb, operation_type, data, error, self.rest_send.response_current if self.rest_send.response_generation > generation else None
                )
            raise
        finally:
            self.rest_send.max_attempts = previous_limit
            fresh = self.rest_send.response_generation > generation
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
    def discovery_groups(models: list[BreakoutInterfaceModel]) -> list[tuple[str, str, list[BreakoutInterfaceModel]]]:
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

    def _query_group(self, switch_id: str, filter_text: str) -> list[dict[str, Any]]:
        """Read a filtered interface family/group, following bounded pagination."""
        rows = []
        offset = 0
        fingerprints = set()
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
            fingerprint = tuple((row.get("switchId"), row.get("interfaceName"), row.get("physicalInterface")) for row in page)
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
            has_more = (
                counts["remaining"] > 0 if "remaining" in counts else offset + len(page) < counts["total"] if "total" in counts else len(page) >= _PAGE_SIZE
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
        children = []
        native = []
        seen = set()
        child_re = re.compile(re.escape(parent) + r"/([1-9]\d*)$", re.IGNORECASE)
        for row in rows:
            name = row.get("interfaceName")
            if not isinstance(name, str):
                continue
            is_parent = name.casefold() == parent.casefold()
            child = child_re.fullmatch(name)
            if not is_parent and child is None:
                continue
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
            outcome = {**item, "action": action, "outcome": "unknown", "message": "No identifiable result was returned for this action."}
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
                    outcome.update(outcome="success", message=row.get("message") or "Action reported success.")
                elif _failed_multistatus_items(one_item):
                    outcome.update(outcome="failed", message=row.get("message") or "Action reported failure.")
                else:
                    outcome["message"] = row.get("message") or f"Unrecognized action status '{status}'."
            if outcome["outcome"] == "unknown":
                errors.append(f"Outcome unresolved for '{item['switch_id']}/{item['interface_name']}': {outcome['message']}")
            outcomes.append(outcome)
        return outcomes, errors

    def _execute_action(self, submitted: list[dict[str, Any]], state: str) -> tuple[list[dict[str, Any]], list[str]]:
        """Send one bulk POST; retain fresh partial results even when shared handling fails."""
        action = "breakout" if state == "merged" else "unbreakout"
        endpoint_class = EpManageInterfacesBreakout if state == "merged" else EpManageInterfacesRemove
        endpoint = endpoint_class(fabric_name=self.fabric_name)
        interfaces = []
        for item in submitted:
            wire_item = {"switchId": item["switch_id"], "interfaceName": item["api_interface_name"]}
            if state == "merged":
                wire_item["breakoutMap"] = item["breakout_map"]
            interfaces.append(wire_item)
        before_generation = self.rest_send.response_generation
        request_error = None
        try:
            self._request(
                endpoint.path, endpoint.verb, {"interfaces": interfaces}, operation_type=OperationType.CREATE if state == "merged" else OperationType.DELETE
            )
        except Exception as exc:  # Preserve the response; never replay an uncertain action.
            request_error = str(exc)
        if self.rest_send.response_generation == before_generation:
            message = request_error or "No controller response received."
            return [{**item, "action": action, "outcome": "unknown", "message": message} for item in submitted], [message]
        response = self.rest_send.response_current
        outcomes, errors = self.match_action_results(response, submitted, action)
        # Reuse the shared mutation-evidence rule, but only feed identity-confirmed
        # successes. An unrequested/duplicate/missing row cannot prove a change.
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
            item = {"switch_id": model.switch_id, "interface_name": model.interface_name, "action": action}
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
            action_outcomes = [{**item, "outcome": "planned", "message": "Immediate topology action would be submitted."} for item in submitted]
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

        # This GET is opt-in and restricted to the families that were actually submitted.
        if not check_mode and submitted and (params.get("verify") or {}).get("enabled", False):
            try:
                mutation_keys = {(item["switch_id"], item["interface_name"]) for item in submitted}
                observed = self.discover([model for model in models if (model.switch_id, model.interface_name) in mutation_keys])
                observed_after = {key: {**resource, "evidence": "initial_discovery"} for key, resource in before.items()}
                observed_after.update({key: {**resource, "evidence": "post_action_discovery"} for key, resource in observed.items()})
                result["after"] = [observed_after[key] for key in keys]
                result["after_status"] = "observed" if len(mutation_keys) == len(keys) else "partially_observed"
                result["changed"] = any(observed_after[key]["broken_out"] != before[key]["broken_out"] for key in keys) or result["changed"]
                result["verification"] = {
                    "enabled": True,
                    "complete": True,
                    "scope": [key for key in keys if key in mutation_keys],
                    "topology_matches": all(observed[key]["broken_out"] == (state == "merged") for key in mutation_keys),
                }
                if not result["verification"]["topology_matches"]:
                    errors.append("Observed requested topology does not match the requested state.")
                    failed = True
            except Exception as exc:
                errors.append(f"Optional topology verification failed: {exc}")
                result["verification"] = {"enabled": True, "complete": False}
                result.pop("after", None)
                result["after_status"] = "unknown"
                result["may_have_changed"] = True
                failed = True

        result["failed"] = failed
        if failed:
            result["msg"] = "; ".join(dict.fromkeys(errors)) or "One or more topology actions failed."
        result["api_calls"] = list(self._api_calls)
        return result
