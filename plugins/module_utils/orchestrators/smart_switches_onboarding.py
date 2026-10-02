# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Adapt Smart Switch actions to generic per-resource mutation evidence."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_smart_switches import (
    EpManageSmartSwitchesDeboardPost,
    EpManageSmartSwitchesOnboardPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import EpManageSwitchesListGet
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import (
    SmartSwitchDeboardEntry,
    SmartSwitchDeboardRequestModel,
    SmartSwitchOnboardingModel,
    SmartSwitchOnboardingResultEntry,
    SmartSwitchOnboardingResultsModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import MutationOutcome, MutationResourceOutcome, MutationResult
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator


class SmartSwitchOnboardingResponseAdapter:
    """Correlate wrapper membership using the controller's exact name=switchId contract."""

    @staticmethod
    def normalize(body: Any, expected_identifiers: Sequence[str]) -> MutationResult:
        if not isinstance(body, dict):
            return MutationResult(protocol_errors=("Onboarding response must be an object",))
        grouped: dict[str, list[tuple[str, SmartSwitchOnboardingResultEntry]]] = {}
        errors: list[str] = []
        invalid_keys: set[str] = set()
        for side, attribute in (("successResults", "success_results"), ("failureResults", "failure_results")):
            raw_entries = body.get(side, [])
            try:
                wrapper = SmartSwitchOnboardingResultsModel.model_validate({side: raw_entries})
                entries = getattr(wrapper, attribute)
            except ValidationError:
                # A malformed neighbor must not erase independently valid
                # evidence. Recover entries separately, retaining every error.
                if not isinstance(raw_entries, list):
                    errors.append(f"{side} must be an array")
                    continue
                entries = []
                for raw in raw_entries:
                    try:
                        if not isinstance(raw, dict):
                            raise ValueError("result entry must be an object")
                        entries.append(SmartSwitchOnboardingResultEntry.model_validate(raw))
                    except (ValidationError, ValueError) as error:
                        errors.append(f"Malformed {side} entry: {error}")
                        if isinstance(raw, dict) and isinstance(raw.get("name"), str) and raw["name"] in expected_identifiers:
                            invalid_keys.add(raw["name"])
            for entry in entries:
                if entry.name not in expected_identifiers:
                    errors.append(f"Unexpected result name {entry.name!r}")
                    continue
                grouped.setdefault(entry.name, []).append((side, entry))
        outcomes = []
        for key in expected_identifiers:
            entries = grouped.get(key, [])
            sides = {side for side, entry in entries}
            if len(sides) > 1:
                errors.append(f"Contradictory success and failure for {key!r}")
            if key in invalid_keys or len(sides) != 1:
                outcome = MutationOutcome.UNKNOWN
            elif "successResults" in sides:
                outcome = MutationOutcome.SUCCEEDED
            else:
                outcome = MutationOutcome.FAILED
            outcomes.append(
                MutationResourceOutcome(
                    key,
                    outcome,
                    statuses=(entry.status for side, entry in entries if entry.status is not None),
                    messages=(entry.message for side, entry in entries if entry.message is not None),
                    evidence=({"source": side, "returned_name": entry.name, "match": "exact_switch_id"} for side, entry in entries),
                )
            )
        return MutationResult(tuple(outcomes), tuple(errors))


class SmartSwitchOnboardingOrchestrator(NDBaseOrchestrator[SmartSwitchOnboardingModel]):
    """Cache complete fabric inventory and execute association actions only."""

    model_class: ClassVar[type[SmartSwitchOnboardingModel]] = SmartSwitchOnboardingModel
    supports_mutation_outcomes: ClassVar[bool] = True
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    bulk_payload_key: ClassVar[str] = "smartSwitchIntegrations"
    create_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesOnboardPost
    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesOnboardPost
    delete_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesDeboardPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesDeboardPost
    update_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageSwitchesListGet
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageSwitchesListGet
    fabric_name: str
    cluster_name: str | None = None
    _inventory: dict[str, dict[str, Any]] | None = None

    def _action_endpoint(self, endpoint_class: type[NDEndpointBaseModel]) -> NDEndpointBaseModel:
        endpoint = endpoint_class(fabric_name=self.fabric_name)
        endpoint.endpoint_params.cluster_name = self.cluster_name
        return endpoint

    def _normalize_row(self, row: Any) -> dict[str, Any]:
        if not isinstance(row, dict) or not isinstance(row.get("switchId"), str) or not row["switchId"]:
            raise ValueError("Inventory row requires a nonempty string switchId")
        if row.get("fabricName", self.fabric_name) != self.fabric_name:
            raise ValueError(f"Switch {row['switchId']!r} belongs to another fabric")
        variants = [row[key] for key in ("additionalData", "additionalSwitchData") if key in row]
        if any(not isinstance(value, dict) for value in variants) or (len(variants) == 2 and variants[0] != variants[1]):
            raise ValueError(f"Conflicting or malformed additional data for {row['switchId']!r}")
        additional = variants[0] if variants else {}
        smart = additional.get("smartSwitch", False)
        if not isinstance(smart, bool):
            raise ValueError(f"Unknown Smart Switch capability for {row['switchId']!r}")
        # TODO: Revisit hypershieldIntegrationName as the onboarding predicate
        # with before/onboarded/deboarded captures across supported ND releases.
        # User-confirmed contract: nonempty means onboarded; explicit empty means absent.
        if smart and "hypershieldIntegrationName" not in additional:
            raise ValueError(f"Unknown onboarding state for {row['switchId']!r}: missing hypershieldIntegrationName")
        integration = additional.get("hypershieldIntegrationName", "")
        if not isinstance(integration, str):
            raise ValueError(f"Unknown onboarding state for {row['switchId']!r}")
        if integration and not smart:
            raise ValueError(f"Conflicting Smart Switch capability/association for {row['switchId']!r}")
        return {"switch_id": row["switchId"], "switch_name": row.get("hostname"), "integration_name": integration, "smart": smart}

    def _load_inventory(self) -> dict[str, dict[str, Any]]:
        if self._inventory is not None:
            return self._inventory
        inventory: dict[str, dict[str, Any]] = {}
        offset = 0
        total: int | None = None
        for page_number in range(10000):
            endpoint = self.query_all_endpoint(fabric_name=self.fabric_name)
            endpoint.endpoint_params.cluster_name = self.cluster_name
            endpoint.lucene_params.max = 1000
            endpoint.lucene_params.offset = offset
            endpoint.lucene_params.sort = "switchId:asc"
            body = self._request(endpoint.path, endpoint.verb)
            if self.rest_send.return_code != 200 or not isinstance(body, dict) or not isinstance(body.get("switches"), list):
                raise ValueError("Inventory GET must return HTTP 200 with a switches array")
            rows = body["switches"]
            for raw in rows:
                normalized = self._normalize_row(raw)
                key = normalized["switch_id"]
                if key in inventory:
                    raise ValueError(f"Duplicate inventory switchId {key!r}; pagination is ambiguous")
                inventory[key] = normalized
            offset += len(rows)
            metadata = body.get("meta", {})
            if not isinstance(metadata, dict):
                raise ValueError("Malformed inventory metadata")
            counts = metadata.get("counts")
            if counts is not None:
                if not isinstance(counts, dict):
                    raise ValueError("Malformed inventory counts")
                current_total, remaining = counts.get("total"), counts.get("remaining")
                if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (current_total, remaining)):
                    raise ValueError("Inventory total and remaining must be nonnegative integers")
                if total is not None and current_total != total:
                    raise ValueError("Inventory total changed during pagination")
                total = current_total
                if offset > total or remaining != total - offset:
                    raise ValueError("Inventory counts do not match collected rows")
                if remaining == 0:
                    self._inventory = inventory
                    return inventory
            if not rows:
                if total is not None and offset != total:
                    raise ValueError("Inventory ended before all switches were read")
                self._inventory = inventory
                return inventory
        raise ValueError("Inventory pagination did not terminate safely")

    def query_all(self, model_instance: SmartSwitchOnboardingModel | None = None, **kwargs) -> list[dict[str, Any]]:
        return [
            {"switchId": row["switch_id"], "switchName": row["switch_name"], "integrationName": row["integration_name"]}
            for row in self._load_inventory().values()
            if row["integration_name"]
        ]

    def query_one(self, model_instance: SmartSwitchOnboardingModel, **kwargs) -> dict[str, Any]:
        return next((row for row in self.query_all() if row["switchId"] == model_instance.switch_id), {})

    def prepare_config_data(self, raw_config):
        """Resolve/validate every selector on a copy using the same initial snapshot."""
        inventory = self._load_inventory()
        config = deepcopy(raw_config)
        seen: set[str] = set()
        state = self.rest_send.params.get("state")
        for item in config:
            if not isinstance(item, dict):
                raise ValueError("Each config item must be an object")
            key = item.get("switch_id")
            if not isinstance(key, str) or not key:
                raise ValueError("switch_id must be a nonempty string")
            if key in seen:
                raise ValueError(f"Duplicate desired switch_id {key!r}")
            seen.add(key)
            row = inventory.get(key)
            if row is None:
                if state == "deleted":
                    continue
                raise ValueError(f"Switch {key!r} is absent from fabric inventory")
            if item.get("switch_name") is not None and item["switch_name"] != row["switch_name"]:
                raise ValueError(f"switch_id and switch_name conflict for {key!r}")
            if state != "deleted":
                if not row["smart"]:
                    raise ValueError(f"Switch {key!r} is not Smart Switch capable")
                if not isinstance(row["switch_name"], str) or not row["switch_name"]:
                    raise ValueError(f"Inventory hostname missing for {key!r}")
                item["switch_name"] = row["switch_name"]
        return config

    def preflight(self, model_instances: Sequence[SmartSwitchOnboardingModel]) -> None:
        inventory = self._load_inventory()
        for item in model_instances:
            row = inventory.get(item.switch_id)
            if row is None or not row["smart"]:
                raise ValueError(f"Switch {item.switch_id!r} is absent or not Smart Switch capable")
            if not item.integration_name or not item.switch_name:
                raise ValueError("integration_name and prepared switch_name are required")
            if row["integration_name"] and row["integration_name"] != item.integration_name:
                raise ValueError(f"Switch {item.switch_id!r} is already onboarded to {row['integration_name']!r}; update is not supported")

    def create(self, model_instance: SmartSwitchOnboardingModel, **kwargs) -> MutationResult:
        return self.create_bulk([model_instance], **kwargs)

    def create_bulk(self, model_instances: list[SmartSwitchOnboardingModel], **kwargs) -> MutationResult:
        if not model_instances:
            return MutationResult()
        keys = tuple(item.switch_id for item in model_instances)
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate requested switch identifiers")
        if any(not item.integration_name or not item.switch_name for item in model_instances):
            raise ValueError("integration_name and switch_name are required for onboarding")
        endpoint = self._action_endpoint(self.create_bulk_endpoint)
        body = self._request(
            endpoint.path, endpoint.verb, {self.bulk_payload_key: [item.to_payload() for item in model_instances]}, operation_type=OperationType.CREATE
        )
        if self.rest_send.return_code != 202:
            return MutationResult(protocol_errors=(f"Expected onboarding HTTP 202, received {self.rest_send.return_code}",))
        return SmartSwitchOnboardingResponseAdapter.normalize(body, keys)

    def delete(self, model_instance: SmartSwitchOnboardingModel, **kwargs) -> MutationResult:
        return self.delete_bulk([model_instance], **kwargs)

    def delete_bulk(self, model_instances: list[SmartSwitchOnboardingModel], **kwargs) -> MutationResult:
        if not model_instances:
            return MutationResult()
        keys = tuple(item.switch_id for item in model_instances)
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate requested switch identifiers")
        payload = SmartSwitchDeboardRequestModel(smart_switch_integrations=[SmartSwitchDeboardEntry(switch_id=key) for key in keys])
        endpoint = self._action_endpoint(self.delete_bulk_endpoint)
        body = self._request(endpoint.path, endpoint.verb, payload.model_dump(by_alias=True), operation_type=OperationType.DELETE)
        if self.rest_send.return_code != 202:
            return MutationResult(protocol_errors=(f"Expected bulk deboarding HTTP 202, received {self.rest_send.return_code}",))
        # API-owner confirmation (2026-10-08): a bodyless 202 proves every
        # requested deboarding effect, unlike onboarding's keyed result body.
        # HTTPAPI normalizes empty content to {}; test senders may use None.
        # TODO: Revisit this completion guarantee using supported-release captures.
        if body is not None and body != {}:
            return MutationResult(protocol_errors=("Expected bodyless bulk deboarding HTTP 202; final effects are unknown",))
        return MutationResult(
            tuple(
                MutationResourceOutcome(key, MutationOutcome.SUCCEEDED, evidence=({"http_status": 202, "match": "bulk_request_completion"},)) for key in keys
            )
        )

    def update(self, model_instance: SmartSwitchOnboardingModel, **kwargs) -> MutationResult:
        # TODO: Define update/re-association semantics from live-controller evidence in a later iteration.
        raise NotImplementedError("Updating an onboarded Smart Switch association is not supported")
