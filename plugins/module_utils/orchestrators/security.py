# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Orchestrators for Nexus Dashboard security and segmentation resources."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any, ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import (
    SECURITY_CONFIG_ACTIONS,
)
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    ConfigActionsPolicy,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.security import (
    EpManageSecurityAssociationsAttach,
    EpManageSecurityAssociationsDelete,
    EpManageSecurityAssociationsDetach,
    EpManageSecurityAssociationsGet,
    EpManageSecurityAssociationsListGet,
    EpManageSecurityAssociationsPost,
    EpManageSecurityAssociationsPut,
    EpManageSecurityAssociationsRemove,
    EpManageSecurityContractsDelete,
    EpManageSecurityContractsGet,
    EpManageSecurityContractsListGet,
    EpManageSecurityContractsPost,
    EpManageSecurityContractsPut,
    EpManageSecurityContractsRemove,
    EpManageSecurityFabricConfigSave,
    EpManageSecurityFabricDeploy,
    EpManageSecurityFabricSwitchDeploy,
    EpManageSecurityGroupsAttach,
    EpManageSecurityGroupsDelete,
    EpManageSecurityGroupsDetach,
    EpManageSecurityGroupsGet,
    EpManageSecurityGroupsListGet,
    EpManageSecurityGroupsPost,
    EpManageSecurityGroupsPut,
    EpManageSecurityGroupsRemove,
    EpManageSecurityProtocolDefinitionsDelete,
    EpManageSecurityProtocolDefinitionsGet,
    EpManageSecurityProtocolDefinitionsListGet,
    EpManageSecurityProtocolDefinitionsPost,
    EpManageSecurityProtocolDefinitionsPut,
    EpManageSecurityProtocolDefinitionsRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import (
    EpManageSwitchesListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import (
    SecurityAssociationModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.contracts import (
    SecurityContractModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import (
    SecurityGroupModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.protocol_definitions import (
    SecurityProtocolDefinitionModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    ModelType,
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import (
    ConfigActionsMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)


class ManageSecurityResourceOrchestrator(ConfigActionsMixin, NDBaseOrchestrator[ModelType]):
    """Shared CRUD, action, pagination, and config-action behavior for security resources."""

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    config_actions_policy: ClassVar[ConfigActionsPolicy] = SECURITY_CONFIG_ACTIONS

    list_response_key: ClassVar[str]
    create_payload_key: ClassVar[str]
    create_response_key: ClassVar[str]
    remove_payload_key: ClassVar[str]
    remove_response_key: ClassVar[str]
    resource_name_label: ClassVar[str] = "name"
    page_size: ClassVar[int] = 1000
    max_pages: ClassVar[int] = 10_000
    immutable_update_fields: ClassVar[tuple[str, ...]] = ()
    case_insensitive_immutable_fields: ClassVar[tuple[str, ...]] = ()
    optional_derived_immutable_fields: ClassVar[tuple[str, ...]] = ()

    attach_endpoint: Type[NDEndpointBaseModel] | None = None
    detach_endpoint: Type[NDEndpointBaseModel] | None = None
    action_payload_key: ClassVar[str | None] = None
    action_response_key: ClassVar[str | None] = None

    _fabric_context: FabricContext | None = None

    def model_post_init(self, __context) -> None:
        """Initialize per-instance action queues and the inventory cache."""
        super().model_post_init(__context)
        self._pending_attach: list[str] = []
        self._pending_detach: list[str] = []
        self._existing_by_identifier: dict[object, ModelType] = {}
        self._accepted_upserts: dict[object, ModelType] = {}
        self._accepted_deletes: dict[object, ModelType] = {}
        self._accepted_action_states: dict[object, bool] = {}
        self._pending_action_errors: list[str] = []
        raw_config = self.rest_send.params.get("config") or []
        if not isinstance(raw_config, list):
            raw_config = []
        self._managed_display_name_identifiers: set[object] = set()
        for item in raw_config:
            if not isinstance(item, dict):
                continue
            display_name = item.get("display_name")
            if not isinstance(display_name, str) or not display_name.strip():
                display_name = item.get("displayName")
            if not isinstance(display_name, str) or not display_name.strip():
                continue
            identity = self._mapping_identity(item)
            if identity is not None:
                self._managed_display_name_identifiers.add(identity)

    @property
    def fabric_name(self) -> str:
        """Return the fabric name from module params."""
        return self.rest_send.params.get("fabric_name")

    @property
    def cluster_name(self) -> str | None:
        """Return the optional cluster name from module params."""
        return self.rest_send.params.get("cluster_name")

    @property
    def fabric_context(self) -> FabricContext:
        """Return cached fabric context for preflight validation."""
        if self._fabric_context is None:
            self._fabric_context = FabricContext(
                rest_send=self.rest_send,
                fabric_name=self.fabric_name,
                cluster_name=self.cluster_name,
            )
        return self._fabric_context

    def model_validation_context(self) -> dict[str, Any]:
        """Expose the cached controller version to version-aware security validators."""
        return {"controller_version": self.rest_send.controller_version}

    def validate_prerequisites(self) -> None:
        """Validate fabric existence for reads and mutation eligibility for writes."""
        if self.rest_send.params.get("state") == "gathered":
            if not self.fabric_context.fabric_exists():
                raise RuntimeError(f"Fabric '{self.fabric_name}' not found.")
            return
        self.fabric_context.validate_for_mutation()

    def _configure_endpoint(self, api_endpoint: NDEndpointBaseModel) -> NDEndpointBaseModel:
        """Set fabric and cluster context on an endpoint before path generation."""
        api_endpoint.fabric_name = self.fabric_name
        endpoint_params = getattr(api_endpoint, "endpoint_params", None)
        if endpoint_params is not None and hasattr(endpoint_params, "cluster_name"):
            endpoint_params.cluster_name = self.cluster_name
        return api_endpoint

    # ConfigActionsMixin endpoint hooks keep every security action cluster-aware.
    def config_save_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self._configure_endpoint(EpManageSecurityFabricConfigSave(fabric_name=fabric_name))

    def deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        endpoint = self._configure_endpoint(EpManageSecurityFabricDeploy(fabric_name=fabric_name))
        endpoint.endpoint_params.incl_all_fabric_groups_switches = True
        return endpoint

    def switches_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self._configure_endpoint(EpManageSwitchesListGet(fabric_name=fabric_name))

    def switch_deploy_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self._configure_endpoint(EpManageSecurityFabricSwitchDeploy(fabric_name=fabric_name))

    def _explicit_display_name_identifiers(self) -> set[object]:
        """Return resource names whose input explicitly manages ``display_name``."""
        return self._managed_display_name_identifiers

    def _mapping_identity(self, item: dict[str, Any]) -> object | None:
        """Return a qualified, model-defined identity from config or response data."""
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            return None
        wire_name = name.strip()
        tenant_name = item.get("tenantName", item.get("tenant_name"))
        if isinstance(tenant_name, str) and tenant_name.strip() and "~" not in wire_name:
            wire_name = f"{tenant_name.strip()}~{wire_name}"
        return self._identity_key(wire_name)

    def _normalize_response_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """Normalize empty optional strings and unrequested generated display names."""
        normalized = dict(item)
        for optional_string in ("tenantName", "displayName"):
            if normalized.get(optional_string) == "":
                normalized.pop(optional_string, None)
        response_identity = self._mapping_identity(normalized)
        if normalized.get("displayName") == normalized.get("name") and response_identity not in self._explicit_display_name_identifiers():
            normalized.pop("displayName", None)
        return normalized

    @staticmethod
    def _pagination_count(result: dict[str, Any], key: str) -> int | None:
        """Return a validated pagination count, failing on malformed metadata."""
        if "meta" not in result:
            return None
        meta = result["meta"]
        if not isinstance(meta, dict):
            raise RuntimeError("Security resource page field 'meta' must be an object.")
        if "counts" not in meta:
            return None
        counts = meta["counts"]
        if not isinstance(counts, dict):
            raise RuntimeError("Security resource page field 'meta.counts' must be an object.")
        if key not in counts or counts[key] is None:
            return None
        value = counts[key]
        if isinstance(value, bool):
            raise RuntimeError(f"Security resource page field 'meta.counts.{key}' must be a non-negative integer.")
        if isinstance(value, int):
            parsed = value
        elif isinstance(value, str) and value.isdigit():
            parsed = int(value)
        else:
            raise RuntimeError(f"Security resource page field 'meta.counts.{key}' must be a non-negative integer.") from None
        if parsed < 0:
            raise RuntimeError(f"Security resource page field 'meta.counts.{key}' must be a non-negative integer.")
        return parsed

    @classmethod
    def _remaining_count(cls, result: dict[str, Any]) -> int | None:
        """Return validated `meta.counts.remaining` when supplied."""
        return cls._pagination_count(result, "remaining")

    @classmethod
    def _total_count(cls, result: dict[str, Any]) -> int | None:
        """Return validated `meta.counts.total` when supplied."""
        return cls._pagination_count(result, "total")

    @staticmethod
    def _next_page_link(result: dict[str, Any]) -> str | None:
        """Return validated `meta.links.next` when supplied."""
        if "meta" not in result:
            return None
        meta = result["meta"]
        if not isinstance(meta, dict):
            raise RuntimeError("Security resource page field 'meta' must be an object.")
        if "links" not in meta:
            return None
        links = meta["links"]
        if not isinstance(links, dict):
            raise RuntimeError("Security resource page field 'meta.links' must be an object.")
        next_link = links.get("next")
        if next_link is not None and not isinstance(next_link, str):
            raise RuntimeError("Security resource page field 'meta.links.next' must be a string or null.")
        return next_link

    def _unique_page_items(self, items: Sequence[dict[str, Any]], seen_identifiers: set[object]) -> list[dict[str, Any]]:
        """Validate/cache a page and return only first occurrences of complete identities."""
        unique_items: list[dict[str, Any]] = []
        for item in items:
            current = self.model_class.from_response(item)
            identifier = current.get_identifier_value()
            if identifier in seen_identifiers:
                continue
            seen_identifiers.add(identifier)
            self._existing_by_identifier[identifier] = current
            unique_items.append(item)
        return unique_items

    @property
    def accepted_upserts(self) -> tuple[ModelType, ...]:
        """Return accepted resource models with exact attachment outcomes."""
        accepted: list[ModelType] = []
        for identifier, model in self._accepted_upserts.items():
            actual = model.model_copy(deep=True)
            if self.action_payload_key is not None and hasattr(actual, "attach"):
                if identifier in self._accepted_action_states:
                    actual.attach = self._accepted_action_states[identifier]
                else:
                    previous = self._existing_by_identifier.get(identifier)
                    if previous is not None:
                        actual.attach = getattr(previous, "attach", None)
                    elif "attach" in model.model_fields_set:
                        # CRUD omits this action-owned field. Both supported API
                        # schemas default a new resource to attached, so retain
                        # that known controller state if the requested action
                        # did not succeed and no refresh supplied a newer value.
                        actual.attach = True
            accepted.append(actual)
        return tuple(accepted)

    @property
    def accepted_deletes(self) -> tuple[ModelType, ...]:
        """Return resource models whose delete was accepted this run."""
        return tuple(model.model_copy(deep=True) for model in self._accepted_deletes.values())

    @property
    def pending_action_errors(self) -> tuple[str, ...]:
        """Return attach/detach failures collected while draining both queues."""
        return tuple(self._pending_action_errors)

    @property
    def has_accepted_mutations(self) -> bool:
        """Return whether any resource mutation reached the controller."""
        return bool(self._accepted_upserts or self._accepted_deletes)

    def _record_upserts(self, model_instances: Sequence[ModelType]) -> None:
        """Record controller-accepted create/update models by complete identity."""
        for model_instance in model_instances:
            identifier = model_instance.get_identifier_value()
            self._accepted_deletes.pop(identifier, None)
            self._accepted_upserts[identifier] = model_instance.model_copy(deep=True)

    def _record_deletes(self, model_instances: Sequence[ModelType]) -> None:
        """Record controller-accepted delete models by complete identity."""
        for model_instance in model_instances:
            identifier = model_instance.get_identifier_value()
            self._accepted_upserts.pop(identifier, None)
            self._accepted_deletes[identifier] = model_instance.model_copy(deep=True)

    def _response_item_name(self, item: dict[str, Any]) -> str | None:
        """Return a per-family security response item's resource name."""
        label_keys = tuple(
            dict.fromkeys(
                (
                    self.resource_name_label,
                    "name",
                    "resourceName",
                    "protocolDefinitionName",
                    "contractName",
                    "securityGroupName",
                    "securityAssociationName",
                )
            )
        )
        for label_key in label_keys:
            name = item.get(label_key)
            if isinstance(name, str) and name.strip():
                return name.strip()
        return None

    def _identity_key(self, name: str) -> object:
        """Return the model-defined identity for a controller resource name."""
        probe = self.model_class.model_construct(name=name)
        return probe.get_identifier_value()

    def _apply_create_response_fields(self, model_instances: Sequence[ModelType], response_data: Any) -> None:
        """Apply controller-generated create fields; overridden by resource families that need it."""
        del model_instances, response_data

    def _multistatus_outcomes(self, response_keys: Sequence[str]) -> dict[object, bool]:
        """Return validated per-resource outcomes from the latest itemized 2xx response."""
        return_code = self.rest_send.return_code
        if not isinstance(return_code, int) or not 200 <= return_code < 300:
            return {}
        malformed_prefix = f"Malformed HTTP {return_code} security response"
        data = self.rest_send.response_current.get("DATA")
        if not isinstance(data, dict):
            raise RuntimeError(f"{malformed_prefix}: DATA must be an object.")
        present_keys = [response_key for response_key in dict.fromkeys(response_keys) if response_key in data]
        if not present_keys:
            expected = ", ".join(response_keys)
            raise RuntimeError(f"{malformed_prefix}: DATA is missing the expected envelope ({expected}).")
        outcomes: dict[object, bool] = {}
        for response_key in present_keys:
            items = data[response_key]
            if not isinstance(items, list):
                raise RuntimeError(f"{malformed_prefix}: DATA.{response_key} must be a list.")
            for index, item in enumerate(items):
                if not isinstance(item, dict):
                    raise RuntimeError(f"{malformed_prefix}: DATA.{response_key}[{index}] must be an object.")
                name = self._response_item_name(item)
                if name is None:
                    raise RuntimeError(f"{malformed_prefix}: DATA.{response_key}[{index}] has no resource name.")
                identity = self._identity_key(name)
                if identity in outcomes:
                    raise RuntimeError(f"{malformed_prefix}: duplicate resource outcome for '{name}'.")
                status = item.get("status")
                # Deny by default: only the exact documented success token is
                # accepted.  Warning, failure, error, missing, and unknown
                # statuses remain rejected while exact-success siblings can
                # still be finalized.
                outcomes[identity] = isinstance(status, str) and status.strip().casefold() == "success"
        return outcomes

    def _accepted_names_from_latest_response(
        self,
        submitted_names: Sequence[str],
        response_keys: Sequence[str],
        previous_response_count: int,
    ) -> list[str]:
        """Return exact-success submitted names from a fresh, complete itemized 2xx response."""
        return_code = self.rest_send.return_code
        if self.rest_send.response_count <= previous_response_count or not isinstance(return_code, int) or not 200 <= return_code < 300:
            return []
        submitted_by_name: dict[object, str] = {}
        for name in submitted_names:
            identity = self._identity_key(name)
            if identity in submitted_by_name:
                raise RuntimeError(f"Submitted security resource names are not unique under model identity rules: '{name}'.")
            submitted_by_name[identity] = name
        outcomes = self._multistatus_outcomes(response_keys)
        unexpected = sorted(set(outcomes).difference(submitted_by_name))
        missing = sorted(set(submitted_by_name).difference(outcomes))
        if unexpected or missing:
            details = []
            if unexpected:
                details.append(f"unexpected resource(s): {unexpected}")
            if missing:
                details.append(f"missing resource(s): {missing}")
            raise RuntimeError(f"Malformed HTTP {return_code} security response: {'; '.join(details)}.")
        return [name for name in submitted_names if outcomes[self._identity_key(name)]]

    def _latest_response_has_itemized_envelope(self, response_keys: Sequence[str], previous_response_count: int) -> bool:
        """Return whether a fresh 2xx response contains an expected itemized envelope."""
        return_code = self.rest_send.return_code
        if self.rest_send.response_count <= previous_response_count or not isinstance(return_code, int) or not 200 <= return_code < 300:
            return False
        data = self.rest_send.response_current.get("DATA")
        return isinstance(data, dict) and any(response_key in data for response_key in dict.fromkeys(response_keys))

    def _accepted_models_from_latest_response(
        self,
        model_instances: Sequence[ModelType],
        response_keys: Sequence[str],
        previous_response_count: int,
    ) -> list[ModelType]:
        """Match submitted models to exact-success members of a fresh 207 response."""
        submitted_names = [str(model.get_identifier_value()) for model in model_instances]
        accepted_names = {
            self._identity_key(name) for name in self._accepted_names_from_latest_response(submitted_names, response_keys, previous_response_count)
        }
        return [model for model in model_instances if model.get_identifier_value() in accepted_names]

    def _current_model(self, model_instance: ModelType) -> ModelType | None:
        """Return the cached current model for `model_instance`."""
        return self._existing_by_identifier.get(model_instance.get_identifier_value())

    def _resource_names(self, model_instances: list[ModelType]) -> list[str]:
        """Return resource names for action payloads."""
        return [str(model_instance.get_identifier_value()) for model_instance in model_instances]

    @staticmethod
    def _crud_payload(model_instance: ModelType) -> dict[str, Any]:
        """Return a CRUD payload without action-owned attachment intent."""
        payload = model_instance.to_payload()
        payload.pop("attach", None)
        return payload

    def _queue_attach_or_detach(
        self,
        model_instance: ModelType,
        current: ModelType | None = None,
        force: bool = False,
    ) -> None:
        """Queue an attach transition that differs from intent or must follow CRUD.

        ND resets an explicitly detached security group to attached when a PUT
        updates the resource. ``force`` retains the requested detach action for
        an otherwise already-detached resource when the same run will issue that
        PUT.
        """
        if self.action_payload_key is None:
            return
        attach_is_explicit = "attach" in model_instance.model_fields_set
        attach = getattr(model_instance, "attach", None)
        if not attach_is_explicit:
            state = self.rest_send.params.get("state")
            if current is None or state not in ("replaced", "overridden"):
                return
            # Both active API schemas default attach to true.  Replaced and
            # overridden therefore reset an omitted false value through the
            # action endpoint, because CRUD payloads deliberately omit attach.
            attach = True
        if not force and current is not None and getattr(current, "attach", None) is attach:
            return
        name = str(model_instance.get_identifier_value())
        if attach is True and name not in self._pending_attach:
            self._pending_attach.append(name)
        elif attach is False and name not in self._pending_detach:
            self._pending_detach.append(name)

    def _request_action(self, endpoint_class: Type[NDEndpointBaseModel], payload_names: list[str]) -> ResponseType:
        """Send an attach or detach action request."""
        if self.action_payload_key is None:
            raise AssertionError("action_payload_key is required for security actions")
        api_endpoint = self._configure_endpoint(endpoint_class())
        payload = {self.action_payload_key: payload_names}
        return self._request(
            path=api_endpoint.path,
            verb=api_endpoint.verb,
            data=payload,
            operation_type=OperationType.UPDATE,
        )

    def _refresh_attachment_states(self, names: Sequence[str]) -> dict[object, bool]:
        """Best-effort read of current action state for queued resources.

        CRUD deliberately omits ``attach``, but a controller release may still
        apply a schema default.  Reading immediately before an action lets an
        already-satisfied resource remain idempotent.
        A read failure falls back to the action request and its per-item result.
        """
        states: dict[object, bool] = {}
        for name in names:
            saved_results = self.results
            try:
                # This read is an idempotency probe.  If it fails, the action
                # endpoint remains authoritative, so do not register a
                # best-effort read failure as a failed module operation.
                self.results = None
                probe = self.model_class.model_construct(name=name)
                item = self.query_one(probe)
                if not item:
                    continue
                current = self.model_class.from_response(item)
                identity = current.get_identifier_value()
                if identity != self._identity_key(name):
                    continue
                attach = getattr(current, "attach", None)
                if not isinstance(attach, bool):
                    continue
                self._existing_by_identifier[identity] = current
                states[identity] = attach
            except Exception:  # pylint: disable=broad-except
                continue
            finally:
                self.results = saved_results
        return states

    def flush_pending_actions(self, check_mode: bool = False, accepted_only: bool = False) -> dict[str, ResponseType]:
        """Drain both action queues while retaining per-action failures for aggregation.

        When resource mutation failed partway through, ``accepted_only`` limits
        actions to resources whose create/update was confirmed by the controller.
        Mixed 207 responses dequeue exact-success members and preserve the raw
        response alongside the error so later config save/deploy can still run.
        """
        results: dict[str, ResponseType] = {}
        self._pending_action_errors = []
        if self.action_payload_key is None:
            return results
        eligible_identifiers = set(self._accepted_upserts) if accepted_only else None
        for action, endpoint, pending in (
            ("attach", self.attach_endpoint, self._pending_attach),
            ("detach", self.detach_endpoint, self._pending_detach),
        ):
            names = [name for name in pending if eligible_identifiers is None or self._identity_key(name) in eligible_identifiers]
            if not names or endpoint is None:
                continue
            if check_mode:
                results[action] = {"planned": True, self.action_payload_key: names}
                for name in names:
                    if name in pending:
                        pending.remove(name)
                continue

            desired_state = action == "attach"
            refreshed_states = self._refresh_attachment_states(names)
            already_satisfied = [name for name in names if refreshed_states.get(self._identity_key(name)) is desired_state]
            for name in already_satisfied:
                self._accepted_action_states[self._identity_key(name)] = desired_state
                if name in pending:
                    pending.remove(name)
            names = [name for name in names if name not in already_satisfied]
            if not names:
                results[action] = {"already_satisfied": already_satisfied}
                continue

            previous_response_count = self.rest_send.response_count
            accepted: list[str] = list(already_satisfied)
            try:
                action_result = self._request_action(endpoint, names)
                results[action] = {"already_satisfied": already_satisfied, "response": action_result} if already_satisfied else action_result
                response_keys = [self.action_response_key] if self.action_response_key else []
                if self.rest_send.response_count > previous_response_count and (
                    self.rest_send.return_code == 207 or self._latest_response_has_itemized_envelope(response_keys, previous_response_count)
                ):
                    request_accepted = self._accepted_names_from_latest_response(names, response_keys, previous_response_count)
                    accepted.extend(request_accepted)
                    rejected = [name for name in names if name not in request_accepted]
                    if rejected:
                        raise RuntimeError(f"HTTP {self.rest_send.return_code} reported failed {action} outcome(s) for {rejected}.")
                else:
                    accepted.extend(names)
            except Exception as e:  # pylint: disable=broad-except
                response_keys = [self.action_response_key] if self.action_response_key else []
                recovery_error = None
                try:
                    request_accepted = self._accepted_names_from_latest_response(names, response_keys, previous_response_count)
                except Exception as parse_error:  # pylint: disable=broad-except
                    request_accepted = []
                    recovery_error = parse_error
                accepted = list(dict.fromkeys((*already_satisfied, *request_accepted)))
                response_data = self.rest_send.response_current.get("DATA") if self.rest_send.response_count > previous_response_count else None
                error_detail = str(e)
                if recovery_error is not None and str(recovery_error) != error_detail:
                    error_detail += f" Partial-response validation failed: {recovery_error}"
                rejected = [name for name in names if name not in request_accepted]
                results[action] = {
                    "failed": bool(rejected),
                    "error": error_detail,
                    "accepted": accepted,
                    "already_satisfied": already_satisfied,
                    "response": (response_data if isinstance(response_data, dict) else {}),
                }
                if rejected:
                    self._pending_action_errors.append(
                        f"Security {action} failed for {rejected}: {error_detail}"
                        + (f" The controller accepted {accepted} from the same request or a confirming read." if accepted else "")
                    )

            for name in accepted:
                self._accepted_action_states[self._identity_key(name)] = desired_state
            for name in accepted:
                if name in pending:
                    pending.remove(name)
        return results

    def _validate_required_payload_fields(self, model_instance: ModelType, creating: bool = False) -> None:
        """Validate create/update fields that the delete argspec leaves optional."""
        del creating
        if hasattr(model_instance, "validate_required_payload_fields"):
            model_instance.validate_required_payload_fields()

    def _validate_immutable_update(self, model_instance: ModelType, current: ModelType | None = None) -> None:
        """Reject immutable association changes using the cached inventory."""
        if not self.immutable_update_fields:
            return
        current = current or self._current_model(model_instance)
        if current is None:
            return
        changed: list[str] = []
        for field_name in self.immutable_update_fields:
            current_value = getattr(current, field_name, None)
            proposed_value = getattr(model_instance, field_name, None)
            if field_name in self.optional_derived_immutable_fields and proposed_value is None:
                continue
            if field_name in self.case_insensitive_immutable_fields and isinstance(current_value, str) and isinstance(proposed_value, str):
                values_differ = current_value.casefold() != proposed_value.casefold()
            else:
                values_differ = current_value != proposed_value
            if values_differ:
                changed.append(field_name)
        if changed:
            raise RuntimeError(f"{model_instance.get_identifier_value()}: immutable security resource field(s) changed: {', '.join(changed)}")

    def preflight_create(self, model_instances: Sequence[ModelType]) -> None:
        """Validate new resources and plan explicit attach actions in check mode too."""
        for model_instance in model_instances:
            self._validate_required_payload_fields(model_instance, creating=True)
            self._queue_attach_or_detach(model_instance)

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """Validate final update payloads and plan attach transitions from cache."""
        state = self.rest_send.params.get("state")
        for proposed in model_instances:
            current = self._current_model(proposed)
            if current is None:
                continue
            candidate = proposed
            if state == "merged":
                candidate = current.model_copy(deep=True)
                candidate.merge(proposed)
            self._validate_required_payload_fields(candidate)
            self._validate_immutable_update(candidate, current=current)
            will_update = not current.get_diff(proposed, exclude_unset=state == "merged")
            # A merged config that omits ``attach`` preserves the current
            # intent.  Use the merged candidate for action planning so a PUT
            # that changes some other field cannot silently reattach a
            # currently detached resource.
            action_candidate = candidate if state == "merged" else proposed
            force_detach_after_update = will_update and "attach" in action_candidate.model_fields_set and getattr(action_candidate, "attach", None) is False
            self._queue_attach_or_detach(action_candidate, current=current, force=force_detach_after_update)

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """Create one resource through the bulk create API."""
        return self.create_bulk([model_instance])

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """Replace one resource by name."""
        try:
            self._validate_required_payload_fields(model_instance)
            self._validate_immutable_update(model_instance)
            api_endpoint = self._configure_endpoint(self.update_endpoint())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=self._crud_payload(model_instance),
                operation_type=OperationType.UPDATE,
            )
            self._record_upserts([model_instance])
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """Delete one resource by name."""
        try:
            api_endpoint = self._configure_endpoint(self.delete_endpoint())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                operation_type=OperationType.DELETE,
            )
            self._record_deletes([model_instance])
            return result
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """Query one resource by name and normalize generated displayName."""
        try:
            api_endpoint = self._configure_endpoint(self.query_one_endpoint())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            if not result and self.rest_send.return_code == 404:
                return {}
            if not isinstance(result, dict) or not result:
                raise RuntimeError("Security resource response row must be a non-empty object.")
            normalized = self._normalize_response_item(result)
            current = self.model_class.from_response(normalized)
            if current.get_identifier_value() != model_instance.get_identifier_value():
                raise RuntimeError(
                    f"Security resource response identity {current.get_identifier_value()!r} does not match requested identity "
                    f"{model_instance.get_identifier_value()!r}."
                )
            return normalized
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """Query all resources, following response pagination metadata when present."""
        del model_instance, kwargs
        try:
            self.validate_prerequisites()
            self._existing_by_identifier.clear()
            items: list[dict[str, Any]] = []
            offset = 0
            seen_pages: set[str] = set()
            seen_identifiers: set[object] = set()
            known_remaining: int | None = None
            known_total: int | None = None
            for _page_number in range(1, self.max_pages + 1):
                api_endpoint = self._configure_endpoint(self.query_all_endpoint())
                api_endpoint.endpoint_params.offset = offset
                api_endpoint.endpoint_params.max = self.page_size
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                if not isinstance(result, dict):
                    raise RuntimeError("Security resource page must be an object.")
                if not result and self.rest_send.return_code == 404:
                    if items:
                        raise RuntimeError("Security resource pagination returned 404 after earlier pages were collected.")
                    return items
                remaining = self._remaining_count(result)
                total = self._total_count(result)
                next_link = self._next_page_link(result)
                if self.list_response_key not in result:
                    # ND omits the resource envelope for an empty inventory and
                    # returns only ``meta.counts``.  Accept that exact terminal
                    # shape while continuing to reject ambiguous or internally
                    # inconsistent pages.
                    if not items and total == 0 and remaining == 0 and not next_link:
                        return items
                    raise RuntimeError(f"Security resource page is missing the '{self.list_response_key}' envelope.")
                raw_page = result[self.list_response_key]
                if not isinstance(raw_page, list):
                    raise RuntimeError(f"Security resource page field '{self.list_response_key}' must be a list.")
                page_items: list[dict[str, Any]] = []
                for index, item in enumerate(raw_page):
                    if not isinstance(item, dict):
                        raise RuntimeError(f"Security resource page row '{self.list_response_key}[{index}]' must be an object.")
                    page_items.append(self._normalize_response_item(item))
                raw_page_count = len(raw_page)
                if total is not None:
                    if known_total is not None and total != known_total:
                        raise RuntimeError(f"Security resource pagination total changed from {known_total} to {total}.")
                    known_total = total
                if remaining is not None:
                    if known_remaining is not None and remaining > known_remaining:
                        raise RuntimeError(f"Security resource pagination remaining count increased from {known_remaining} to {remaining}.")
                    known_remaining = remaining
                elif known_remaining is not None:
                    known_remaining = max(known_remaining - raw_page_count, 0)
                if not page_items:
                    counts_report_more = (known_remaining is not None and known_remaining > 0) or (
                        known_total is not None and len(seen_identifiers) < known_total
                    )
                    if counts_report_more or (known_remaining is None and known_total is None and bool(next_link)):
                        raise RuntimeError("Pagination metadata reports more security resources, but the next page is empty.")
                    return items

                signature = json.dumps(page_items, sort_keys=True, default=str)
                if signature in seen_pages:
                    raise RuntimeError("Security resource pagination returned the same page twice.")
                seen_pages.add(signature)

                unique_page_items = self._unique_page_items(page_items, seen_identifiers)
                items.extend(unique_page_items)
                offset += raw_page_count

                if known_remaining is not None and known_total is not None:
                    if known_remaining == 0 and len(seen_identifiers) < known_total:
                        raise RuntimeError("Security resource pagination counts are inconsistent: remaining is zero before total is collected.")
                    if known_remaining > 0 and len(seen_identifiers) >= known_total:
                        raise RuntimeError("Security resource pagination counts are inconsistent: remaining is positive after total is collected.")

                if known_remaining is not None:
                    counts_report_more: bool | None = known_remaining > 0
                elif known_total is not None:
                    counts_report_more = len(seen_identifiers) < known_total
                else:
                    counts_report_more = None

                has_more = counts_report_more if counts_report_more is not None else bool(next_link)
                if not unique_page_items and has_more:
                    raise RuntimeError("Pagination metadata reports more security resources, but the next page adds no new resource identities.")
                if has_more:
                    continue
                if counts_report_more is not None or next_link is not None:
                    return items
                if raw_page_count < self.page_size:
                    return items
            raise RuntimeError(f"Security resource pagination exceeded the maximum of {self.max_pages} pages.")
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """Create multiple resources in one API request."""
        previous_response_count = self.rest_send.response_count
        try:
            for model_instance in model_instances:
                self._validate_required_payload_fields(model_instance, creating=True)
            api_endpoint = self._configure_endpoint(self.create_bulk_endpoint())
            payload = {self.create_payload_key: [self._crud_payload(model_instance) for model_instance in model_instances]}
            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=payload,
                operation_type=OperationType.CREATE,
            )
            response_keys = [self.create_response_key]
            if self.rest_send.response_count > previous_response_count and (
                self.rest_send.return_code == 207 or self._latest_response_has_itemized_envelope(response_keys, previous_response_count)
            ):
                accepted = self._accepted_models_from_latest_response(model_instances, response_keys, previous_response_count)
                if len(accepted) != len(model_instances):
                    accepted_identifiers = {model.get_identifier_value() for model in accepted}
                    rejected_names = [
                        str(model.get_identifier_value()) for model in model_instances if model.get_identifier_value() not in accepted_identifiers
                    ]
                    raise RuntimeError(f"HTTP {self.rest_send.return_code} reported failed create outcome(s) for {rejected_names}.")
        except Exception as e:
            try:
                accepted = self._accepted_models_from_latest_response(model_instances, [self.create_response_key], previous_response_count)
            except Exception as recovery_error:
                raise RuntimeError(f"Bulk create failed: {e}. Partial-response validation failed: {recovery_error}") from e
            response_data = self.rest_send.response_current.get("DATA") if self.rest_send.response_count > previous_response_count else None
            self._apply_create_response_fields(accepted, response_data)
            self._record_upserts(accepted)
            accepted_names = [str(model.get_identifier_value()) for model in accepted]
            accepted_identifiers = {model.get_identifier_value() for model in accepted}
            rejected_names = [str(model.get_identifier_value()) for model in model_instances if model.get_identifier_value() not in accepted_identifiers]
            detail = f" The controller accepted {accepted_names} from the same request." if accepted_names else ""
            raise RuntimeError(f"Bulk create failed for {rejected_names}: {e}.{detail}") from e
        self._apply_create_response_fields(model_instances, result)
        self._record_upserts(model_instances)
        return result

    def delete_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """Delete multiple resources in one action request."""
        previous_response_count = self.rest_send.response_count
        try:
            api_endpoint = self._configure_endpoint(self.delete_bulk_endpoint())
            payload = {self.remove_payload_key: self._resource_names(model_instances)}
            result = self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data=payload,
                operation_type=OperationType.DELETE,
            )
            response_keys = tuple(dict.fromkeys((self.remove_response_key, self.list_response_key)))
            if self.rest_send.response_count > previous_response_count and (
                self.rest_send.return_code == 207 or self._latest_response_has_itemized_envelope(response_keys, previous_response_count)
            ):
                accepted = self._accepted_models_from_latest_response(model_instances, response_keys, previous_response_count)
                if len(accepted) != len(model_instances):
                    accepted_identifiers = {model.get_identifier_value() for model in accepted}
                    rejected_names = [
                        str(model.get_identifier_value()) for model in model_instances if model.get_identifier_value() not in accepted_identifiers
                    ]
                    raise RuntimeError(f"HTTP {self.rest_send.return_code} reported failed delete outcome(s) for {rejected_names}.")
        except Exception as e:
            response_keys = tuple(dict.fromkeys((self.remove_response_key, self.list_response_key)))
            try:
                accepted = self._accepted_models_from_latest_response(model_instances, response_keys, previous_response_count)
            except Exception as recovery_error:
                raise RuntimeError(f"Bulk delete failed: {e}. Partial-response validation failed: {recovery_error}") from e
            self._record_deletes(accepted)
            accepted_names = [str(model.get_identifier_value()) for model in accepted]
            accepted_identifiers = {model.get_identifier_value() for model in accepted}
            rejected_names = [str(model.get_identifier_value()) for model in model_instances if model.get_identifier_value() not in accepted_identifiers]
            detail = f" The controller accepted {accepted_names} from the same request." if accepted_names else ""
            raise RuntimeError(f"Bulk delete failed for {rejected_names}: {e}.{detail}") from e
        self._record_deletes(model_instances)
        return result


class SecurityProtocolDefinitionOrchestrator(ManageSecurityResourceOrchestrator[SecurityProtocolDefinitionModel]):
    """Orchestrator for security protocol definitions."""

    model_class: ClassVar[Type[NDBaseModel]] = SecurityProtocolDefinitionModel
    list_response_key: ClassVar[str] = "securityProtocolDefinitions"
    create_payload_key: ClassVar[str] = "securityProtocolDefinitions"
    create_response_key: ClassVar[str] = "securityProtocolDefinitions"
    remove_payload_key: ClassVar[str] = "securityProtocolDefinitionNames"
    remove_response_key: ClassVar[str] = "protocols"
    resource_name_label: ClassVar[str] = "protocolDefinitionName"

    create_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityProtocolDefinitionsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityProtocolDefinitionsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityProtocolDefinitionsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityProtocolDefinitionsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityProtocolDefinitionsListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityProtocolDefinitionsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityProtocolDefinitionsRemove


class SecurityContractOrchestrator(ManageSecurityResourceOrchestrator[SecurityContractModel]):
    """Orchestrator for security contracts."""

    model_class: ClassVar[Type[NDBaseModel]] = SecurityContractModel
    list_response_key: ClassVar[str] = "securityContracts"
    create_payload_key: ClassVar[str] = "securityContracts"
    create_response_key: ClassVar[str] = "securityContracts"
    remove_payload_key: ClassVar[str] = "securityContractNames"
    remove_response_key: ClassVar[str] = "securityContracts"
    resource_name_label: ClassVar[str] = "contractName"

    create_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityContractsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityContractsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityContractsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityContractsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityContractsListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityContractsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityContractsRemove

    def _uses_nd_42_direction_contract(self) -> bool:
        """Return whether the controller uses the live-verified ND 4.2 contract."""
        version = self.rest_send.controller_version
        if not version:
            return False
        match = re.match(r"^\s*(\d+)\.(\d+)", str(version))
        return match is not None and (int(match.group(1)), int(match.group(2))) == (
            4,
            2,
        )

    def _scope_default_direction(self, model_instance: SecurityContractModel) -> str:
        """Return the release- and tenant-specific contract direction default."""
        if model_instance.tenant_name is None and self._uses_nd_42_direction_contract():
            return "custom"
        return "bidirectional"

    def _materialize_scope_default_direction(self, model_instance: SecurityContractModel) -> None:
        """Materialize the release/scope default used by create and replacement."""
        if "direction" not in model_instance.model_fields_set:
            model_instance.direction = self._scope_default_direction(model_instance)

    def _validate_direction_scope(
        self,
        model_instance: SecurityContractModel,
        current: SecurityContractModel | None = None,
    ) -> None:
        """Reject release/scope combinations while preserving legacy rows."""
        direction = model_instance.direction
        if direction is None:
            return

        if model_instance.tenant_name is None:
            allowed_directions = {"custom"} if self._uses_nd_42_direction_contract() else {"bidirectional", "unidirectional", "custom"}
        else:
            allowed_directions = {"bidirectional", "unidirectional"}
        if direction in allowed_directions:
            return

        # Responses may contain a direction/scope combination accepted by an
        # earlier controller or documented schema.  Permit an exact replay of
        # that value so a no-op or metadata-only update remains possible.
        if current is not None and current.direction == direction:
            return

        if model_instance.tenant_name is None:
            raise ValueError(
                f"{model_instance.api_name}: direction='{direction}' is unsupported "
                "for a contract in the default tenant on ND 4.2; use "
                "direction='custom'"
            )
        raise ValueError(
            f"{model_instance.api_name}: direction='custom' is unsupported for a "
            "tenant-scoped contract; use direction='bidirectional' or "
            "direction='unidirectional'"
        )

    def preflight_create(self, model_instances: Sequence[SecurityContractModel]) -> None:
        """Apply and validate the live scope-specific create direction."""
        for model_instance in model_instances:
            self._materialize_scope_default_direction(model_instance)
            self._validate_direction_scope(model_instance)
        super().preflight_create(model_instances)

    def preflight(self, model_instances: Sequence[SecurityContractModel]) -> None:
        """Apply replacement defaults and validate direction against tenant scope."""
        state = self.rest_send.params.get("state")
        for proposed in model_instances:
            current = self._current_model(proposed)
            if current is None:
                continue
            if state in ("replaced", "overridden"):
                self._materialize_scope_default_direction(proposed)
            candidate = proposed
            if state == "merged":
                candidate = current.model_copy(deep=True)
                candidate.merge(proposed)
            self._validate_direction_scope(candidate, current=current)
        super().preflight(model_instances)


class SecurityGroupOrchestrator(ManageSecurityResourceOrchestrator[SecurityGroupModel]):
    """Orchestrator for security groups."""

    model_class: ClassVar[Type[NDBaseModel]] = SecurityGroupModel
    list_response_key: ClassVar[str] = "securityGroups"
    create_payload_key: ClassVar[str] = "securityGroups"
    create_response_key: ClassVar[str] = "securityGroups"
    remove_payload_key: ClassVar[str] = "securityGroupNames"
    remove_response_key: ClassVar[str] = "securityGroups"
    resource_name_label: ClassVar[str] = "securityGroupName"
    action_payload_key: ClassVar[str | None] = "securityGroupNames"
    action_response_key: ClassVar[str | None] = "securityGroups"
    immutable_update_fields: ClassVar[tuple[str, ...]] = ("id",)

    create_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsRemove
    attach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsAttach
    detach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsDetach

    def _apply_create_response_fields(self, model_instances: Sequence[SecurityGroupModel], response_data: Any) -> None:
        """Copy ND 4.3 controller-generated group IDs into accepted models."""
        if not isinstance(response_data, dict):
            return
        response_items = response_data.get(self.create_response_key)
        if not isinstance(response_items, list):
            return
        generated_ids: dict[object, int] = {}
        for item in response_items:
            if not isinstance(item, dict):
                continue
            name = self._response_item_name(item)
            generated_id = item.get("id")
            if name is None or isinstance(generated_id, bool):
                continue
            try:
                generated_ids[self._identity_key(name)] = int(generated_id)
            except (TypeError, ValueError):
                continue
        for model_instance in model_instances:
            if model_instance.id is not None:
                continue
            generated_id = generated_ids.get(model_instance.get_identifier_value())
            if generated_id is not None:
                model_instance.id = generated_id

    @staticmethod
    def _parse_major_minor(version: str | None) -> tuple[int, int] | None:
        """Return the controller major/minor version, or None when unavailable."""
        if not version:
            return None
        match = re.match(r"^\s*(\d+)\.(\d+)", str(version))
        if match is None:
            return None
        return (int(match.group(1)), int(match.group(2)))

    def _validate_required_payload_fields(self, model_instance: SecurityGroupModel, creating: bool = False) -> None:
        """Require an explicit group ID for ND 4.2 creates and every update."""
        version = self._parse_major_minor(self.rest_send.controller_version)
        require_id = not (creating and version is not None and version >= (4, 3))
        model_instance.validate_required_payload_fields(require_id=require_id)

    def preflight(self, model_instances: Sequence[SecurityGroupModel]) -> None:
        """Preserve controller-generated ND 4.3 IDs across replacement-style updates."""
        version = self._parse_major_minor(self.rest_send.controller_version)
        state = self.rest_send.params.get("state")
        if version is not None and version >= (4, 3) and state in ("replaced", "overridden"):
            for proposed in model_instances:
                current = self._current_model(proposed)
                if current is None or "id" in proposed.model_fields_set or proposed.id is not None:
                    continue
                # ND 4.3 can allocate this immutable value at create time. PUT
                # still requires it, so carry forward the cached response value
                # for both diffing and any mutable replacement update.
                proposed.id = current.id
        super().preflight(model_instances)


class SecurityAssociationOrchestrator(ManageSecurityResourceOrchestrator[SecurityAssociationModel]):
    """Orchestrator for security associations."""

    model_class: ClassVar[Type[NDBaseModel]] = SecurityAssociationModel
    list_response_key: ClassVar[str] = "securityAssociations"
    create_payload_key: ClassVar[str] = "securityAssociations"
    create_response_key: ClassVar[str] = "securityAssociations"
    remove_payload_key: ClassVar[str] = "securityAssociationNames"
    remove_response_key: ClassVar[str] = "securityAssociations"
    resource_name_label: ClassVar[str] = "securityAssociationName"
    action_payload_key: ClassVar[str | None] = "securityAssociationNames"
    action_response_key: ClassVar[str | None] = "securityAssociations"
    immutable_update_fields: ClassVar[tuple[str, ...]] = (
        "contract_name",
        "src_security_group_name",
        "src_vrf_name",
        "dst_security_group_name",
        "dst_vrf_name",
    )
    case_insensitive_immutable_fields: ClassVar[tuple[str, ...]] = ("contract_name",)
    optional_derived_immutable_fields: ClassVar[tuple[str, ...]] = (
        "src_vrf_name",
        "dst_vrf_name",
    )

    create_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsRemove
    attach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsAttach
    detach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsDetach
