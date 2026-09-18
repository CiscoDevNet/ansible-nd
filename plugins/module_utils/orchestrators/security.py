# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Orchestrators for Nexus Dashboard security and segmentation resources."""

from __future__ import annotations

from typing import Any, ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
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
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import SecurityAssociationModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import ConfigActionsModel, validate_config_actions_dict
from ansible_collections.cisco.nd.plugins.module_utils.models.security.contracts import SecurityContractModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import SecurityGroupModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.protocol_definitions import SecurityProtocolDefinitionModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import ModelType, NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class ManageSecurityResourceOrchestrator(NDBaseOrchestrator[ModelType]):
    """Shared CRUD/action behavior for security and segmentation resources."""

    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    list_response_key: ClassVar[str]
    create_payload_key: ClassVar[str]
    create_response_key: ClassVar[str]
    remove_payload_key: ClassVar[str]
    remove_response_key: ClassVar[str]
    resource_name_label: ClassVar[str] = "name"
    page_size: ClassVar[int] = 1000
    immutable_update_fields: ClassVar[tuple[str, ...]] = ()

    attach_endpoint: Type[NDEndpointBaseModel] | None = None
    detach_endpoint: Type[NDEndpointBaseModel] | None = None
    action_payload_key: ClassVar[str | None] = None
    action_response_key: ClassVar[str | None] = None

    _fabric_context: FabricContext | None = None

    def model_post_init(self, __context) -> None:
        """Initialize per-instance pending action queues."""
        self._pending_attach: list[str] = []
        self._pending_detach: list[str] = []

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
            self._fabric_context = FabricContext(rest_send=self.rest_send, fabric_name=self.fabric_name)
        return self._fabric_context

    def validate_prerequisites(self) -> None:
        """Validate that the target fabric can accept mutations."""
        self.fabric_context.validate_for_mutation()

    def _configure_endpoint(self, api_endpoint: NDEndpointBaseModel) -> NDEndpointBaseModel:
        """Set fabric and cluster context on an endpoint before path generation."""
        api_endpoint.fabric_name = self.fabric_name
        endpoint_params = getattr(api_endpoint, "endpoint_params", None)
        if endpoint_params is not None and hasattr(endpoint_params, "cluster_name"):
            endpoint_params.cluster_name = self.cluster_name
        return api_endpoint

    def _resource_names(self, model_instances: list[ModelType]) -> list[str]:
        """Return resource names for action payloads."""
        return [str(model_instance.get_identifier_value()) for model_instance in model_instances]

    def _raise_on_207_errors(self, result: Any, response_key: str) -> None:
        """Raise when a 207 response reports failed, warning, or unknown per-item status."""
        if not isinstance(result, dict):
            return
        items = result.get(response_key)
        if not isinstance(items, list):
            return
        failures = []
        for item in items:
            if not isinstance(item, dict):
                continue
            status = item.get("status")
            if status != "success":
                name = item.get("name") or item.get(self.resource_name_label) or item.get("resourceName") or "<unknown>"
                message = item.get("message") or item.get("warningMessage") or item.get("description") or item.get("error") or "no message"
                failures.append(f"{name}: {status or 'missing status'} - {message}")
        if failures:
            raise RuntimeError(f"Per-item failures in {response_key} response: {', '.join(failures)}")

    def _queue_attach_or_detach(self, model_instance: ModelType) -> None:
        """Queue attach or detach actions when the model exposes an explicit attach value."""
        if self.action_payload_key is None:
            return
        attach = getattr(model_instance, "attach", None)
        if attach is True:
            name = str(model_instance.get_identifier_value())
            if name not in self._pending_attach:
                self._pending_attach.append(name)
        elif attach is False:
            name = str(model_instance.get_identifier_value())
            if name not in self._pending_detach:
                self._pending_detach.append(name)

    def _request_action(self, endpoint_class: Type[NDEndpointBaseModel], payload_names: list[str]) -> ResponseType:
        """Send an attach/detach/remove action request."""
        api_endpoint = self._configure_endpoint(endpoint_class())
        payload = {self.action_payload_key: payload_names}
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.UPDATE)
        if self.action_response_key is not None:
            self._raise_on_207_errors(result, self.action_response_key)
        return result

    def flush_pending_actions(self) -> dict[str, ResponseType]:
        """Execute pending attach and detach actions after state reconciliation."""
        results: dict[str, ResponseType] = {}
        if self.action_payload_key is None:
            return results
        if self._pending_attach and self.attach_endpoint is not None:
            results["attach"] = self._request_action(self.attach_endpoint, self._pending_attach)
            self._pending_attach = []
        if self._pending_detach and self.detach_endpoint is not None:
            results["detach"] = self._request_action(self.detach_endpoint, self._pending_detach)
            self._pending_detach = []
        return results

    def _validate_required_payload_fields(self, model_instance: ModelType) -> None:
        """Validate create/update fields that the delete argspec intentionally leaves optional."""
        if hasattr(model_instance, "validate_required_payload_fields"):
            model_instance.validate_required_payload_fields()

    def _validate_immutable_update(self, model_instance: ModelType) -> None:
        """Reject updates to association fields that the product treats as immutable."""
        if not self.immutable_update_fields:
            return
        current_raw = self.query_one(model_instance)
        if not isinstance(current_raw, dict) or not current_raw:
            return
        current = self.model_class.from_response(current_raw)
        changed = []
        for field_name in self.immutable_update_fields:
            if getattr(current, field_name, None) != getattr(model_instance, field_name, None):
                changed.append(field_name)
        if changed:
            raise RuntimeError(f"{model_instance.get_identifier_value()}: immutable association field(s) changed: {', '.join(changed)}")

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
                data=model_instance.to_payload(),
                operation_type=OperationType.UPDATE,
            )
            self._queue_attach_or_detach(model_instance)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """Delete one resource by name."""
        try:
            api_endpoint = self._configure_endpoint(self.delete_endpoint())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, operation_type=OperationType.DELETE)
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """Query one resource by name."""
        try:
            api_endpoint = self._configure_endpoint(self.query_one_endpoint())
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """Query all resources, following offset/max pagination."""
        try:
            self.validate_prerequisites()
            items: list[dict] = []
            offset = 0
            while True:
                api_endpoint = self._configure_endpoint(self.query_all_endpoint())
                api_endpoint.endpoint_params.offset = offset
                api_endpoint.endpoint_params.max = self.page_size
                result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
                if not isinstance(result, dict):
                    return items
                page_items = result.get(self.list_response_key) or []
                if not isinstance(page_items, list):
                    return items
                items.extend(page_items)
                if len(page_items) < self.page_size:
                    return items
                offset += len(page_items)
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """Create multiple resources in one API request."""
        try:
            for model_instance in model_instances:
                self._validate_required_payload_fields(model_instance)
            api_endpoint = self._configure_endpoint(self.create_bulk_endpoint())
            payload = {self.create_payload_key: [model_instance.to_payload() for model_instance in model_instances]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.CREATE)
            self._raise_on_207_errors(result, self.create_response_key)
            for model_instance in model_instances:
                self._queue_attach_or_detach(model_instance)
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def delete_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """Delete multiple resources in one action request."""
        try:
            api_endpoint = self._configure_endpoint(self.delete_bulk_endpoint())
            payload = {self.remove_payload_key: self._resource_names(model_instances)}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=OperationType.DELETE)
            self._raise_on_207_errors(result, self.remove_response_key)
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk delete failed: {e}") from e

    def apply_config_actions(self, changed: bool) -> dict[str, Any]:
        """Run fabric save/deploy actions after mutations when configured."""
        config_actions = validate_config_actions_dict(self.rest_send.params.get("config_actions"))
        result: dict[str, Any] = {"config_actions": config_actions.model_dump()}
        if not changed:
            result["skipped"] = "No resource changes were detected."
            return result
        if self.rest_send.params.get("check_mode"):
            result["planned"] = True
            return result
        if config_actions.save:
            result["save"] = self._run_config_save(config_actions)
        if config_actions.deploy:
            result["deploy"] = self._run_config_deploy(config_actions)
        return result

    def _run_config_save(self, config_actions: ConfigActionsModel) -> ResponseType:
        """Run fabric configSave."""
        api_endpoint = self._configure_endpoint(EpManageSecurityFabricConfigSave())
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, operation_type=OperationType.UPDATE)

    def _run_config_deploy(self, config_actions: ConfigActionsModel) -> ResponseType:
        """Run fabric deploy."""
        api_endpoint = self._configure_endpoint(EpManageSecurityFabricDeploy())
        api_endpoint.endpoint_params.incl_all_fabric_groups_switches = config_actions.type == "global"
        return self._request(path=api_endpoint.path, verb=api_endpoint.verb, operation_type=OperationType.UPDATE)


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

    create_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityGroupsListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsRemove
    attach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsAttach
    detach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityGroupsDetach


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

    create_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageSecurityAssociationsListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsPost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsRemove
    attach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsAttach
    detach_endpoint: Type[NDEndpointBaseModel] | None = EpManageSecurityAssociationsDetach

