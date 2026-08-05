# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Orchestrator for Nexus Dashboard Interface Groups."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from ipaddress import ip_address
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    PrivateAttr,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.template_validation import (
    validate_template_inputs,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_config_templates import (
    EpManageConfigTemplateGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_interface_groups import (
    EpManageFabricsInterfaceGroupsActionsRemovePost,
    EpManageFabricsInterfaceGroupsGet,
    EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete,
    EpManageFabricsInterfaceGroupsInterfaceGroupNameGet,
    EpManageFabricsInterfaceGroupsInterfaceGroupNamePut,
    EpManageFabricsInterfaceGroupsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_networks import (
    EpManageFabricsNetworksNetworkNameGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import (
    EpVpcPairGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDeploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupConfigModel,
    InterfaceGroupGatheredFilterModel,
    InterfaceGroupGatheredSwitchFilterModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.data_models import (
    InterfaceGroupsCreateRequestModel,
    InterfaceGroupsCreateResponseModel,
    InterfaceGroupsDeleteResponseModel,
    InterfaceGroupsListResponseModel,
    InterfaceGroupsRemoveRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.enums import (
    InterfaceGroupConfigActionType,
    InterfaceGroupType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)

_QUERY_PAGE_SIZE = 100
_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})
_CUSTOM_TEMPLATE_REQUIRED_TAG = "interface_edit_shared_policy"
_CUSTOM_TEMPLATE_CONTENT_TYPES = frozenset({"python", "pythoncli"})
_INTERFACE_POLICY_TYPES = frozenset(
    {
        InterfaceGroupType.ETHERNET_CUSTOM.value,
        InterfaceGroupType.ETHERNET_WITH_POLICY.value,
    }
)
_ANY_MEMBER_KIND_ORDER = ("ethernet", "port_channel", "vpc")


class ManageInterfaceGroupOrchestrator(NDBaseOrchestrator[InterfaceGroupConfigModel]):
    """Manage Interface Group CRUD, dependency validation, moves, and deploys."""

    model_class: ClassVar[type[NDBaseModel]] = InterfaceGroupConfigModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsInterfaceGroupsPost
    update_endpoint: type[NDEndpointBaseModel] = (
        EpManageFabricsInterfaceGroupsInterfaceGroupNamePut
    )
    delete_endpoint: type[NDEndpointBaseModel] = (
        EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete
    )
    query_one_endpoint: type[NDEndpointBaseModel] = (
        EpManageFabricsInterfaceGroupsInterfaceGroupNameGet
    )
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageFabricsInterfaceGroupsGet
    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageFabricsInterfaceGroupsPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = (
        EpManageFabricsInterfaceGroupsActionsRemovePost
    )

    _fabric_context: FabricContext | None = PrivateAttr(default=None)
    _existing_groups: dict[str, InterfaceGroupConfigModel] = PrivateAttr(
        default_factory=dict
    )
    _move_plan: dict[str, InterfaceGroupConfigModel] = PrivateAttr(default_factory=dict)
    _pending_interfaces: set[tuple[str, str]] = PrivateAttr(default_factory=set)
    _pending_switches: set[str] = PrivateAttr(default_factory=set)
    _custom_template_cache: dict[str, dict[str, Any] | None] = PrivateAttr(
        default_factory=dict
    )
    _vpc_peer_cache: dict[str, str | None] = PrivateAttr(default_factory=dict)
    _warnings: list[str] = PrivateAttr(default_factory=list)

    @property
    def fabric_name(self) -> str:
        """Return the target fabric name."""
        return self.rest_send.params.get("fabric_name")

    @property
    def fabric_context(self) -> FabricContext:
        """Return a cached fabric context."""
        if self._fabric_context is None:
            self._fabric_context = FabricContext(
                rest_send=self.rest_send, fabric_name=self.fabric_name
            )
        return self._fabric_context

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Return whether a switch identifier is an IPv4 or IPv6 address."""
        try:
            ip_address(value)
            return True
        except ValueError:
            return False

    def _resolve_switch_id(self, switch_id_or_ip: str) -> str:
        """Resolve a management IP to its switch serial number."""
        if not self._is_ip_address(switch_id_or_ip):
            return switch_id_or_ip
        try:
            return self.fabric_context.get_switch_id(switch_id_or_ip)
        except RuntimeError as exc:
            raise RuntimeError(
                f"Unable to resolve switch IP '{switch_id_or_ip}' to a serial number "
                f"in fabric '{self.fabric_name}'. Provide a valid switch serial number "
                "or management IP from the fabric inventory."
            ) from exc

    def _resolve_config_switch_identifiers(
        self, model_instances: Sequence[InterfaceGroupConfigModel]
    ) -> None:
        """Resolve switch management IPs in Interface Group membership in place."""
        for model_instance in model_instances:
            for switch_entry in model_instance.switch_interfaces or []:
                switch_entry.switch_id = self._resolve_switch_id(switch_entry.switch_id)

    @staticmethod
    def _collapse_switch_entries(
        model_instances: Sequence[InterfaceGroupConfigModel],
    ) -> None:
        """Merge switch entries that resolve to the same serial number.

        Pydantic merges repeated switch identifiers from the original input, but
        a serial number and its management IP are distinct until runtime
        resolution. Rebuild each supplied membership collection after resolution
        so request payloads contain one entry per switch and one copy of each
        member interface.
        """
        for model_instance in model_instances:
            if model_instance.switch_interfaces is None:
                continue
            by_switch: dict[str, set[str]] = {}
            for switch_entry in model_instance.switch_interfaces:
                by_switch.setdefault(switch_entry.switch_id, set()).update(
                    switch_entry.interface_names
                )
            model_instance.switch_interfaces = [
                {
                    "switch_id": switch_id,
                    "interface_names": sorted(interface_names),
                }
                for switch_id, interface_names in sorted(by_switch.items())
            ]

    def _resolve_gathered_switch_identifiers(
        self, filters: Sequence[InterfaceGroupGatheredFilterModel]
    ) -> None:
        """Resolve switch management IPs in gathered filters in place."""
        for filter_item in filters:
            for switch_entry in filter_item.switch_interfaces or []:
                switch_entry.switch_id = self._resolve_switch_id(switch_entry.switch_id)

    def _get_vpc_peer_id(self, switch_id: str) -> str | None:
        """Return and cache the peer serial for one switch in a vPC pair."""
        if switch_id in self._vpc_peer_cache:
            return self._vpc_peer_cache[switch_id]

        endpoint = EpVpcPairGet()
        endpoint.fabric_name = self.fabric_name
        endpoint.switch_id = switch_id
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        response_switch_id = (
            response.get("switchId") if isinstance(response, dict) else None
        )
        peer_switch_id = (
            response.get("peerSwitchId") if isinstance(response, dict) else None
        )
        if response_switch_id and peer_switch_id:
            self._vpc_peer_cache[response_switch_id] = peer_switch_id
            self._vpc_peer_cache[peer_switch_id] = response_switch_id
            resolved_peer = self._vpc_peer_cache.get(switch_id)
            if resolved_peer:
                return resolved_peer

        self._vpc_peer_cache[switch_id] = peer_switch_id
        if peer_switch_id:
            self._vpc_peer_cache.setdefault(peer_switch_id, switch_id)
        return peer_switch_id

    def _vpc_switch_ids_are_equivalent(
        self, first_switch_id: str, second_switch_id: str
    ) -> bool:
        """Return whether two serials identify peers in the same vPC pair."""
        if first_switch_id == second_switch_id:
            return True
        if self._get_vpc_peer_id(first_switch_id) == second_switch_id:
            return True
        return self._get_vpc_peer_id(second_switch_id) == first_switch_id

    def _validate_runtime_member_ownership(
        self, model_instances: Sequence[InterfaceGroupConfigModel]
    ) -> None:
        """Revalidate member ownership after runtime switch canonicalization.

        Raw Pydantic validation cannot know that an IP and serial identify the
        same switch or that a logical vPC member can be returned under either
        peer. Exact switch/member collisions are checked first. Only repeated
        vPC names on different switches require peer lookups, keeping the common
        path free of additional controller requests.
        """
        exact_owners: dict[tuple[str, str], str] = {}
        vpc_candidates: dict[str, list[tuple[str, str]]] = {}

        for model_instance in model_instances:
            group_name = model_instance.interface_group_name
            for switch_entry in model_instance.switch_interfaces or []:
                for interface_name in switch_entry.interface_names:
                    membership = (switch_entry.switch_id, interface_name)
                    existing_group = exact_owners.get(membership)
                    if existing_group and existing_group != group_name:
                        raise RuntimeError(
                            f"Interface '{interface_name}' on switch "
                            f"'{switch_entry.switch_id}' is present in both "
                            f"'{existing_group}' and '{group_name}'."
                        )
                    exact_owners[membership] = group_name
                    if InterfaceGroupValidators.interface_kind(interface_name) == "vpc":
                        vpc_candidates.setdefault(interface_name, []).append(
                            (switch_entry.switch_id, group_name)
                        )

        for interface_name, candidates in vpc_candidates.items():
            for index, (switch_id, group_name) in enumerate(candidates):
                for other_switch_id, other_group_name in candidates[:index]:
                    if group_name == other_group_name or switch_id == other_switch_id:
                        continue
                    if not self._vpc_switch_ids_are_equivalent(
                        switch_id, other_switch_id
                    ):
                        continue
                    pair = "/".join(sorted((switch_id, other_switch_id)))
                    raise RuntimeError(
                        f"Interface '{interface_name}' on vPC pair '{pair}' is "
                        f"present in both '{other_group_name}' and '{group_name}'."
                    )

    def _existing_vpc_member_switches(self) -> dict[str, set[str]]:
        """Return existing vPC member names mapped to their echoed switch IDs."""
        result: dict[str, set[str]] = {}
        for group in self._existing_groups.values():
            for switch_entry in group.switch_interfaces or []:
                for interface_name in switch_entry.interface_names:
                    if InterfaceGroupValidators.interface_kind(interface_name) == "vpc":
                        result.setdefault(interface_name, set()).add(
                            switch_entry.switch_id
                        )
        return result

    def _align_vpc_member_switch_ids(
        self, model_instances: Sequence[InterfaceGroupConfigModel]
    ) -> None:
        """Align only vPC members with ND's existing peer representation.

        A vPC interface is one logical resource across a switch pair, but the
        Interface Groups list response can echo it under the opposite peer from
        the one supplied in the playbook. Reusing the existing echoed serial
        prevents a false diff while leaving Ethernet and port-channel members
        tied to their exact switch IDs.
        """
        existing_switches = self._existing_vpc_member_switches()
        if not existing_switches:
            return

        for model_instance in model_instances:
            if not model_instance.switch_interfaces:
                continue
            aligned_members: set[tuple[str, str]] = set()
            changed = False
            for switch_entry in model_instance.switch_interfaces:
                for interface_name in switch_entry.interface_names:
                    aligned_switch_id = switch_entry.switch_id
                    if InterfaceGroupValidators.interface_kind(interface_name) == "vpc":
                        for existing_switch_id in sorted(
                            existing_switches.get(interface_name, set())
                        ):
                            if self._vpc_switch_ids_are_equivalent(
                                switch_entry.switch_id, existing_switch_id
                            ):
                                aligned_switch_id = existing_switch_id
                                break
                    changed = changed or aligned_switch_id != switch_entry.switch_id
                    aligned_members.add((aligned_switch_id, interface_name))

            if changed:
                model_instance.switch_interfaces = self._with_interface_pairs(
                    model_instance, aligned_members
                ).switch_interfaces

    @property
    def config_actions(self) -> dict[str, Any]:
        """Return config actions with the module defaults applied."""
        actions = self.rest_send.params.get("config_actions") or {}
        return {
            "deploy": actions.get("deploy", True),
            "type": actions.get("type", InterfaceGroupConfigActionType.SWITCH.value),
        }

    @property
    def warnings(self) -> list[str]:
        """Return de-duplicated operator warnings in insertion order."""
        return list(dict.fromkeys(self._warnings))

    def _configure_endpoint(
        self,
        endpoint: NDEndpointBaseModel,
        *,
        max_records: int | None = None,
        offset: int | None = None,
    ) -> NDEndpointBaseModel:
        """Apply fabric and supported query parameters to an endpoint."""
        endpoint.fabric_name = self.fabric_name
        endpoint_params = getattr(endpoint, "endpoint_params", None)
        if endpoint_params is None:
            return endpoint
        if max_records is not None and hasattr(endpoint_params, "max"):
            endpoint_params.max = max_records
        if offset is not None and hasattr(endpoint_params, "offset"):
            endpoint_params.offset = offset
        return endpoint

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _has_next_page(cls, response: Any, page_count: int, total_seen: int) -> bool:
        if not isinstance(response, dict) or page_count == 0:
            return False
        meta = response.get("meta") or response.get("metadata") or {}
        counts = meta.get("counts") or {}
        remaining = cls._coerce_int(counts.get("remaining"))
        if remaining is not None:
            return remaining > 0
        total = cls._coerce_int(counts.get("total"))
        if total is not None:
            return total_seen < total
        return page_count == _QUERY_PAGE_SIZE

    @staticmethod
    def _models_from_list_response(response: Any) -> list[InterfaceGroupConfigModel]:
        if isinstance(response, list):
            return [InterfaceGroupConfigModel.from_response(item) for item in response]
        parsed = InterfaceGroupsListResponseModel.from_response(response or {})
        return parsed.interface_group_details

    def query_all(
        self, model_instance: InterfaceGroupConfigModel | None = None, **kwargs
    ) -> ResponseType:
        """Query all Interface Groups using offset/max pagination."""
        try:
            if self.rest_send.params.get("state") == "gathered":
                if not self.fabric_context.fabric_exists():
                    raise RuntimeError(f"Fabric '{self.fabric_name}' does not exist.")
            else:
                self.fabric_context.validate_for_mutation()
            groups: list[InterfaceGroupConfigModel] = []
            offset = 0
            while True:
                endpoint = self._configure_endpoint(
                    self.query_all_endpoint(),
                    max_records=_QUERY_PAGE_SIZE,
                    offset=offset,
                )
                response = self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    not_found_ok=True,
                    operation_type=OperationType.QUERY,
                )
                page = self._models_from_list_response(response)
                groups.extend(page)
                if not self._has_next_page(response, len(page), len(groups)):
                    break
                offset += len(page)

            self._existing_groups = {
                item.interface_group_name: deepcopy(item) for item in groups
            }
            return [
                item.model_dump(by_alias=True, exclude_none=True, mode="json")
                for item in groups
            ]
        except Exception as exc:
            raise RuntimeError(f"Query all Interface Groups failed: {exc}") from exc

    @staticmethod
    def _switch_member_map(
        group: InterfaceGroupConfigModel,
    ) -> dict[str, set[str]]:
        """Return normalized member interfaces keyed by switch ID."""
        return {
            item.switch_id: set(item.interface_names)
            for item in group.switch_interfaces or []
        }

    @staticmethod
    def _dict_is_subset(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
        """Return whether every nested expected key/value exists in actual."""
        for key, value in expected.items():
            if key not in actual:
                return False
            if isinstance(value, dict):
                if not isinstance(actual[key], dict) or not (
                    ManageInterfaceGroupOrchestrator._dict_is_subset(value, actual[key])
                ):
                    return False
            elif actual[key] != value:
                return False
        return True

    def _gathered_switch_filter_matches(
        self,
        expected_switch: InterfaceGroupGatheredSwitchFilterModel,
        actual_members: dict[str, set[str]],
    ) -> bool:
        """Match one gathered switch filter with peer-aware vPC comparison."""
        exact_members = actual_members.get(expected_switch.switch_id)
        expected_names = expected_switch.interface_names
        if expected_names is None:
            if exact_members is not None:
                return True
            return any(
                any(
                    InterfaceGroupValidators.interface_kind(interface_name) == "vpc"
                    for interface_name in interface_names
                )
                and self._vpc_switch_ids_are_equivalent(
                    expected_switch.switch_id, actual_switch_id
                )
                for actual_switch_id, interface_names in actual_members.items()
            )

        if exact_members is None and not expected_names:
            return False
        for interface_name in expected_names:
            if exact_members is not None and interface_name in exact_members:
                continue
            if InterfaceGroupValidators.interface_kind(interface_name) != "vpc":
                return False
            if not any(
                interface_name in interface_names
                and self._vpc_switch_ids_are_equivalent(
                    expected_switch.switch_id, actual_switch_id
                )
                for actual_switch_id, interface_names in actual_members.items()
            ):
                return False
        return True

    def _matches_gathered_filter(
        self,
        group: InterfaceGroupConfigModel,
        filter_item: InterfaceGroupGatheredFilterModel,
    ) -> bool:
        """Apply one authoritative local gathered filter to one group."""
        supplied = filter_item.model_fields_set

        if (
            "interface_group_name" in supplied
            and group.interface_group_name != filter_item.interface_group_name
        ):
            return False
        if "type" in supplied and group.type != filter_item.type:
            return False
        if "template_name" in supplied and group.template_name != (
            filter_item.template_name
        ):
            return False

        if "network_names" in supplied:
            expected_networks = set(filter_item.network_names or [])
            actual_networks = set(group.network_names or [])
            if not expected_networks:
                if actual_networks:
                    return False
            elif not expected_networks.issubset(actual_networks):
                return False

        if "switch_interfaces" in supplied:
            expected_switches = filter_item.switch_interfaces or []
            actual_members = self._switch_member_map(group)
            if not expected_switches:
                if actual_members:
                    return False
            else:
                for expected_switch in expected_switches:
                    if not self._gathered_switch_filter_matches(
                        expected_switch, actual_members
                    ):
                        return False

        if "template_config" in supplied and not (
            InterfaceGroupValidators.template_config_is_subset(
                filter_item.template_config or {},
                group.template_config or {},
            )
        ):
            return False

        if "ethernet_attributes" in supplied:
            expected_attributes = (
                filter_item.ethernet_attributes.model_dump(
                    exclude_unset=True,
                    exclude_none=True,
                    mode="json",
                )
                if filter_item.ethernet_attributes is not None
                else {}
            )
            actual_attributes = (
                group.ethernet_attributes.model_dump(
                    exclude_none=True,
                    mode="json",
                )
                if group.ethernet_attributes is not None
                else {}
            )
            if not self._dict_is_subset(
                expected_attributes,
                actual_attributes,
            ):
                return False

        return True

    def gather(
        self, filters: Sequence[InterfaceGroupGatheredFilterModel] | None = None
    ) -> list[dict[str, Any]]:
        """Return replayable Interface Group config using reliable local filters.

        The controller exposes a generic Lucene filter on the list endpoint,
        but nested association lists and normalized Ethernet subtypes are not
        safe server-side predicates. ``query_all`` therefore performs one
        paginated read and this method applies the complete customer-facing
        contract locally. One filter entry is an AND expression; multiple
        entries are OR expressions. Scanning each group once also de-duplicates
        overlapping filter matches by Interface Group name.
        """
        filter_items = list(filters or [])
        self._resolve_gathered_switch_identifiers(filter_items)
        groups = sorted(
            self._existing_groups.values(),
            key=lambda item: item.interface_group_name,
        )
        if filter_items:
            groups = [
                group
                for group in groups
                if any(
                    self._matches_gathered_filter(group, filter_item)
                    for filter_item in filter_items
                )
            ]
        return [group.to_config() for group in groups]

    def query_one(
        self, model_instance: InterfaceGroupConfigModel, **kwargs
    ) -> ResponseType:
        """Query one Interface Group by name."""
        endpoint = self._configure_endpoint(self.query_one_endpoint())
        endpoint.set_identifiers(model_instance.interface_group_name)
        return self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )

    @staticmethod
    def _raise_create_failures(response: Any) -> None:
        parsed = InterfaceGroupsCreateResponseModel.from_response(response or {})
        if parsed.failures:
            messages = [
                item.message or f"type={item.type or '?'}" for item in parsed.failures
            ]
            raise RuntimeError(
                f"Interface Group create reported per-item failures: {'; '.join(messages)}"
            )

    @staticmethod
    def _raise_delete_failures(response: Any) -> None:
        parsed = InterfaceGroupsDeleteResponseModel.from_response(response or {})
        if parsed.failures:
            messages = [
                f"{item.interface_group_name or '?'}: {item.message or 'unknown error'}"
                for item in parsed.failures
            ]
            raise RuntimeError(
                f"Interface Group delete reported per-item failures: {'; '.join(messages)}"
            )

    @classmethod
    def _raise_action_failures(cls, response: Any, action: str) -> None:
        """Inspect common 207 per-item containers for explicit failures."""
        if not isinstance(response, dict):
            return
        failures: list[str] = []
        for key in ("results", "items", "switchIds", "interfaces"):
            values = response.get(key)
            if not isinstance(values, list):
                continue
            for item in values:
                if not isinstance(item, dict):
                    continue
                status = str(item.get("status") or "").strip().lower()
                if status not in _FAILURE_STATUSES:
                    continue
                identity = (
                    item.get("interfaceName")
                    or item.get("switchId")
                    or item.get("name")
                    or "?"
                )
                failures.append(f"{identity}: {item.get('message') or status}")
        if failures:
            raise RuntimeError(
                f"{action} reported per-item failures: {'; '.join(failures)}"
            )

    def create_bulk(
        self, model_instances: list[InterfaceGroupConfigModel], **kwargs
    ) -> ResponseType:
        """Create Interface Groups and populate ``any`` membership safely.

        ND rejects a single request whose newly associated members contain
        multiple interface kinds. Create ``any`` groups without members, then
        add each kind through cumulative PUTs so earlier batches are retained.
        Other group types keep the normal one-request bulk-create path.
        """
        endpoint = self._configure_endpoint(self.create_bulk_endpoint())
        create_models: list[InterfaceGroupConfigModel] = []
        deferred_any_members: list[InterfaceGroupConfigModel] = []
        for item in model_instances:
            if item.type == InterfaceGroupType.ANY.value and self._interface_pairs(
                item
            ):
                create_models.append(self._with_interface_pairs(item, set()))
                deferred_any_members.append(item)
            else:
                create_models.append(item)

        payload = InterfaceGroupsCreateRequestModel(
            interface_groups=create_models
        ).to_payload()
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=payload,
            operation_type=OperationType.CREATE,
        )
        self._raise_create_failures(response)

        for item in deferred_any_members:
            self._put_any_group_batches(None, item)

        for item in model_instances:
            self._queue_deploy_change(None, item, item.interface_group_name)
            self._existing_groups[item.interface_group_name] = deepcopy(item)
        return response

    def create(
        self, model_instance: InterfaceGroupConfigModel, **kwargs
    ) -> ResponseType:
        """Create one Interface Group through the bulk endpoint."""
        return self.create_bulk([model_instance])

    def _payload_for_update(
        self, model_instance: InterfaceGroupConfigModel
    ) -> dict[str, Any]:
        """Build a PUT payload for one Interface Group update."""
        payload = model_instance.to_payload()
        if self.rest_send.params.get("state") in {"replaced", "overridden"}:
            if model_instance.type in {
                InterfaceGroupType.ETHERNET_WITH_POLICY.value,
                InterfaceGroupType.ETHERNET_WITHOUT_POLICY.value,
            }:
                payload.setdefault("ethernetAttributes", {})
            if model_instance.type == InterfaceGroupType.ETHERNET_CUSTOM.value:
                payload.setdefault("templateConfig", {})
        return InterfaceGroupValidators.to_wire_group(payload)

    def _put_group(self, model_instance: InterfaceGroupConfigModel) -> ResponseType:
        endpoint = self._configure_endpoint(self.update_endpoint())
        endpoint.set_identifiers(model_instance.interface_group_name)
        return self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=self._payload_for_update(model_instance),
            operation_type=OperationType.UPDATE,
        )

    @staticmethod
    def _with_interface_pairs(
        model_instance: InterfaceGroupConfigModel,
        members: set[tuple[str, str]],
    ) -> InterfaceGroupConfigModel:
        """Return a copy with deterministic switch/member associations."""
        by_switch: dict[str, list[str]] = {}
        for switch_id, interface_name in sorted(members):
            by_switch.setdefault(switch_id, []).append(interface_name)

        updated = deepcopy(model_instance)
        updated.switch_interfaces = [
            {
                "switch_id": switch_id,
                "interface_names": interface_names,
            }
            for switch_id, interface_names in by_switch.items()
        ]
        return updated

    def _put_any_group_batches(
        self,
        before: InterfaceGroupConfigModel | None,
        after: InterfaceGroupConfigModel,
    ) -> ResponseType:
        """Apply newly added ``any`` members in homogeneous cumulative batches.

        The update body is authoritative, so every batch contains retained
        current members plus all members accepted by earlier batches. Grouping
        only newly added members avoids redundant requests when an existing
        heterogeneous group changes only networks, policy fields, or removals.
        """
        before_pairs = self._interface_pairs(before)
        after_pairs = self._interface_pairs(after)
        added_pairs = after_pairs - before_pairs

        additions_by_kind = {
            kind: {
                member
                for member in added_pairs
                if InterfaceGroupValidators.interface_kind(member[1]) == kind
            }
            for kind in _ANY_MEMBER_KIND_ORDER
        }
        populated_kinds = [
            kind for kind in _ANY_MEMBER_KIND_ORDER if additions_by_kind[kind]
        ]
        if not populated_kinds:
            return self._put_group(after)

        cumulative_pairs = before_pairs & after_pairs
        response: ResponseType = None
        for kind in populated_kinds:
            cumulative_pairs.update(additions_by_kind[kind])
            response = self._put_group(
                self._with_interface_pairs(after, cumulative_pairs)
            )
        return response

    def update(
        self, model_instance: InterfaceGroupConfigModel, **kwargs
    ) -> ResponseType:
        """Update one Interface Group and queue only switch-affecting changes."""
        before = self._existing_groups.get(model_instance.interface_group_name)
        if model_instance.type == InterfaceGroupType.ANY.value:
            response = self._put_any_group_batches(before, model_instance)
        else:
            response = self._put_group(model_instance)
        self._queue_deploy_change(
            before, model_instance, model_instance.interface_group_name
        )
        self._existing_groups[model_instance.interface_group_name] = deepcopy(
            model_instance
        )
        return response

    def delete_bulk(
        self, model_instances: list[InterfaceGroupConfigModel], **kwargs
    ) -> ResponseType:
        """Clear associations, then delete Interface Groups in one bulk request."""
        for item in model_instances:
            before = self._existing_groups.get(item.interface_group_name, item)
            if before.network_names or before.switch_interfaces:
                detached = deepcopy(before)
                detached.network_names = []
                detached.switch_interfaces = []
                self._put_group(detached)
                self._queue_deploy_change(before, detached, item.interface_group_name)
                self._existing_groups[item.interface_group_name] = deepcopy(detached)

        endpoint = self._configure_endpoint(self.delete_bulk_endpoint())
        payload = InterfaceGroupsRemoveRequestModel(
            interface_group_names=[
                item.interface_group_name for item in model_instances
            ]
        ).to_payload()
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=payload,
            operation_type=OperationType.DELETE,
        )
        self._raise_delete_failures(response)
        for item in model_instances:
            self._existing_groups.pop(item.interface_group_name, None)
        return response

    def delete(
        self, model_instance: InterfaceGroupConfigModel, **kwargs
    ) -> ResponseType:
        """Delete one Interface Group through the bulk endpoint."""
        return self.delete_bulk([model_instance])

    def preflight_create(
        self, model_instances: Sequence[InterfaceGroupConfigModel]
    ) -> None:
        """Require type and custom-template identity for new groups."""
        failures: list[str] = []
        for item in model_instances:
            if item.type is None:
                failures.append(f"'{item.interface_group_name}' requires type")
            elif (
                item.type == InterfaceGroupType.ETHERNET_CUSTOM.value
                and not item.template_name
            ):
                failures.append(
                    f"'{item.interface_group_name}' requires template_name for type=ethernetCustom"
                )
        if failures:
            raise RuntimeError("; ".join(failures))

    @staticmethod
    def _interface_pairs(
        model: InterfaceGroupConfigModel | None,
    ) -> set[tuple[str, str]]:
        if model is None:
            return set()
        return {
            (entry.switch_id, interface_name)
            for entry in model.switch_interfaces or []
            for interface_name in entry.interface_names
        }

    @staticmethod
    def _policy_signature(
        model: InterfaceGroupConfigModel | None,
    ) -> tuple[Any, ...] | None:
        if model is None or model.type not in _INTERFACE_POLICY_TYPES:
            return None
        return (
            model.type,
            model.template_name,
            model.template_config,
            model.ethernet_attributes,
        )

    @staticmethod
    def _has_interface_configuration(model: InterfaceGroupConfigModel | None) -> bool:
        if model is None:
            return False
        return bool(model.network_names) or model.type in _INTERFACE_POLICY_TYPES

    @classmethod
    def _affected_interfaces(
        cls,
        before: InterfaceGroupConfigModel | None,
        after: InterfaceGroupConfigModel | None,
    ) -> set[tuple[str, str]]:
        before_pairs = cls._interface_pairs(before)
        after_pairs = cls._interface_pairs(after)
        affected: set[tuple[str, str]] = set()

        if cls._has_interface_configuration(after):
            affected.update(after_pairs - before_pairs)
        if cls._has_interface_configuration(before):
            affected.update(before_pairs - after_pairs)

        before_networks = set(before.network_names or []) if before else set()
        after_networks = set(after.network_names or []) if after else set()
        if before_networks != after_networks:
            affected.update(before_pairs | after_pairs)

        if cls._policy_signature(before) != cls._policy_signature(after):
            affected.update(before_pairs | after_pairs)
        return affected

    def _resource_deploy_enabled(self, group_name: str) -> bool:
        if not self.config_actions["deploy"]:
            return False
        if self.config_actions["type"] != InterfaceGroupConfigActionType.RESOURCE.value:
            return True
        for item in self.rest_send.params.get("config") or []:
            name = item.get("interface_group_name", item.get("interfaceGroupName"))
            if name == group_name:
                return item.get("deploy", True) is not False
        return True

    def _queue_deploy_change(
        self,
        before: InterfaceGroupConfigModel | None,
        after: InterfaceGroupConfigModel | None,
        group_name: str,
    ) -> None:
        if not self._resource_deploy_enabled(group_name):
            return
        affected = self._affected_interfaces(before, after)
        if self.config_actions["type"] == InterfaceGroupConfigActionType.RESOURCE.value:
            self._pending_interfaces.update(affected)
        else:
            self._pending_switches.update(
                switch_id for switch_id, _interface_name in affected
            )

    def _effective_model(
        self, proposed: InterfaceGroupConfigModel
    ) -> InterfaceGroupConfigModel:
        existing = self._existing_groups.get(proposed.interface_group_name)
        if existing is not None and self.rest_send.params.get("state") == "merged":
            return deepcopy(existing).merge(proposed)
        return deepcopy(proposed)

    def _preserve_omitted_associations(
        self, model_instances: Sequence[InterfaceGroupConfigModel]
    ) -> None:
        """Keep existing association lists when authoritative input omits them.

        ``replaced`` and ``overridden`` treat a supplied association list as the
        complete desired list, but omission means that collection is not being
        managed by this task. Hydrating the proposed model before reconciliation
        keeps the request payload, predicted ``after`` state, move planning, and
        deployment calculation consistent. Explicit empty lists remain present
        in ``model_fields_set`` and therefore continue to clear associations.
        """
        if self.rest_send.params.get("state") not in {"replaced", "overridden"}:
            return

        for proposed in model_instances:
            existing = self._existing_groups.get(proposed.interface_group_name)
            if existing is None:
                continue
            if "network_names" not in proposed.model_fields_set:
                proposed.network_names = deepcopy(existing.network_names)
            if "switch_interfaces" not in proposed.model_fields_set:
                proposed.switch_interfaces = deepcopy(existing.switch_interfaces)

    @staticmethod
    def _membership_owner_map(
        groups: dict[str, InterfaceGroupConfigModel],
    ) -> dict[tuple[str, str], str]:
        owners: dict[tuple[str, str], str] = {}
        for group_name, group in groups.items():
            for member in ManageInterfaceGroupOrchestrator._interface_pairs(group):
                owners[member] = group_name
        return owners

    @staticmethod
    def _remove_members(
        model: InterfaceGroupConfigModel,
        members: set[tuple[str, str]],
    ) -> InterfaceGroupConfigModel:
        remaining: list[dict[str, Any]] = []
        for entry in model.switch_interfaces or []:
            interface_names = [
                interface_name
                for interface_name in entry.interface_names
                if (entry.switch_id, interface_name) not in members
            ]
            if interface_names:
                remaining.append(
                    {
                        "switch_id": entry.switch_id,
                        "interface_names": interface_names,
                    }
                )
        updated = deepcopy(model)
        updated.switch_interfaces = remaining
        return updated

    def _plan_moves(
        self,
        proposed_models: Sequence[InterfaceGroupConfigModel],
        effective: dict[str, InterfaceGroupConfigModel],
    ) -> None:
        state = self.rest_send.params.get("state")
        owners = self._membership_owner_map(self._existing_groups)
        moving_from: dict[str, set[tuple[str, str]]] = {}

        for target_name, target in effective.items():
            for member in self._interface_pairs(target):
                source_name = owners.get(member)
                if source_name is None or source_name == target_name:
                    continue
                if state == "merged":
                    raise RuntimeError(
                        f"Interface '{member[1]}' on switch '{member[0]}' already belongs to Interface Group "
                        f"'{source_name}'. state=merged is additive and cannot remove it from that group; "
                        "use state=replaced or state=overridden for an explicit move."
                    )

                source_desired = effective.get(source_name)
                source_will_be_deleted = (
                    state == "overridden" and source_desired is None
                )
                source_removes_member = (
                    source_desired is not None
                    and member not in self._interface_pairs(source_desired)
                )
                if not source_will_be_deleted and not source_removes_member:
                    raise RuntimeError(
                        f"Moving interface '{member[1]}' on switch '{member[0]}' from '{source_name}' to "
                        f"'{target_name}' requires the source group to omit that member in the same "
                        f"{state} task."
                    )
                moving_from.setdefault(source_name, set()).add(member)

        self._move_plan = {
            source_name: self._remove_members(
                self._existing_groups[source_name], members
            )
            for source_name, members in moving_from.items()
        }

    def _network_exists(self, network_name: str) -> bool:
        endpoint = self._configure_endpoint(EpManageFabricsNetworksNetworkNameGet())
        endpoint.network_name = network_name
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        return bool(response)

    @staticmethod
    def _normalize_template_metadata_token(value: Any) -> str:
        """Normalize controller enum spelling across camel/snake/upper variants."""
        return "".join(
            character for character in str(value or "").lower() if character.isalnum()
        )

    @staticmethod
    def _normalize_template_tags(value: Any) -> set[str]:
        """Normalize tags returned as a CSV string or comma-suffixed list entries."""
        raw_tags = [value] if isinstance(value, str) else value or []
        return {
            token.strip().lower()
            for raw_tag in raw_tags
            for token in str(raw_tag).split(",")
            if token.strip()
        }

    @classmethod
    def _template_property(cls, template: dict[str, Any], property_name: str) -> Any:
        """Read a top-level value or one property from the template content header."""
        if property_name in template:
            return template[property_name]

        in_properties = False
        for line in str(template.get("content") or "").splitlines():
            stripped = line.strip()
            if stripped.lower() == "##template properties":
                in_properties = True
                continue
            if in_properties and stripped == "##":
                break
            if not in_properties:
                continue
            key, separator, value = stripped.partition("=")
            if separator and cls._normalize_template_metadata_token(
                key
            ) == cls._normalize_template_metadata_token(property_name):
                return value.strip().rstrip(";").strip()
        return None

    @classmethod
    def _custom_template_eligibility_errors(cls, template: dict[str, Any]) -> list[str]:
        """Return customer-facing reasons a template cannot back an Ethernet group."""
        errors: list[str] = []
        if (
            cls._normalize_template_metadata_token(template.get("templateType"))
            != "policy"
        ):
            errors.append("it is not a policy template")
        if (
            cls._normalize_template_metadata_token(template.get("templateSubType"))
            != "interfaceethernet"
        ):
            errors.append("its subtype is not Ethernet interface")
        if (
            cls._normalize_template_metadata_token(template.get("contentType"))
            not in _CUSTOM_TEMPLATE_CONTENT_TYPES
        ):
            errors.append("its content type is not Python or Python CLI")

        tags = cls._normalize_template_tags(template.get("tags"))
        if _CUSTOM_TEMPLATE_REQUIRED_TAG not in tags:
            errors.append("it is not tagged as an editable shared-interface policy")

        user_defined = cls._template_property(template, "userDefined")
        if cls._normalize_template_metadata_token(user_defined) != "true":
            errors.append("it is not a user-defined template")

        supported_platforms = template.get("supportedPlatforms") or []
        if isinstance(supported_platforms, str):
            supported_platforms = [supported_platforms]
        if not [item for item in supported_platforms if str(item).strip()]:
            errors.append("it does not declare any supported switch platforms")
        return errors

    def _get_custom_template(self, template_name: str) -> dict[str, Any]:
        """Fetch and cache one complete template definition for strict preflight."""
        if template_name in self._custom_template_cache:
            cached = self._custom_template_cache[template_name]
            if cached is None:
                raise RuntimeError(f"Custom template '{template_name}' does not exist.")
            return cached

        endpoint = EpManageConfigTemplateGet()
        endpoint.template_name = template_name
        try:
            response = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Unable to validate custom template '{template_name}': {exc}"
            ) from exc

        if not isinstance(response, dict) or not response:
            self._custom_template_cache[template_name] = None
            raise RuntimeError(f"Custom template '{template_name}' does not exist.")
        self._custom_template_cache[template_name] = response
        return response

    def _validate_custom_templates(
        self,
        model_instances: Sequence[InterfaceGroupConfigModel],
        effective: dict[str, InterfaceGroupConfigModel],
    ) -> None:
        """Validate changed custom-template references and inputs before writes."""
        failures: list[str] = []
        for proposed in model_instances:
            after = effective[proposed.interface_group_name]
            if after.type != InterfaceGroupType.ETHERNET_CUSTOM.value:
                continue

            before = self._existing_groups.get(proposed.interface_group_name)
            template_fields_changed = (
                before is None
                or "template_name" in proposed.model_fields_set
                or "template_config" in proposed.model_fields_set
            )
            if not template_fields_changed or not after.template_name:
                continue

            try:
                template = self._get_custom_template(after.template_name)
            except RuntimeError as exc:
                failures.append(f"'{after.interface_group_name}': {exc}")
                continue

            eligibility_errors = self._custom_template_eligibility_errors(template)
            if eligibility_errors:
                failures.append(
                    f"'{after.interface_group_name}': Custom template "
                    f"'{after.template_name}' is not eligible for Ethernet Interface Groups: "
                    f"{'; '.join(eligibility_errors)}."
                )
                continue

            input_errors = validate_template_inputs(
                after.template_name,
                after.template_config or {},
                template.get("parameters") or [],
                input_label="template_config",
            )
            failures.extend(
                f"'{after.interface_group_name}': {message}" for message in input_errors
            )

        if failures:
            raise RuntimeError("; ".join(failures))

    def _validate_networks_exist(self, network_names: set[str]) -> None:
        missing = sorted(
            name for name in network_names if not self._network_exists(name)
        )
        if missing:
            quoted = ", ".join(f"'{name}'" for name in missing)
            raise RuntimeError(
                f"Referenced network(s) {quoted} do not exist in fabric '{self.fabric_name}'. "
                "The Interface Groups module does not create networks."
            )

    def _warn_resource_network_deploy_scope(self, network_names: set[str]) -> None:
        """Warn that resource deployment applies interfaces, not networks."""
        if not network_names:
            return
        quoted = ", ".join(f"'{name}'" for name in sorted(network_names))
        message = (
            f"Resource-level Interface Group deployment will deploy affected "
            f"interfaces but will not deploy referenced network(s) {quoted}. "
            "Deploy the network configuration separately with "
            "cisco.nd.nd_manage_networks."
        )
        self._warnings.append(message)
        self.rest_send.warn(message)

    def preflight(self, model_instances: Sequence[InterfaceGroupConfigModel]) -> None:
        """Validate immutable fields, moves, and referenced networks before writes."""
        self._resolve_config_switch_identifiers(model_instances)
        self._collapse_switch_entries(model_instances)
        self._preserve_omitted_associations(model_instances)
        self._align_vpc_member_switch_ids(model_instances)
        self._collapse_switch_entries(model_instances)
        self._validate_runtime_member_ownership(model_instances)
        effective = {
            item.interface_group_name: self._effective_model(item)
            for item in model_instances
        }

        for item in model_instances:
            existing = self._existing_groups.get(item.interface_group_name)
            if (
                existing is not None
                and item.type is not None
                and item.type != existing.type
            ):
                raise RuntimeError(
                    f"Interface Group '{item.interface_group_name}' type cannot be changed "
                    f"from '{existing.type}' to '{item.type}'."
                )

        self._validate_custom_templates(model_instances, effective)
        self._plan_moves(model_instances, effective)

        referenced_networks: set[str] = set()
        for group_name, after in effective.items():
            before = self._existing_groups.get(group_name)
            before_networks = set(before.network_names or []) if before else set()
            referenced_networks.update(set(after.network_names or []) - before_networks)
        self._validate_networks_exist(referenced_networks)

        if (
            self.config_actions["deploy"]
            and self.config_actions["type"]
            == InterfaceGroupConfigActionType.RESOURCE.value
        ):
            resource_networks: set[str] = set()
            for group_name, after in effective.items():
                if not self._resource_deploy_enabled(group_name):
                    continue
                before = self._existing_groups.get(group_name)
                if before is not None and before.get_diff(after, exclude_unset=False):
                    continue
                resource_networks.update(after.network_names or [])
            self._warn_resource_network_deploy_scope(resource_networks)

    def prepare_mutations(
        self,
        existing: NDConfigCollection,
        proposed: NDConfigCollection,
        check_mode: bool = False,
    ) -> None:
        """Remove cross-group members from source groups before final updates."""
        for source_name, intermediate in sorted(self._move_plan.items()):
            before = existing.get(source_name)
            if before is None:
                continue
            if not check_mode:
                self._put_group(intermediate)
            self._queue_deploy_change(before, intermediate, source_name)
            existing.replace(deepcopy(intermediate))
            self._existing_groups[source_name] = deepcopy(intermediate)

    def deploy_pending(self) -> ResponseType | None:
        """Deploy queued interface or switch targets once after all mutations."""
        if not self.config_actions["deploy"]:
            return None

        if self.config_actions["type"] == InterfaceGroupConfigActionType.RESOURCE.value:
            if not self._pending_interfaces:
                return None
            endpoint = EpManageInterfacesDeploy()
            endpoint.fabric_name = self.fabric_name
            payload = {
                "interfaces": [
                    {"switchId": switch_id, "interfaceName": interface_name}
                    for switch_id, interface_name in sorted(self._pending_interfaces)
                ]
            }
            response = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                data=payload,
                operation_type=OperationType.UPDATE,
            )
            self._raise_action_failures(response, "interfaceActions/deploy")
            self._pending_interfaces.clear()
            return response

        if not self._pending_switches:
            return None
        endpoint = self._configure_endpoint(EpManageSwitchActionsDeployPost())
        payload = {"switchIds": sorted(self._pending_switches)}
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=payload,
            operation_type=OperationType.UPDATE,
        )
        self._raise_action_failures(response, "switchActions/deploy")
        self._pending_switches.clear()
        return response
