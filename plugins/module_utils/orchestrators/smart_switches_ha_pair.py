# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Reconcile fabric-scoped Smart Switch HA intent through Manage actions."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, TypeVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import PrivateAttr, ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.controller import ConfigActionsController
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions, ConfigActionsContext, ConfigActionsResult
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import EpFabricConfigSavePost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import EpFabricDeployPost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import EpManageSwitchActionsDeployPost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_smart_switches import (
    EpManageSmartSwitchHaRecommendationsGet,
    EpManageSmartSwitchesHaPairPost,
    EpManageSmartSwitchesHaPairsGet,
    EpManageSmartSwitchesHaUnpairPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_ha_pair.pairing import (
    PRESENT_HA_STATES,
    PairKey,
    SmartSwitchHaPairModel,
    SmartSwitchHaResultEntry,
    SmartSwitchHaRow,
    SmartSwitchHaRows,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import MutationOutcome, MutationResourceOutcome, MutationResult
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.backends.fabric import FabricConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import parse_controller_version

EndpointType = TypeVar("EndpointType", bound=NDEndpointBaseModel)


# HA inventory indexing


@dataclass
class _SmartSwitchHaInventory:
    """Index topology by switch ID and active HA associations by unordered pair."""

    rows_by_switch_id: dict[str, SmartSwitchHaRow] = field(default_factory=dict)
    active_rows_by_pair: dict[PairKey, SmartSwitchHaRow] = field(default_factory=dict)
    _reported_switch_ids: set[str] = field(default_factory=set)

    def add_inventory_row(self, row: SmartSwitchHaRow) -> None:
        """Index both peers and prefer the primary vPC row when ND reports both orientations."""
        switch_info = row.switch_info
        switch_id, peer_id = switch_info.switch_id, switch_info.peer_id
        if switch_id in self._reported_switch_ids:
            raise ValueError(f"HA inventory repeats row for switch {switch_id!r}")

        reported_pair = row.peers
        pair_is_active = switch_info.ha_paired in PRESENT_HA_STATES
        if switch_info.ha_paired is None:
            raise ValueError(f"HA inventory row for {switch_id!r} is missing haPaired")
        if peer_id == switch_id or (pair_is_active and reported_pair is None):
            raise ValueError(f"HA inventory row for {switch_id!r} requires a peer with a different switch ID")

        # An indexed pair points both switch IDs to the same row, so one match is enough.
        existing_row = self.rows_by_switch_id.get(switch_id)
        if existing_row is None and peer_id is not None:
            existing_row = self.rows_by_switch_id.get(peer_id)
        if existing_row is not None:
            existing_info = existing_row.switch_info
            if (
                existing_row.peers != reported_pair
                or existing_row.pairing_type != row.pairing_type
                or existing_info.ha_paired != switch_info.ha_paired
                or (existing_info.vpc_domain is not None and switch_info.vpc_domain is not None and existing_info.vpc_domain != switch_info.vpc_domain)
            ):
                raise ValueError(f"Conflicting HA inventory for switch {switch_id!r}")
            if (existing_info.vpc_role != "primary", existing_info.switch_id) < (switch_info.vpc_role != "primary", switch_id):
                row = existing_row

        self._reported_switch_ids.add(switch_id)
        self.rows_by_switch_id[switch_id] = row
        if peer_id is not None:
            self.rows_by_switch_id[peer_id] = row
        if pair_is_active and reported_pair is not None:
            self.active_rows_by_pair[reported_pair] = row


# Pair and unpair response handling


def normalize_ha_pair_action_response(response: object, expected_pairs: Sequence[PairKey]) -> MutationResult:
    """Translate controller evidence into one state-machine outcome per requested pair."""
    if not isinstance(response, dict) or not isinstance(response.get("results"), dict):
        return MutationResult(protocol_errors=("Expected an HA action response with a results object",))

    protocol_errors = [] if isinstance(response.get("rows"), list) else ["Expected an HA action response with a rows array"]
    pair_names = {pair: {"-".join(pair), "-".join(reversed(pair))} for pair in expected_pairs}
    pairs_by_result_name: dict[str, set[PairKey]] = defaultdict(set)
    for pair, names in pair_names.items():
        for name in names.union(pair):
            pairs_by_result_name[name].add(pair)

    evidence_by_pair: dict[PairKey, list[tuple[str, SmartSwitchHaResultEntry, MutationOutcome]]] = defaultdict(list)
    invalid_pairs: set[PairKey] = set()
    result_groups = (
        ("successResults", "success", MutationOutcome.SUCCEEDED),
        ("failureResults", "failed", MutationOutcome.FAILED),
    )
    for source, expected_status, group_outcome in result_groups:
        raw_entries = response["results"].get(source, [])
        if not isinstance(raw_entries, list):
            protocol_errors.append(f"HA {source} must be an array")
            continue
        for raw_entry in raw_entries:
            name = raw_entry.get("name") if isinstance(raw_entry, dict) else None
            matching_pairs = pairs_by_result_name.get(name, ()) if isinstance(name, str) else ()
            if len(matching_pairs) != 1:
                protocol_errors.append(f"Unrecognized or ambiguous HA result name {name!r} in {source}")
                invalid_pairs.update(matching_pairs)
                continue
            pair = next(iter(matching_pairs))
            try:
                entry = SmartSwitchHaResultEntry.model_validate(raw_entry)
            except ValidationError as error:
                invalid_pairs.add(pair)
                protocol_errors.append(f"Malformed HA result for {name!r}: {error}")
                continue
            if entry.status is not None and entry.status != expected_status:
                invalid_pairs.add(pair)
                protocol_errors.append(f"HA result status {entry.status!r} contradicts {source} for {name!r}")
            evidence_by_pair[pair].append((source, entry, group_outcome))

    pair_outcomes = []
    for pair in expected_pairs:
        pair_evidence = evidence_by_pair[pair]
        reported_outcomes = {outcome for _source, _entry, outcome in pair_evidence}
        reported_names = {entry.name for _source, entry, _outcome in pair_evidence}
        # One pair name or both switch IDs account for the complete association.
        has_complete_result = not reported_names.isdisjoint(pair_names[pair]) or reported_names.issuperset(pair)
        outcome = MutationOutcome.UNKNOWN
        if pair not in invalid_pairs:
            if len(reported_outcomes) > 1:
                protocol_errors.append(f"Conflicting HA results for {pair!r}")
            elif not has_complete_result:
                protocol_errors.append(f"Missing complete pair result for {pair!r}")
            else:
                outcome = next(iter(reported_outcomes))
        pair_outcomes.append(
            MutationResourceOutcome(
                pair,
                outcome,
                statuses=(entry.status for _source, entry, _outcome in pair_evidence if entry.status is not None),
                messages=(entry.message for _source, entry, _outcome in pair_evidence if entry.message is not None),
                evidence=({"source": source, "returned_name": entry.name} for source, entry, _outcome in pair_evidence),
            )
        )
    return MutationResult(tuple(pair_outcomes), tuple(protocol_errors))


# Switch-scoped deployment backend


class _SmartSwitchHaPeerDeploymentBackend(FabricConfigActionsBackend):
    """Send the full affected-peer set through the shared fabric config actions."""

    def deploy_switches(self, context: ConfigActionsContext, fabric_name: str, switch_ids: tuple[str, ...]) -> ResponseType:
        # Submit both peers together so the controller can report a result for each.
        return self.owner.deploy_switch_ids(fabric_name, list(switch_ids))


# Smart Switch HA orchestration


class SmartSwitchHaPairOrchestrator(ConfigActionsMixin, NDBaseOrchestrator[SmartSwitchHaPairModel]):
    """Read and validate HA intent, then submit the corresponding controller actions."""

    model_class: ClassVar[type[SmartSwitchHaPairModel]] = SmartSwitchHaPairModel
    supports_mutation_outcomes: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    _PAGE_SIZE: ClassVar[int] = 500
    _PAGE_LIMIT: ClassVar[int] = 1000

    create_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesHaPairPost
    delete_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesHaUnpairPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesHaUnpairPost
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesHaPairsGet
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageSmartSwitchesHaPairsGet
    update_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel
    fabric_name: str
    cluster_name: str | None = None
    _ha_inventory: _SmartSwitchHaInventory | None = PrivateAttr(default=None)
    _prepared_create_rows_by_pair: dict[PairKey, list[SmartSwitchHaRow]] = PrivateAttr(default_factory=dict)

    # Cluster routing and HA discovery

    def _route_endpoint_to_cluster(self, endpoint: EndpointType) -> EndpointType:
        endpoint.endpoint_params.cluster_name = self.cluster_name
        return endpoint

    def _read_ha_rows(self, endpoint: NDEndpointBaseModel) -> list[SmartSwitchHaRow]:
        body = self._request(endpoint.path, endpoint.verb)
        if self.rest_send.return_code != 200:
            raise ValueError(f"Expected HTTP 200 from the HA read, received {self.rest_send.return_code}")
        return SmartSwitchHaRows.model_validate(body).rows

    def _load_ha_inventory(self) -> _SmartSwitchHaInventory:
        """Cache a complete fabric snapshot for the current reconciliation."""
        if self._ha_inventory is not None:
            return self._ha_inventory
        endpoint = self._route_endpoint_to_cluster(self.query_all_endpoint(fabric_name=self.fabric_name))
        # The connection reports the local controller's version. A routed query probes the target instead.
        if self.cluster_name is None:
            controller_version = parse_controller_version(self.rest_send.controller_version)
            minimum_version = parse_controller_version(endpoint.min_controller_version)
            if controller_version is not None and minimum_version is not None and controller_version < minimum_version:
                raise ValueError(f"Smart Switch HA pairing requires Nexus Dashboard {endpoint.min_controller_version} or later")

        inventory = _SmartSwitchHaInventory()
        endpoint.endpoint_params.max = self._PAGE_SIZE
        offset = 0
        for _page_number in range(self._PAGE_LIMIT):
            endpoint.endpoint_params.offset = offset
            rows = self._read_ha_rows(endpoint)
            # HA list pages have no required count metadata. A short page can still precede another page.
            if not rows:
                self._ha_inventory = inventory
                return inventory
            for row in rows:
                inventory.add_inventory_row(row)
            offset += len(rows)
        raise ValueError("Smart Switch HA inventory pagination exceeded its page limit")

    # Current-state queries

    def query_all(self, model_instance: SmartSwitchHaPairModel | None = None, **kwargs) -> list[dict[str, Any]]:
        return [{"switch_id": first, "peer_switch_id": second} for first, second in sorted(self._load_ha_inventory().active_rows_by_pair)]

    def query_one(self, model_instance: SmartSwitchHaPairModel, **kwargs) -> dict[str, Any]:
        if model_instance.peers in self._load_ha_inventory().active_rows_by_pair:
            return model_instance.to_config()
        return {}

    # Pair creation preflight

    def preflight_create(self, model_instances: Sequence[SmartSwitchHaPairModel]) -> None:
        """Validate topology and controller eligibility for every planned pair before writing."""
        inventory = self._load_ha_inventory()
        rows_by_pair = {item.peers: self._prepare_pair_create_rows(item.peers, inventory) for item in model_instances}
        for (first_switch_id, second_switch_id), request_rows in rows_by_pair.items():
            anchor_row = request_rows[0]
            anchor_id = anchor_row.switch_info.switch_id
            if anchor_row.switch_info.ha_paired == "unpairPending":
                # The action explicitly allows reversing an identifiable vPC unpair.
                continue
            peer_id = second_switch_id if first_switch_id == anchor_id else first_switch_id
            endpoint = self._route_endpoint_to_cluster(EpManageSmartSwitchHaRecommendationsGet(fabric_name=self.fabric_name, switch_id=anchor_id))
            recommended_rows = self._read_ha_rows(endpoint)
            if not any(row.switch_info.switch_id == peer_id and row.pairing_type == anchor_row.pairing_type for row in recommended_rows):
                raise ValueError(f"Switch {peer_id!r} is not an eligible HA peer for {anchor_id!r}")
        self._prepared_create_rows_by_pair.update(rows_by_pair)

    @staticmethod
    def _prepare_pair_create_rows(pair: PairKey, inventory: _SmartSwitchHaInventory) -> list[SmartSwitchHaRow]:
        """Build one row for an existing vPC topology or two for standalone peers."""
        request_rows = []
        for switch_id in pair:
            row = inventory.rows_by_switch_id.get(switch_id)
            if row is None:
                raise ValueError(f"Switch {switch_id!r} is not in the HA inventory")
            if row.switch_info.ha_paired in PRESENT_HA_STATES:
                raise ValueError(
                    f"Switch {switch_id!r} is already paired with {row.peers!r}. To change peers, unpair and deploy the existing association first."
                )
            if row.pairing_type == "vpc":
                if row.peers != pair:
                    raise ValueError(f"Switch {switch_id!r} must be paired with its physical vPC peer")
                return [row]
            if row.switch_info.ha_paired != "unpaired" or row.peers:
                raise ValueError(f"Switch {switch_id!r} must be standalone and unpaired. Its HA state is {row.switch_info.ha_paired!r}")
            request_rows.append(row)
        return request_rows

    # Pair and unpair actions

    def create(self, model_instance: SmartSwitchHaPairModel, **kwargs) -> MutationResult:
        pair = model_instance.peers
        if pair not in self._prepared_create_rows_by_pair:
            self.preflight_create([model_instance])
        endpoint = self._route_endpoint_to_cluster(self.create_endpoint(fabric_name=self.fabric_name))
        return self._submit_ha_pair_action(endpoint, OperationType.CREATE, [pair], self._prepared_create_rows_by_pair[pair])

    def delete(self, model_instance: SmartSwitchHaPairModel, **kwargs) -> MutationResult:
        return self.delete_bulk([model_instance], **kwargs)

    def delete_bulk(self, model_instances: list[SmartSwitchHaPairModel], **kwargs) -> MutationResult:
        active_rows = self._load_ha_inventory().active_rows_by_pair
        pairs_to_unpair = sorted({item.peers for item in model_instances if item.peers in active_rows})
        if not pairs_to_unpair:
            return MutationResult()
        endpoint = self._route_endpoint_to_cluster(self.delete_bulk_endpoint(fabric_name=self.fabric_name))
        return self._submit_ha_pair_action(endpoint, OperationType.DELETE, pairs_to_unpair, [active_rows[pair] for pair in pairs_to_unpair])

    def update(self, model_instance: SmartSwitchHaPairModel, **kwargs) -> MutationResult:
        raise NotImplementedError("Smart Switch HA pairs have no in-place update")

    def _submit_ha_pair_action(
        self, endpoint: NDEndpointBaseModel, operation: OperationType, expected_pairs: Sequence[PairKey], request_rows: list[SmartSwitchHaRow]
    ) -> MutationResult:
        body = SmartSwitchHaRows(rows=request_rows).model_dump(by_alias=True, mode="json", exclude_unset=True)
        try:
            response = self._request(endpoint.path, endpoint.verb, body, operation_type=operation)
        except RuntimeError as error:
            # Authentication, authorization and missing-resource responses reject the action before it can apply.
            if self.rest_send.return_code in (401, 403, 404):
                return MutationResult(tuple(MutationResourceOutcome(pair, MutationOutcome.FAILED, messages=(str(error),)) for pair in expected_pairs))
            raise
        if self.rest_send.return_code != 202:
            return MutationResult(protocol_errors=(f"Expected HTTP 202 from the HA action, received {self.rest_send.return_code}",))
        return normalize_ha_pair_action_response(response, expected_pairs)

    # Configuration save and deployment

    def run_pair_config_actions(self, actions: ConfigActions, switch_ids: tuple[str, ...], *, check_mode: bool) -> ConfigActionsResult:
        """Return the shared post-action result for the peers identified by the state machine."""
        context = ConfigActionsContext(
            fabric_names=(self.fabric_name,),
            switch_ids_by_fabric={self.fabric_name: switch_ids},
            check_mode=check_mode,
        )
        executor = ConfigActionsController(policy=self.config_actions_policy, backend=_SmartSwitchHaPeerDeploymentBackend(self))
        # A lost response can leave an action applied. Limit save and deploy to one attempt each.
        previous_attempts = self.rest_send.max_attempts
        self.rest_send.max_attempts = 1
        try:
            return executor.execute(actions, context)
        finally:
            self.rest_send.max_attempts = previous_attempts

    def config_save_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self._route_endpoint_to_cluster(EpFabricConfigSavePost(fabric_name=fabric_name))

    def deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self._route_endpoint_to_cluster(EpFabricDeployPost(fabric_name=fabric_name))

    def switch_deploy_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self._route_endpoint_to_cluster(EpManageSwitchActionsDeployPost(fabric_name=fabric_name))

    def deploy_switch_ids(self, fabric_name: str, switch_ids: list[str]) -> ResponseType:
        """Deploy the requested peers and require one result per switch."""
        if not switch_ids:
            return None
        response = super().deploy_switch_ids(fabric_name, switch_ids)
        rows = response.get("switchIds") if isinstance(response, dict) else None
        if self.rest_send.return_code != 207 or not isinstance(rows, list):
            raise ValueError("Expected HTTP 207 with per-switch deployment results")
        reported_switch_ids = {row.get("switchId") for row in rows if isinstance(row, dict) and isinstance(row.get("switchId"), str)}
        if len(rows) != len(switch_ids) or reported_switch_ids != set(switch_ids):
            raise ValueError("The switch deployment response does not cover every requested HA peer")
        return response
