# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pyright: reportAttributeAccessIssue=false
# ModelType is NDBaseModel which lacks interface-specific fields (switch_ip,
# interface_name, config_data). Concrete subclasses always bind ModelType to a
# model that provides these fields, so the accesses are safe at runtime.

"""
Base orchestrator for vPC interface modules on Nexus Dashboard.

This module provides `VpcInterfaceBaseOrchestrator`, which implements shared CRUD operations for all vPC interface
types (`accessVpcHost`, `trunkVpcHost`, etc.) via the ND Manage Interfaces API. Type-specific orchestrators
inherit from this base and provide their own `model_class` and `_managed_policy_types()`.

Inherits shared interface lifecycle operations (deploy queuing, fabric validation, switch resolution) from
`NDBaseInterfaceOrchestrator` and adds vPC-specific functionality:

- Peer-serial auto-resolution: each create/update reads the per-switch `vpcPair` endpoint to obtain the peer
  serial, then injects it as `peerSwitchId` in the payload. Results are cached per orchestrator instance so
  bulk operations make at most one lookup per primary switch.
- Standard remove-based deletion (vPC interfaces are virtual and deletable).
- Fabric-wide `query_all()` filtered by `interfaceType: "vpc"` and per-type policy filtering.

A vPC interface spans two switches in a vPC pair; the user supplies one peer's management IP as `switch_ip`.
If the supplied switch is not in a vPC pair the orchestrator raises a clear `RuntimeError` instructing the
user to create the pair first via `nd_manage_vpc_pair`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import EpVpcPairGet
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import (
    EthernetMembershipIndex,
    MembershipValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    requires_bulk_support,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    BulkCreateGroupKey,
    BulkCreateItem,
    NDBaseInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)

ModelType = NDBaseModel


class VpcInterfaceBaseOrchestrator(NDBaseInterfaceOrchestrator[ModelType]):
    """
    # Summary

    Base orchestrator for vPC interface CRUD operations on Nexus Dashboard.

    Provides shared logic for all vPC interface types. Subclasses must set `model_class` and implement
    `_managed_policy_types()` to define which policy types they manage.

    Each create/update reads the `vpcPair` record for the primary switch to obtain the peer serial, which is
    then injected as `peerSwitchId` in the payload. Lookups are cached per orchestrator instance.

    Mutation methods (`create`, `update`) queue deploys for bulk execution. `delete` issues an immediate
    per-interface `DELETE /interfaces/{name}` (the bulk `interfaceActions/remove` endpoint rejects vPC interfaces;
    see the `TODO(4.2.1)` below) and queues a deploy. Call `deploy_pending` after all mutations are complete.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist, or is in deployment-freeze mode for a state
      that mutates configuration.
    - Via `_resolve_switch_id` if no switch matches the given IP in the fabric.
    - Via `_resolve_peer_switch_id` if the switch is not in a vPC pair.
    - Via `create` if the create API request fails.
    - Via `update` if the update API request fails.
    - Via `remove_pending` if the bulk remove API request fails.
    - Via `deploy_pending` if the bulk deploy API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    """

    # TODO(4.2.1) vpc-interface-bulk-delete-silent-fail
    # The bulk `/api/v1/manage/fabrics/{fabric}/interfaceActions/remove` endpoint returns
    # `{"status":"Failed","message":"Invalid Interface"}` inside a 207 for vPC interfaces (lab-verified). The
    # per-interface `DELETE /interfaces/{name}` endpoint works (returns 204). We therefore disable bulk delete and
    # use the per-interface DELETE via `delete_endpoint`.
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = False

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = None

    def model_post_init(self, __context) -> None:
        """
        # Summary

        Initialize mutable private state. Extends `NDBaseInterfaceOrchestrator.model_post_init` with a
        per-instance peer-serial cache so bulk operations make at most one `vpcPair` GET per primary switch.

        ## Raises

        None
        """
        super().model_post_init(__context)
        self._peer_serial_cache: dict[str, str] = {}
        self._peer_echo_cache: dict[str, str] = {}
        self._preview_scoped_child_switches: dict[tuple[str, str], set[str]] = {}

    def _register_pending_preview_derived_identities(
        self,
        result: ResponseType,
        pairs: list[tuple[str, str]],
    ) -> set[tuple[str, str]]:
        """Retain exact pair scope when ND omits one peer's child preview.

        ND 4.3.1 can return an exact two-row vPC preview where the primary row
        contains the pending generated port-channel/member CLI while the peer
        row says the interface is not discovered and has zero pending lines.
        The subsequent 207 deploy nevertheless reports generated children for
        both peers. Keep ordinary row-scoped child registration unchanged, but
        remember the exact reciprocal switch set proven by that structurally
        valid parent preview. An unregistered canonical child on that pair can
        then be treated as insufficient evidence and must pass the ordinary
        exact post-deploy preview; it is never accepted from the 207 alone.
        """

        # TODO(4.3.1) vpc-preview-omits-peer-pending-child-cli
        processed = super()._register_pending_preview_derived_identities(result, pairs)
        originals = {
            normalized: (name, switch_id) for name, switch_id in pairs if (normalized := self._normalized_interface_pair(name, switch_id)) is not None
        }
        for parent in processed:
            original = originals.get(parent)
            if original is None:
                continue
            verification_pairs = self._preview_verification_pairs([original])
            switch_ids = {
                normalized[1] for name, switch_id in verification_pairs if (normalized := self._normalized_interface_pair(name, switch_id)) is not None
            }
            if len(switch_ids) == 2:
                self._preview_scoped_child_switches[parent] = switch_ids
        return processed

    def _preview_scoped_unregistered_child_requires_verification(
        self,
        pair: tuple[str, str],
        submitted_pairs: list[tuple[str, str]],
    ) -> bool:
        """Force post-deploy preview for canonical children on an exact vPC pair."""

        if not self._is_canonical_deploy_child_name(pair[0]):
            return False
        for interface_name, switch_id in submitted_pairs:
            parent = self._normalized_interface_pair(interface_name, switch_id)
            if parent is not None and pair[1] in self._preview_scoped_child_switches.get(parent, set()):
                return True
        return False

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Run the shared interface preflight, then reject two unsafe ownership shapes before any mutation:

        - A config that lists the same `interface_name` under both peers of one vPC pair. With the composite
          `(switch_ip, interface_name)` identity (issue #356), those two proposed items target one ND resource.
        - A proposed physical member that current ND intent assigns to another port-channel/vPC, or that another vPC in the same task
          also claims. ND otherwise rejects the create only after the POST reaches the controller (issue #533 IFACE-006).

        Every proposed item resolves both sides of its vPC pair before any mutation. This reconciles the authoritative ``vpcPair``
        records with any peer identity echoed by interface inventory. Member-bearing items additionally read each pair member's
        already paginated/cached interface inventory once.

        ## Raises

        ### RuntimeError

        - If two (or more) proposed items share an `interface_name` and resolve to the same vPC pair.
        - If a proposed member is already owned by another parent, has inconsistent current member evidence, or is claimed by two
          proposed vPCs in the same task.
        - Propagated from `super().preflight` / `_resolve_switch_id` / `_resolve_peer_switch_id` (unresolvable switch, missing pair).
        """
        super().preflight(model_instances)
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._resolve_reciprocal_peer_switch_id(model_instance.switch_ip, switch_id)
        items_by_name: dict[str, list[ModelType]] = {}
        for model_instance in model_instances:
            items_by_name.setdefault(model_instance.interface_name, []).append(model_instance)
        offenders: list[str] = []
        for name, items in items_by_name.items():
            if len(items) < 2:
                continue
            switch_ips_by_pair: dict[frozenset[str], list[str]] = {}
            for item in items:
                switch_id = self._resolve_switch_id(item.switch_ip)
                peer_serial = self._resolve_reciprocal_peer_switch_id(item.switch_ip, switch_id)
                switch_ips_by_pair.setdefault(frozenset({switch_id, peer_serial}), []).append(item.switch_ip)
            for switch_ips in switch_ips_by_pair.values():
                if len(switch_ips) > 1:
                    offenders.append(
                        f"{name} is listed for multiple peers ({', '.join(sorted(switch_ips))}) of the same vPC pair; list it once, under either peer"
                    )
        if offenders:
            raise RuntimeError(f"Invalid vPC config in fabric '{self.fabric_name}': " + "; ".join(sorted(offenders)))
        self._validate_members_available(model_instances)

    @staticmethod
    def _proposed_peer_members(
        model_instance: ModelType,
    ) -> tuple[tuple[int, tuple[str, ...]], ...]:
        """Return the non-empty, per-peer physical-member lists from one proposal."""

        config_data = getattr(model_instance, "config_data", None)
        network_os = getattr(config_data, "network_os", None) if config_data is not None else None
        policy = getattr(network_os, "policy", None) if network_os is not None else None
        if policy is None:
            return ()
        proposed: list[tuple[int, tuple[str, ...]]] = []
        for peer_number in (1, 2):
            members = getattr(policy, f"peer{peer_number}_member_ports", None) or []
            normalized = tuple(member for member in members if isinstance(member, str) and member)
            if normalized:
                proposed.append((peer_number, normalized))
        return tuple(proposed)

    @staticmethod
    def _claim_matches_target_vpc(claim, *, parent_name: str, peer_switch_id: str) -> bool:
        """Return whether an existing claim is the same pair-scoped vPC parent."""

        if claim.interface_type != "vpc" or claim.interface_name.lower() != parent_name.lower():
            return False
        config_data = claim.record.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}
        declared_peer = policy.get("peerSwitchId")
        return declared_peer in (None, "", peer_switch_id)

    def _validate_members_available(self, model_instances: Sequence[ModelType]) -> None:
        """Reject physical members already owned by another parent.

        Proposed ``peer1`` members are scoped to the configured ``switch_ip``;
        proposed ``peer2`` members are scoped to its authoritative vPC peer.
        Existing ownership comes from ``EthernetMembershipIndex``, so reciprocal
        parent orientation and switch-local interface-name reuse follow the same
        fail-closed rules as standalone member updates.
        """

        proposals: list[tuple[ModelType, str, str, tuple[tuple[int, tuple[str, ...]], ...]]] = []
        pair_indexes: dict[frozenset[str], EthernetMembershipIndex] = {}
        for model_instance in model_instances:
            peer_members = self._proposed_peer_members(model_instance)
            if not peer_members:
                continue
            primary_switch_id = self._resolve_switch_id(model_instance.switch_ip)
            peer_switch_id = self._resolve_reciprocal_peer_switch_id(model_instance.switch_ip, primary_switch_id)
            proposals.append((model_instance, primary_switch_id, peer_switch_id, peer_members))

            pair_key = frozenset({primary_switch_id, peer_switch_id})
            if pair_key in pair_indexes:
                continue
            try:
                pair_indexes[pair_key] = EthernetMembershipIndex(
                    {
                        primary_switch_id: self._switch_interfaces(primary_switch_id),
                        peer_switch_id: self._switch_interfaces(peer_switch_id),
                    },
                    peer_switch_ids={
                        primary_switch_id: peer_switch_id,
                        peer_switch_id: primary_switch_id,
                    },
                )
            except MembershipValidationError as exc:
                raise RuntimeError(f"Cannot validate vPC member ownership for pair {sorted(pair_key)!r} " f"in fabric '{self.fabric_name}': {exc}") from exc

        conflicts: list[str] = []
        task_claims: dict[tuple[str, str], tuple[frozenset[str], str]] = {}
        for (
            model_instance,
            primary_switch_id,
            peer_switch_id,
            peer_members,
        ) in proposals:
            pair_key = frozenset({primary_switch_id, peer_switch_id})
            membership_index = pair_indexes[pair_key]
            parent_name = model_instance.interface_name
            switches_by_peer = {1: primary_switch_id, 2: peer_switch_id}
            peer_by_switch = {
                primary_switch_id: peer_switch_id,
                peer_switch_id: primary_switch_id,
            }
            target_identity = (pair_key, parent_name.lower())

            for peer_number, members in peer_members:
                switch_id = switches_by_peer[peer_number]
                for member_name in members:
                    member_key = (switch_id, member_name.lower())
                    prior_target = task_claims.get(member_key)
                    if prior_target is not None and prior_target != target_identity:
                        conflicts.append(
                            f"(switch_id={switch_id}, vPC={parent_name}, member={member_name}, " f"also claimed by proposed vPC={prior_target[1]})"
                        )
                    else:
                        task_claims[member_key] = target_identity

                    claims = membership_index.claiming_parents(switch_id, member_name)
                    foreign_claims = [
                        claim
                        for claim in claims
                        if not self._claim_matches_target_vpc(
                            claim,
                            parent_name=parent_name,
                            peer_switch_id=peer_by_switch[switch_id],
                        )
                    ]
                    if foreign_claims:
                        owners = sorted({f"{claim.interface_name} ({claim.policy_type or claim.interface_type})" for claim in foreign_claims})
                        conflicts.append(f"(switch_id={switch_id}, vPC={parent_name}, member={member_name}, " f"current owner={', '.join(owners)})")
                        continue

                    current_member = membership_index.get_member(switch_id, member_name)
                    if current_member is None:
                        continue
                    try:
                        ownership = membership_index.validate(switch_id, member_name)
                    except MembershipValidationError as exc:
                        conflicts.append(
                            f"(switch_id={switch_id}, vPC={parent_name}, member={member_name}, " f"current member ownership is inconsistent: {exc})"
                        )
                        continue
                    if (
                        ownership.owner.interface_name.lower() != parent_name.lower()
                        or ownership.peer_owner is None
                        or ownership.peer_owner.switch_id != peer_by_switch[switch_id]
                        or ownership.peer_owner.interface_name.lower() != parent_name.lower()
                    ):
                        conflicts.append(
                            f"(switch_id={switch_id}, vPC={parent_name}, member={member_name}, " f"current owner={ownership.owner.interface_name})"
                        )

        if conflicts:
            raise RuntimeError(
                f"Cannot configure vPC member(s) already in use or inconsistently owned in fabric "
                f"'{self.fabric_name}': {'; '.join(conflicts)}. Remove each member from its current parent first."
            )

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the set of API-side policy type values managed by this orchestrator. Subclasses must override this method
        to return their specific policy types (e.g., `{"accessVpcHost"}` for the access orchestrator).

        ## Raises

        ### NotImplementedError

        - Always, if not overridden by a subclass.
        """
        raise NotImplementedError("Subclasses must implement _managed_policy_types()")

    def _resolve_peer_switch_id(self, switch_ip: str, primary_serial: str) -> str:
        """
        # Summary

        Resolve one switch's declared peer serial from its authoritative
        ``vpcPair`` endpoint. Cache only that directed observation; a one-sided
        record is not evidence for the reverse relation.

        ## Raises

        ### RuntimeError

        - If the switch is not in a vPC pair (the `vpcPair` GET returns 404 / empty body).
        - If the `vpcPair` GET returns success but omits `peerSwitchId`.
        """
        cached = self._peer_serial_cache.get(primary_serial)
        if cached:
            return cached

        peer_serial = self._fetch_peer_switch_id(switch_ip, primary_serial)
        self._peer_serial_cache[primary_serial] = peer_serial
        return peer_serial

    def _resolve_reciprocal_peer_switch_id(self, switch_ip: str, primary_serial: str) -> str:
        """Require authoritative, reciprocal endpoint evidence for a vPC pair."""

        peer_serial = self._resolve_peer_switch_id(switch_ip, primary_serial)
        reciprocal_serial = self._resolve_peer_switch_id(peer_serial, peer_serial)
        if reciprocal_serial != primary_serial:
            raise RuntimeError(
                f"vPC pair identity is not reciprocal for switch {switch_ip} (serial {primary_serial}): "
                f"primary reports {peer_serial!r}, but that peer reports {reciprocal_serial!r}"
            )
        return peer_serial

    def _validate_peer_evidence(self, switch_id: str, peer_switch_id: str, *, record_echo: bool = False) -> None:
        """Reject directed peer evidence that cannot form one reciprocal pair.

        Interface rows are only evidence for the switch that returned them. Do
        not manufacture the reverse relation from a one-sided echo; retain each
        directed observation independently and reconcile it when the peer row
        or authoritative pair endpoints are available.
        """

        outgoing = self._peer_echo_cache.get(switch_id)
        reverse_outgoing = self._peer_echo_cache.get(peer_switch_id)
        incoming_to_switch = {source for source, target in self._peer_echo_cache.items() if target == switch_id}
        incoming_to_peer = {source for source, target in self._peer_echo_cache.items() if target == peer_switch_id}
        if (
            outgoing not in (None, peer_switch_id)
            or reverse_outgoing not in (None, switch_id)
            or not incoming_to_switch.issubset({peer_switch_id})
            or not incoming_to_peer.issubset({switch_id})
        ):
            raise RuntimeError(
                f"vPC peer identity for switch {switch_id!r} and peer {peer_switch_id!r} conflicts with "
                f"interface inventory: outgoing={outgoing!r}, peer outgoing={reverse_outgoing!r}, "
                f"incoming={sorted(incoming_to_switch)!r}, peer incoming={sorted(incoming_to_peer)!r}"
            )
        if record_echo:
            self._peer_echo_cache[switch_id] = peer_switch_id

    def _fetch_peer_switch_id(self, switch_label: str, switch_id: str) -> str:
        """Fetch and validate one side of an authoritative vPC-pair relation."""

        api_endpoint = EpVpcPairGet()
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_id = switch_id
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        if not result:
            raise RuntimeError(
                f"Switch {switch_label} (serial {switch_id}) is not in a vPC pair; "
                f"create the pair via nd_manage_vpc_pair before configuring vPC interfaces."
            )
        returned_switch_id = result.get("switchId")
        if returned_switch_id not in (None, ""):
            if not isinstance(returned_switch_id, str) or returned_switch_id.strip() != switch_id:
                raise RuntimeError(f"vPC pair record requested for switch {switch_label} (serial {switch_id}) " f"declares switchId {returned_switch_id!r}")
        peer_serial = result.get("peerSwitchId")
        if not isinstance(peer_serial, str) or not peer_serial.strip():
            raise RuntimeError(f"vPC pair record for switch {switch_label} (serial {switch_id}) is missing 'peerSwitchId'; " f"received: {result!r}")
        peer_serial = peer_serial.strip()
        if peer_serial == switch_id:
            raise RuntimeError(f"vPC pair record for switch {switch_label} (serial {switch_id}) identifies the switch as its own peer")
        try:
            self._validate_peer_evidence(switch_id, peer_serial)
        except RuntimeError as exc:
            raise RuntimeError(
                f"Authoritative vPC pair identity for switch {switch_label} (serial {switch_id}) "
                f"conflicts with interface inventory: endpoint reports {peer_serial!r}: {exc}"
            ) from exc
        return peer_serial

    def _preview_verification_pairs(self, pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
        """Expand each submitted vPC identity to its exact two-switch preview pair.

        ND deploy accepts one switch-scoped vPC parent identity but its preview
        reports convergence for both parent copies. Use cached peer evidence from
        create/update when available; after delete, resolve the still-existing
        switch pair directly because the interface record itself is gone.
        """

        expanded: list[tuple[str, str]] = []
        for interface_name, switch_id in pairs:
            peer_switch_id = self._peer_serial_cache.get(switch_id)
            if peer_switch_id is None:
                peer_switch_id = self._resolve_reciprocal_peer_switch_id(switch_id, switch_id)
            for pair in ((interface_name, switch_id), (interface_name, peer_switch_id)):
                if pair not in expanded:
                    expanded.append(pair)
        return expanded

    def _pending_deploy_pairs(self, pairs: list[tuple[str, str]], pending_pairs: set[tuple[str, str]]) -> list[tuple[str, str]]:
        """A pending preview on either vPC peer requires the submitted parent deploy."""

        return [pair for pair in pairs if any(self._normalized_interface_pair(*peer) in pending_pairs for peer in self._preview_verification_pairs([pair]))]

    def _prepare_deploy_context(self, model_instance: ModelType, switch_id: str) -> None:
        """Require exact preview-derived child identities for a vPC deploy."""

        if not self.deploy:
            return
        self._resolve_reciprocal_peer_switch_id(model_instance.switch_ip, switch_id)
        # Controller echoes can use pair-wide or switch-local peer-slot order.
        # A parent-scoped preview is the only unambiguous source for the exact
        # switch identity of generated port-channel/member result rows.
        self._queue_preview_derived_discovery(model_instance.interface_name, switch_id)

    def _prepare_no_diff_deploy_context(self, model_instance: ModelType, switch_id: str) -> None:
        """Discover pending switch-side children when unchanged vPC intent has none."""

        if self.deploy:
            self._queue_preview_derived_discovery(model_instance.interface_name, switch_id)

    def _inject_peer_switch_id(self, payload: dict, peer_serial: str) -> dict:
        """
        # Summary

        Inject `peerSwitchId` into the nested `configData.networkOS.policy` block of an interface payload. Every vPC
        interface requires a peer serial, so a payload without a `policy` block is structurally invalid and is rejected
        here rather than silently sent to ND as a one-sided vPC.

        ## Raises

        ### RuntimeError

        - If the payload has no `configData.networkOS.policy` block to inject `peerSwitchId` into.
        """
        policy = (payload.get("configData") or {}).get("networkOS", {}).get("policy")
        if policy is None:
            raise RuntimeError(
                f"vPC interface payload is missing the 'configData.networkOS.policy' block required to inject 'peerSwitchId'; received: {payload!r}"
            )
        policy["peerSwitchId"] = peer_serial
        return payload

    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Create a vPC interface configuration. Resolves `switch_ip` to a primary serial, resolves the peer serial via
        the vPC pair record, injects both into the payload, and POSTs the wrapped `interfaces` array. Queues a deploy
        for later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the create API request fails.
        - If the primary switch is not in a vPC pair.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            peer_serial = self._resolve_reciprocal_peer_switch_id(model_instance.switch_ip, switch_id)
            api_endpoint = self._configure_endpoint(self.create_endpoint(), switch_sn=switch_id)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            self._inject_peer_switch_id(payload, peer_serial)
            request_body = {"interfaces": [payload]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=request_body)
            self._prepare_deploy_context(model_instance, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Update a vPC interface configuration. Resolves `switch_ip` to a primary serial, resolves the peer serial via
        the vPC pair record, injects both into the payload, and PUTs the updated configuration. Queues a deploy for
        later bulk execution via `deploy_pending`.

        ## Raises

        ### RuntimeError

        - If the update API request fails.
        - If the primary switch is not in a vPC pair.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            peer_serial = self._resolve_reciprocal_peer_switch_id(model_instance.switch_ip, switch_id)
            previous_model = kwargs.get("previous_model")
            if previous_model is not None:
                self._prepare_deploy_context(previous_model, switch_id)
                if not self._proposed_peer_members(previous_model) and not self._proposed_peer_members(model_instance):
                    self._queue_preview_derived_discovery(model_instance.interface_name, switch_id)
            api_endpoint = self._configure_endpoint(self.update_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            payload = model_instance.to_payload()
            payload["switchId"] = switch_id
            self._inject_peer_switch_id(payload, peer_serial)
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
            self._prepare_deploy_context(model_instance, switch_id)
            self._queue_deploy(model_instance.interface_name, switch_id)
            return result
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> None:
        """
        # Summary

        Delete a vPC interface immediately via the per-interface `DELETE /interfaces/{name}` endpoint, then queue
        a deploy for later bulk execution via `deploy_pending`. The DELETE returns 204 on success; a subsequent GET
        returns 404. The deploy pushes the removal to both peers and reverts member interfaces to their fabric
        default configuration.

        ## Raises

        ### RuntimeError

        - If the DELETE API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            # Delete is not routed through the ordinary create/update preflight.
            # Require reciprocal authoritative pair evidence here before the
            # controller receives the mutation.
            self._resolve_reciprocal_peer_switch_id(model_instance.switch_ip, switch_id)
            api_endpoint = self._configure_endpoint(self.delete_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            self._prepare_deploy_context(model_instance, switch_id)
            if not self._proposed_peer_members(model_instance):
                self._queue_preview_derived_discovery(model_instance.interface_name, switch_id)
            self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            self._queue_deploy(model_instance.interface_name, switch_id)
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    @requires_bulk_support("supports_bulk_create")
    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple vPC interfaces in bulk. Groups by primary switch and policy type, resolves the peer serial once per group,
        and sends one POST per group with all vPC interfaces in the `interfaces` array. Uses the shared interface partial-create
        recovery so every vPC explicitly accepted from a mixed response is queued for failure-path deployment.

        ## Raises

        ### RuntimeError

        - If any create API request fails.
        - If any primary switch is not in a vPC pair.
        """
        try:
            groups: dict[BulkCreateGroupKey, list[BulkCreateItem]] = {}
            for model_instance in model_instances:
                switch_id = self._resolve_switch_id(model_instance.switch_ip)
                peer_serial = self._resolve_reciprocal_peer_switch_id(model_instance.switch_ip, switch_id)
                payload = model_instance.to_payload()
                payload["switchId"] = switch_id
                self._inject_peer_switch_id(payload, peer_serial)
                self._prepare_deploy_context(model_instance, switch_id)
                group_key = BulkCreateGroupKey(
                    switch_id=switch_id,
                    policy_type=self._desired_policy_type(model_instance),
                )
                groups.setdefault(group_key, []).append(
                    BulkCreateItem(
                        interface_name=model_instance.interface_name,
                        payload=payload,
                    )
                )

            results = []
            for group_key, items in groups.items():
                results.append(self._post_bulk_create_group(group_key, items))
            return results
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single vPC interface by name on a specific switch.

        ## Raises

        ### RuntimeError

        - If the query API request fails.
        """
        try:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            api_endpoint = self._configure_endpoint(self.query_one_endpoint(), switch_sn=switch_id)
            api_endpoint.set_identifiers(model_instance.interface_name)
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def _configured_switch_ips_by_interface_name(self) -> dict[str, set[str]]:
        """
        # Summary

        Map each config `interface_name` to the set of user-supplied `switch_ip` values. A vPC interface spans two peers and ND returns
        it on both; `query_all` uses this to keep the peer copy whose IP the user actually configured, so the existing state's composite
        identifier `(switch_ip, interface_name)` matches the proposed identifier and the run stays idempotent regardless of which peer
        the user names. A set (not a single IP) because the same name may legally appear on multiple pairs (issue #356). Keys are
        canonical (lowercase) names — see `_canonical_interface_name`.

        ## Raises

        None
        """
        mapping: dict[str, set[str]] = {}
        for item in self.rest_send.params.get("config") or []:
            name = item.get("interface_name")
            switch_ip = item.get("switch_ip")
            if name and switch_ip:
                mapping.setdefault(self._canonical_interface_name(name), set()).add(switch_ip)
        return mapping

    @staticmethod
    def _canonical_interface_name(name: str) -> str:
        """
        # Summary

        Return the canonical (lowercase) form of a vPC interface name. The vPC models lowercase `interface_name` on validation
        (`VPC501` -> `vpc501`, matching what ND echoes), but `query_all` reads the user config raw from `rest_send.params`, so both
        the configured names and the response names must pass through this one canonicalizer before they are compared; otherwise a
        mixed-case config never matches its own echo and the dedup falls back to the wrong peer (PR #411 review).

        ## Raises

        None
        """
        return name.lower()

    @staticmethod
    def _policy_type(iface: dict) -> str | None:
        """
        # Summary

        Return `configData.networkOS.policy.policyType` for an interface dict, tolerating a missing or null value at
        any level of the nested chain (ND occasionally returns `configData: null`).

        ## Raises

        None
        """
        config_data = iface.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}
        return policy.get("policyType")

    def _pair_key(self, iface: dict, switch_ip: str, switch_id: str) -> frozenset[str]:
        """
        # Summary

        Return the unordered vPC pair discriminator for an interface record: `frozenset({switchId, peerSwitchId})`. The two peer copies
        of one vPC interface carry the same set (only the orientation swaps), while same-name interfaces on different pairs carry
        disjoint sets (issue #356).

        When the echo omits `peerSwitchId` (the OpenAPI schema does not mark it required, so this is a schema-valid shape) the peer is
        resolved from the authoritative `vpcPair` endpoint via `_resolve_peer_switch_id` (cached per switch, so the degraded path costs
        at most one extra GET per switch). A per-switch singleton key is NOT an acceptable fallback: if even one of the two peer echoes
        lacked the field, the copies would key on `{A}` vs `{A, B}`, both would survive dedup, and `state: overridden` would delete the
        pair-wide interface through the "unconfigured" peer (PR #411 review). If the pair cannot be resolved, this raises and
        `query_all` fails closed before any override deletion can be computed.

        ## Raises

        ### RuntimeError

        - Propagated from `_resolve_peer_switch_id` when `peerSwitchId` is absent and the switch is not in a vPC pair (or the
          `vpcPair` record itself omits `peerSwitchId`).
        """
        config_data = iface.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}
        raw_peer_switch_id = policy.get("peerSwitchId")
        if raw_peer_switch_id in (None, ""):
            peer_switch_id = self._resolve_peer_switch_id(switch_ip, switch_id)
        else:
            if not isinstance(raw_peer_switch_id, str) or not raw_peer_switch_id.strip():
                raise RuntimeError(f"vPC interface {iface.get('interfaceName')!r} on switch {switch_id!r} has an invalid peerSwitchId")
            peer_switch_id = raw_peer_switch_id.strip()
            if peer_switch_id == switch_id:
                raise RuntimeError(f"vPC interface {iface.get('interfaceName')!r} on switch {switch_id!r} identifies itself as its peer")
            authoritative_peer = self._peer_serial_cache.get(switch_id)
            if authoritative_peer is not None and peer_switch_id != authoritative_peer:
                raise RuntimeError(
                    f"vPC interface {iface.get('interfaceName')!r} peerSwitchId {peer_switch_id!r} conflicts with "
                    f"the authoritative vpcPair peer {authoritative_peer!r} for switch {switch_id!r}"
                )
            try:
                self._validate_peer_evidence(switch_id, peer_switch_id, record_echo=True)
            except RuntimeError as exc:
                raise RuntimeError(f"vPC interface {iface.get('interfaceName')!r} has non-reciprocal peer identity: {exc}") from exc
        return frozenset({switch_id, peer_switch_id})

    def _managed_vpc_interfaces(self, switch_ip: str, switch_id: str, managed_types: set[str]) -> list[dict]:
        """
        # Summary

        Read one switch's complete shared interface inventory and return the vPC interfaces whose policy type this orchestrator manages,
        each enriched with the `switchIp` of the switch it was read from. The shared reader paginates, validates identities, and publishes
        its cache only after the full collection succeeds.

        ## Raises

        ### Exception

        - If the paginated interface-list request or completeness validation fails (propagated to `query_all`'s wrapper).
        """
        interfaces = self._switch_interfaces(switch_id).values()
        managed = [dict(iface) for iface in interfaces if iface.get("interfaceType") == "vpc" and self._policy_type(iface) in managed_types]
        for iface in managed:
            iface["switchIp"] = switch_ip
        return managed

    def query_all(self, model_instance: ModelType | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query interfaces, filtering for vPC interfaces with policy types managed by
        this orchestrator (as defined by `_managed_policy_types()`).

        The set of switches queried is determined by `_switches_to_query`: fabric-wide for `state: overridden`, and
        limited to switches named in the user config for all other states.

        Runs `validate_prerequisites` on first call to ensure the fabric exists and is modifiable before returning any data.

        Each returned interface dict is enriched with a `switchIp` field so that the model can be constructed with the
        composite identifier `(switch_ip, interface_name)`.

        Dedup is keyed on `(interfaceName, frozenset({switchId, peerSwitchId}))`, not `interfaceName` alone, so that two vPC pairs in
        the same fabric may legally reuse the same vPC interface name (issue #356). An echo that omits `peerSwitchId` has its pair
        resolved from the `vpcPair` endpoint; if that fails the whole query fails closed (see `_pair_key`).

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode and the state mutates configuration.
        - If the query API request fails.
        - If an interface echo omits `peerSwitchId` and its switch's vPC pair cannot be resolved.
        """
        managed_types = self._managed_policy_types()
        try:
            self.validate_prerequisites()
            configured_ips_by_name = self._configured_switch_ips_by_interface_name()
            # TODO(4.2.1) vpc-interface-dual-peer-duplicate
            # ND returns each vPC interface TWICE — once per peer switch — with identical configData. Dedupe on
            # (interfaceName, frozenset({switchId, peerSwitchId})): one pair's two copies share the unordered set and
            # collapse, while same-name interfaces on DIFFERENT pairs have disjoint sets and stay distinct (two pairs
            # may legally reuse a vPC id — the vpcId pool is devicePair-scoped; issue #356). When the interface is in
            # the user config, keep the peer whose switchIp the user supplied so idempotency holds regardless of which
            # peer they name; otherwise keep the alphabetically-lower switchId for a stable representative. Names are
            # canonicalized (lowercase) on both sides so a mixed-case config still matches its echo. Without this
            # dedupe, `_manage_override_deletions` would see the peer-side copy as "not in proposed" and queue a
            # spurious delete.
            interfaces_by_key: dict[tuple[str, frozenset[str]], tuple[str, dict]] = {}
            for switch_ip, switch_id in self._switches_to_query().items():
                for iface in self._managed_vpc_interfaces(switch_ip, switch_id, managed_types):
                    raw_name = iface.get("interfaceName")
                    if raw_name is None:
                        continue
                    name = self._canonical_interface_name(raw_name)
                    key = (name, self._pair_key(iface, switch_ip, switch_id))
                    existing = interfaces_by_key.get(key)
                    if self._prefers_candidate(name, switch_id, switch_ip, existing, configured_ips_by_name):
                        interfaces_by_key[key] = (switch_id, iface)
            return [entry[1] for entry in interfaces_by_key.values()]
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    @staticmethod
    def _prefers_candidate(
        name: str,
        switch_id: str,
        switch_ip: str,
        existing: tuple[str, dict] | None,
        configured_ips_by_name: dict[str, set[str]],
    ) -> bool:
        """
        # Summary

        Decide whether a newly-seen per-peer copy of a vPC interface should replace the one already kept for its dedup key. Prefer the
        peer whose `switch_ip` the user configured (idempotency); when neither peer is the configured one (or the interface is not in
        config, e.g. an `overridden` deletion candidate), prefer the alphabetically-lower `switch_id` for a stable representative. The
        two candidates for one key are always the two peers of one pair (issue #356 keys dedup on the unordered pair set).

        ## Raises

        None
        """
        if existing is None:
            return True
        configured_ips = configured_ips_by_name.get(name, set())
        if configured_ips:
            if switch_ip in configured_ips:
                return True
            if existing[1].get("switchIp") in configured_ips:
                return False
        return switch_id < existing[0]
