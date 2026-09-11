# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Controller-independent ethernet membership ownership validation.

``EthernetMembershipIndex`` consumes interface inventories that have already been
fetched and cached by an orchestrator.  It never sends a REST request.  This keeps
membership validation reusable by both the standalone ethernet orchestrators and
the interface aggregator without adding a per-interface discovery cost.

The index deliberately fails closed.  A member update is safe only when its exact
member-policy descriptor agrees with one unambiguous parent, the configured and
operational port-channel identities do not conflict, and every required parent
membership reference is internally consistent.  vPC members additionally require
reciprocal evidence from both peers' cached inventories.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, TypeAlias

from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    MemberPolicyDescriptor,
    MemberPolicyDisposition,
    classify_member_policy,
    get_member_policy_descriptor,
    normalize_port_channel_id,
    parse_member_interface_response,
    policy_type_from_interface_record,
)

MemberKey: TypeAlias = tuple[str, str]
InterfaceRecord: TypeAlias = Mapping[str, Any]
SwitchInventory: TypeAlias = Mapping[str, InterfaceRecord]
InterfaceInventories: TypeAlias = Mapping[str, SwitchInventory]

VpcParentSignature: TypeAlias = tuple[
    str,
    str,
    str,
    tuple[Any, ...],
]
_LOCAL_PARENT_MEMBER_FIELDS = (
    "ports",
    "peer1MemberPorts",
    "peer2MemberPorts",
)


class MembershipValidationError(ValueError):
    """Raised when cached inventory cannot prove one safe member owner."""


class MissingPeerInventoryError(MembershipValidationError):
    """Raised when pair-aware validation needs a peer inventory not yet cached."""

    def __init__(self, peer_switch_id: str) -> None:
        self.peer_switch_id = peer_switch_id
        super().__init__(f"Pair-aware membership validation requires cached interface inventory " f"for peer switch {peer_switch_id!r}")


class MissingPeerIdentityError(MembershipValidationError):
    """Raised when a vPC parent omits its peer and cached evidence is insufficient."""

    def __init__(self, switch_id: str, parent_name: str) -> None:
        self.switch_id = switch_id
        self.parent_name = parent_name
        super().__init__(
            f"Pair-aware membership validation cannot resolve the peer for vPC "
            f"parent {parent_name!r} on switch {switch_id!r} from cached inventory "
            "or pair evidence"
        )


@dataclass(frozen=True)
class IndexedEthernetMember:
    """One member-policy interface found in the supplied inventories."""

    switch_id: str
    interface_name: str
    policy_type: str
    disposition: MemberPolicyDisposition
    descriptor: MemberPolicyDescriptor | None
    record: InterfaceRecord

    @property
    def key(self) -> MemberKey:
        """Return the canonical index key."""

        return self.switch_id, self.interface_name.lower()


@dataclass(frozen=True)
class MemberOwner:
    """Validated parent metadata for one member on one switch."""

    switch_id: str
    interface_name: str
    interface_type: str
    policy_type: str
    port_channel_id: int
    claim_fields: tuple[str, ...]
    record: InterfaceRecord


@dataclass(frozen=True)
class ValidatedMemberOwnership:
    """Proof that a member's cached ownership is safe for an in-place update."""

    member: IndexedEthernetMember
    owner: MemberOwner
    configured_port_channel_id: int
    operational_port_channel_id: int | None
    peer_owner: MemberOwner | None = None
    peer_members: tuple[IndexedEthernetMember, ...] = ()
    pair_validated: bool = False


@dataclass(frozen=True)
class _ParentClaim:
    """Internal representation of a parent record that names a member."""

    switch_id: str
    interface_name: str
    interface_type: str
    policy_type: str | None
    claim_fields: tuple[str, ...]
    record: InterfaceRecord


@dataclass(frozen=True)
class _VpcParentCopy:
    """One valid, literal vPC parent signature used for O(1) peer inference."""

    switch_id: str
    signature: VpcParentSignature
    record: InterfaceRecord


@dataclass(frozen=True)
class _VpcParentSlot:
    """One literal peer slot from a vPC parent's pair-wide configuration."""

    number: int
    port_channel_id: int
    member_names: frozenset[str]
    fingerprint: tuple[Any, ...]

    @property
    def member_field(self) -> str:
        """Return the ND policy key that names this slot's members."""

        return f"peer{self.number}MemberPorts"


@dataclass(frozen=True)
class _ValidatedVpcSlotMember:
    """One vPC member whose configured, operational, and parent evidence agrees."""

    member: IndexedEthernetMember
    configured_port_channel_id: int
    operational_port_channel_id: int | None


@dataclass(frozen=True)
class _ValidatedVpcParentPair:
    """Cached pair-wide ownership proof for every member of one vPC parent."""

    results: Mapping[MemberKey, ValidatedMemberOwnership]


class EthernetMembershipIndex:
    """Index and validate ethernet members from already-cached inventories.

    ``inventories`` has the same shape as the interface orchestrator cache:
    ``{switch_id: {lower_interface_name: raw_interface_record}}``.  The mapping
    keys are treated as lookup hints; canonical keys come from each record's
    ``interfaceName`` and the enclosing switch serial.
    """

    def __init__(
        self,
        inventories: InterfaceInventories,
        *,
        peer_switch_ids: Mapping[str, str] | None = None,
    ) -> None:
        self._inventories: dict[str, dict[str, InterfaceRecord]] = {}
        self._members: dict[MemberKey, IndexedEthernetMember] = {}
        self._vpc_members_by_parent: dict[MemberKey, tuple[IndexedEthernetMember, ...]] = {}
        self._claims: dict[MemberKey, tuple[_ParentClaim, ...]] = {}
        self._peer_switch_ids = self._normalize_peer_switch_ids(peer_switch_ids)
        self._vpc_parents_by_signature: dict[VpcParentSignature, tuple[_VpcParentCopy, ...]] = {}
        self._vpc_peer_cache: dict[tuple[str, str], str] = {}
        self._vpc_pair_validation_cache: dict[tuple[tuple[str, str], str, str], _ValidatedVpcParentPair] = {}
        self._validation_cache: dict[MemberKey, ValidatedMemberOwnership] = {}
        self._build(inventories)

    @property
    def members(self) -> Mapping[MemberKey, IndexedEthernetMember]:
        """Return the indexed member records keyed by serial and lower-case name."""

        return MappingProxyType(self._members)

    @property
    def member_keys(self) -> tuple[MemberKey, ...]:
        """Return canonical member keys in deterministic order."""

        return tuple(sorted(self._members))

    def get_member(self, switch_id: str, interface_name: str) -> IndexedEthernetMember | None:
        """Return one indexed member, or ``None`` for a non-member/missing record."""

        return self._members.get(self._key(switch_id, interface_name))

    def require_member(self, switch_id: str, interface_name: str) -> IndexedEthernetMember:
        """Return one indexed member or raise a closed ownership error."""

        member = self.get_member(switch_id, interface_name)
        if member is None:
            raise MembershipValidationError(f"Interface {interface_name!r} on switch {switch_id!r} is not an " "indexed ethernet member")
        return member

    def validate(self, switch_id: str, interface_name: str) -> ValidatedMemberOwnership:
        """Validate and return ownership proof for one indexed member.

        Standalone port-channel membership requires only the target switch's
        inventory.  A vPC member requires both peer inventories and raises
        ``MissingPeerInventoryError`` with the exact missing serial when the
        orchestrator must populate another cached inventory before retrying.
        """

        key = self._key(switch_id, interface_name)
        cached = self._validation_cache.get(key)
        if cached is not None:
            return cached

        member = self.require_member(switch_id, interface_name)
        descriptor = member.descriptor
        if descriptor is None:
            raise MembershipValidationError(
                f"Interface {interface_name!r} on switch {switch_id!r} uses " f"protected or unsupported member policy {member.policy_type!r}"
            )

        if descriptor.pair_aware:
            claim = self._require_vpc_parent_claim(member)
            result = self._validate_vpc_pair(member=member, claim=claim)
        else:
            configured_id, operational_id = self._member_port_channel_ids(member)
            claim = self._require_single_claim(member)
            owner = self._validate_parent_claim(
                member,
                claim,
                configured_id,
                local_member_field=descriptor.parent_member_fields[0],
            )
            result = ValidatedMemberOwnership(
                member=member,
                owner=owner,
                configured_port_channel_id=configured_id,
                operational_port_channel_id=operational_id,
            )
        self._validation_cache[key] = result
        return result

    def _build(self, inventories: InterfaceInventories) -> None:
        if not isinstance(inventories, Mapping):
            raise TypeError("inventories must be a mapping keyed by switch serial")

        for switch_id, inventory in inventories.items():
            if not isinstance(switch_id, str) or not switch_id:
                raise MembershipValidationError(f"Inventory switch identifier must be a non-empty string; got {switch_id!r}")
            if not isinstance(inventory, Mapping):
                raise TypeError(f"Inventory for switch {switch_id!r} must be a mapping keyed by interface name")

            normalized_inventory: dict[str, InterfaceRecord] = {}
            for record in inventory.values():
                if not isinstance(record, Mapping):
                    raise TypeError(f"Interface inventory entry for switch {switch_id!r} must be a mapping")
                interface_name = record.get("interfaceName")
                if not isinstance(interface_name, str) or not interface_name:
                    raise MembershipValidationError(f"Interface inventory entry for switch {switch_id!r} lacks a valid interfaceName")
                record_switch_id = record.get("switchId")
                if record_switch_id is not None and record_switch_id != switch_id:
                    raise MembershipValidationError(
                        f"Interface {interface_name!r} is stored under switch {switch_id!r} " f"but its record declares switchId {record_switch_id!r}"
                    )

                normalized_name = interface_name.lower()
                if normalized_name in normalized_inventory:
                    raise MembershipValidationError(
                        f"Inventory for switch {switch_id!r} contains duplicate interface " f"name {interface_name!r} after case normalization"
                    )
                normalized_inventory[normalized_name] = record

                policy_type = policy_type_from_interface_record(record)
                disposition = classify_member_policy(policy_type)
                if disposition == MemberPolicyDisposition.NOT_MEMBER:
                    continue
                if not isinstance(policy_type, str) or not policy_type:
                    raise MembershipValidationError(
                        f"Interface {interface_name!r} on switch {switch_id!r} " "was classified as an ethernet member without a valid policyType"
                    )
                member = IndexedEthernetMember(
                    switch_id=switch_id,
                    interface_name=interface_name,
                    policy_type=policy_type,
                    disposition=disposition,
                    descriptor=get_member_policy_descriptor(policy_type),
                    record=record,
                )
                if member.key in self._members:
                    raise MembershipValidationError(f"Duplicate member index key {member.key!r}")
                self._members[member.key] = member
            self._inventories[switch_id] = normalized_inventory
        self._build_vpc_member_index()
        self._build_parent_claims()
        self._build_vpc_parent_index()

    def _build_vpc_member_index(self) -> None:
        """Index supported physical vPC members by switch and parent once.

        ND also labels the parent-side ``portChannel`` record with policies such as
        ``trunkVpcMember`` and ``accessVpcMember``.  Those protected records are not
        physical members and must not contaminate a vPC parent's member set.
        """

        mutable: dict[MemberKey, list[IndexedEthernetMember]] = {}
        for member in self._members.values():
            descriptor = member.descriptor
            if member.record.get("interfaceType") != "ethernet" or descriptor is None or not descriptor.pair_aware:
                continue
            policy = self._policy(member.record)
            parent_name = policy.get("primaryInterface") if policy is not None else None
            if not isinstance(parent_name, str) or not parent_name:
                continue
            mutable.setdefault((member.switch_id, parent_name.lower()), []).append(member)
        self._vpc_members_by_parent = {key: tuple(sorted(members, key=lambda item: item.interface_name.lower())) for key, members in mutable.items()}

    def _build_parent_claims(self) -> None:
        """Index every parent membership reference once for constant-time lookups."""

        mutable_claims: dict[MemberKey, list[_ParentClaim]] = {}
        for switch_id, inventory in self._inventories.items():
            for record in inventory.values():
                policy = self._policy(record)
                if policy is None:
                    continue
                claim_fields_by_member: dict[str, list[str]] = {}
                for field in _LOCAL_PARENT_MEMBER_FIELDS:
                    for member_name in self._normalized_member_names(policy.get(field)):
                        claim_fields_by_member.setdefault(member_name, []).append(field)
                if not claim_fields_by_member:
                    continue

                parent_name = record.get("interfaceName")
                interface_type = record.get("interfaceType")
                if not isinstance(parent_name, str) or not isinstance(interface_type, str):
                    raise MembershipValidationError(f"A parent membership record on switch {switch_id!r} lacks " "interfaceName or interfaceType")
                policy_type = policy_type_from_interface_record(record)
                for member_name, claim_fields in claim_fields_by_member.items():
                    key = (switch_id, member_name)
                    mutable_claims.setdefault(key, []).append(
                        _ParentClaim(
                            switch_id=switch_id,
                            interface_name=parent_name,
                            interface_type=interface_type,
                            policy_type=policy_type,
                            claim_fields=tuple(claim_fields),
                            record=record,
                        )
                    )
        self._claims = {key: tuple(claims) for key, claims in mutable_claims.items()}

    def _build_vpc_parent_index(self) -> None:
        """Index valid literal parent signatures once for constant-time peer inference."""

        mutable: dict[VpcParentSignature, list[_VpcParentCopy]] = {}
        for switch_id, inventory in self._inventories.items():
            for record in inventory.values():
                signature = self._optional_vpc_parent_signature(record)
                if signature is None:
                    continue
                mutable.setdefault(signature, []).append(
                    _VpcParentCopy(
                        switch_id=switch_id,
                        signature=signature,
                        record=record,
                    )
                )
        self._vpc_parents_by_signature = {signature: tuple(copies) for signature, copies in mutable.items()}

    @staticmethod
    def _normalize_peer_switch_ids(
        peer_switch_ids: Mapping[str, str] | None,
    ) -> dict[str, str]:
        """Validate optional authoritative vPC pair evidence and fail closed."""

        if peer_switch_ids is None:
            return {}
        if not isinstance(peer_switch_ids, Mapping):
            raise TypeError("peer_switch_ids must be a mapping of switch serials")
        normalized: dict[str, str] = {}
        owners_by_peer: dict[str, str] = {}
        for switch_id, peer_switch_id in peer_switch_ids.items():
            if not isinstance(switch_id, str) or not switch_id:
                raise MembershipValidationError(f"Pair evidence has invalid switch identifier {switch_id!r}")
            if not isinstance(peer_switch_id, str) or not peer_switch_id:
                raise MembershipValidationError(f"Pair evidence for switch {switch_id!r} has invalid peer " f"identifier {peer_switch_id!r}")
            if switch_id == peer_switch_id:
                raise MembershipValidationError(f"Pair evidence for switch {switch_id!r} points to itself")
            prior_owner = owners_by_peer.get(peer_switch_id)
            if prior_owner is not None and prior_owner != switch_id:
                raise MembershipValidationError(f"Pair evidence assigns peer {peer_switch_id!r} to both " f"{prior_owner!r} and {switch_id!r}")
            owners_by_peer[peer_switch_id] = switch_id
            normalized[switch_id] = peer_switch_id
        for switch_id, peer_switch_id in normalized.items():
            reciprocal = normalized.get(peer_switch_id)
            if reciprocal is not None and reciprocal != switch_id:
                raise MembershipValidationError(f"Pair evidence for {switch_id!r} and {peer_switch_id!r} " "is not reciprocal")
        return normalized

    @classmethod
    def _optional_vpc_parent_signature(cls, record: InterfaceRecord) -> VpcParentSignature | None:
        """Return a literal signature for a structurally valid vPC parent.

        ND preserves peer1/peer2 meaning in both switch-scoped echoes.  The record
        switchId and policy peerSwitchId reverse, but peer1*/peer2* fields do not.
        """

        if record.get("interfaceType") != "vpc":
            return None
        parent_name = record.get("interfaceName")
        policy = cls._policy(record)
        if not isinstance(parent_name, str) or not parent_name or policy is None:
            return None
        policy_type = policy.get("policyType")
        if not isinstance(policy_type, str):
            return None
        try:
            peer1_id = normalize_port_channel_id(policy.get("peer1PortChannelId"))
            peer2_id = normalize_port_channel_id(policy.get("peer2PortChannelId"))
        except ValueError:
            return None
        peer1_members = cls._normalized_member_names(policy.get("peer1MemberPorts"))
        peer2_members = cls._normalized_member_names(policy.get("peer2MemberPorts"))
        if peer1_id is None or peer2_id is None or not peer1_members or not peer2_members:
            return None
        fingerprint = cls._vpc_parent_fingerprint(record)
        if fingerprint is None:
            return None
        return (parent_name.lower(), "vpc", policy_type, fingerprint)

    def _required_vpc_parent_signature(self, record: InterfaceRecord, switch_id: str, parent_name: str) -> VpcParentSignature:
        """Return one target parent's literal signature with precise errors."""

        policy_type = policy_type_from_interface_record(record)
        if record.get("interfaceType") != "vpc" or not isinstance(policy_type, str):
            raise MembershipValidationError(f"Interface {parent_name!r} on switch {switch_id!r} is not a " "valid vPC parent")
        self._required_policy_port_channel_id(record, "peer1PortChannelId", parent_name=parent_name, switch_id=switch_id)
        self._required_policy_port_channel_id(record, "peer2PortChannelId", parent_name=parent_name, switch_id=switch_id)
        self._required_vpc_member_names(record, "peer1MemberPorts", switch_id, parent_name)
        self._required_vpc_member_names(record, "peer2MemberPorts", switch_id, parent_name)
        fingerprint = self._vpc_parent_fingerprint(record)
        if fingerprint is None:
            raise MembershipValidationError(f"vPC parent {parent_name!r} on switch {switch_id!r} lacks valid configData")
        return (parent_name.lower(), "vpc", policy_type, fingerprint)

    @classmethod
    def _vpc_parent_fingerprint(cls, record: InterfaceRecord) -> tuple[Any, ...] | None:
        """Return hashable pair-comparable configData with only echo metadata removed."""

        config_data = record.get("configData")
        if not isinstance(config_data, Mapping):
            return None
        frozen = cls._freeze_vpc_value(config_data)
        return frozen if isinstance(frozen, tuple) else None

    @classmethod
    def _freeze_vpc_value(cls, value: Any, *, field_name: str = "") -> Any:
        """Freeze JSON-like data while normalizing only vPC member-list presentation."""

        if isinstance(value, Mapping):
            ignored = {"switchId", "peerSwitchId", "policyId"}
            return tuple(
                sorted((key, cls._freeze_vpc_value(item, field_name=key)) for key, item in value.items() if isinstance(key, str) and key not in ignored)
            )
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            if field_name.endswith("MemberPorts") and all(isinstance(item, str) for item in value):
                return tuple(sorted(item.strip().lower() for item in value))
            return tuple(cls._freeze_vpc_value(item) for item in value)
        return value

    def _infer_vpc_peer_switch_id(self, switch_id: str, parent_name: str, record: InterfaceRecord) -> str | None:
        """Infer one peer from an identical literal cached parent signature."""

        signature = self._required_vpc_parent_signature(record, switch_id, parent_name)
        candidates: set[str] = set()
        for copy in self._vpc_parents_by_signature.get(signature, ()):
            if copy.switch_id == switch_id:
                continue
            candidate_policy = self._required_policy(copy.record)
            declared_peer = candidate_policy.get("peerSwitchId")
            if declared_peer not in (None, ""):
                if not isinstance(declared_peer, str) or declared_peer != switch_id:
                    continue
            candidates.add(copy.switch_id)
        if len(candidates) > 1:
            raise MembershipValidationError(
                f"Cannot resolve peer for vPC parent {parent_name!r} on switch "
                f"{switch_id!r}: reciprocal cached parent evidence is ambiguous "
                f"across {sorted(candidates)!r}"
            )
        return next(iter(candidates), None)

    def _resolve_vpc_peer_switch_id(self, switch_id: str, parent_name: str, record: InterfaceRecord) -> str:
        """Resolve a vPC peer without guessing, caching one result per parent copy."""

        cache_key = (switch_id, parent_name.lower())
        cached = self._vpc_peer_cache.get(cache_key)
        if cached is not None:
            return cached

        policy = self._required_policy(record)
        raw_declared = policy.get("peerSwitchId")
        if raw_declared in (None, ""):
            declared_peer = None
        elif not isinstance(raw_declared, str):
            raise MembershipValidationError(f"vPC parent {parent_name!r} on switch {switch_id!r} has invalid " f"peerSwitchId {raw_declared!r}")
        else:
            declared_peer = raw_declared

        mapped_peer = self._peer_switch_ids.get(switch_id)
        if declared_peer is not None and mapped_peer is not None and declared_peer != mapped_peer:
            raise MembershipValidationError(
                f"vPC parent {parent_name!r} on switch {switch_id!r} declares "
                f"peerSwitchId {declared_peer!r}, but authoritative pair evidence "
                f"resolves {mapped_peer!r}"
            )

        peer_switch_id = declared_peer or mapped_peer
        if peer_switch_id is None:
            peer_switch_id = self._infer_vpc_peer_switch_id(switch_id, parent_name, record)
        if peer_switch_id is None:
            raise MissingPeerIdentityError(switch_id, parent_name)
        if peer_switch_id == switch_id:
            raise MembershipValidationError(f"vPC parent {parent_name!r} on switch {switch_id!r} resolves " "itself as peerSwitchId")
        self._vpc_peer_cache[cache_key] = peer_switch_id
        return peer_switch_id

    @staticmethod
    def _key(switch_id: str, interface_name: str) -> MemberKey:
        if not isinstance(switch_id, str) or not switch_id:
            raise ValueError("switch_id must be a non-empty string")
        if not isinstance(interface_name, str) or not interface_name:
            raise ValueError("interface_name must be a non-empty string")
        return switch_id, interface_name.lower()

    def _member_port_channel_ids(self, member: IndexedEthernetMember) -> tuple[int, int | None]:
        try:
            model = parse_member_interface_response(member.record)
            configured_id = model.normalized_port_channel_id
            operational_id = normalize_port_channel_id(self._mapping(member.record.get("operData")).get("portChannelId"))
        except (TypeError, ValueError) as exc:
            raise MembershipValidationError(f"Cannot validate member {member.interface_name!r} on switch " f"{member.switch_id!r}: {exc}") from exc

        if configured_id is None:
            raise MembershipValidationError(
                f"Member {member.interface_name!r} on switch {member.switch_id!r} " "does not declare a valid configured portChannelId"
            )
        if operational_id is not None and operational_id != configured_id:
            raise MembershipValidationError(
                f"Member {member.interface_name!r} on switch {member.switch_id!r} "
                f"has configured port-channel ID {configured_id} but operational ID "
                f"{operational_id}"
            )
        return configured_id, operational_id

    def _claims_for(self, switch_id: str, interface_name: str) -> tuple[_ParentClaim, ...]:
        if switch_id not in self._inventories:
            raise MembershipValidationError(f"No cached interface inventory exists for switch {switch_id!r}")
        return self._claims.get(self._key(switch_id, interface_name), ())

    def _require_single_claim(self, member: IndexedEthernetMember) -> _ParentClaim:
        descriptor = member.descriptor
        if descriptor is None:
            raise MembershipValidationError(
                f"Interface {member.interface_name!r} on switch {member.switch_id!r} uses " f"protected or unsupported member policy {member.policy_type!r}"
            )
        claims = self._claims_for(member.switch_id, member.interface_name)
        if not claims:
            raise MembershipValidationError(
                f"Member {member.interface_name!r} on switch {member.switch_id!r} " "is orphaned: no parent membership list contains it"
            )
        if len(claims) != 1:
            owners = ", ".join(f"{claim.interface_name} ({claim.policy_type})" for claim in claims)
            raise MembershipValidationError(f"Member {member.interface_name!r} on switch {member.switch_id!r} " f"has multiple parent owners: {owners}")
        return claims[0]

    def _require_vpc_parent_claim(
        self,
        member: IndexedEthernetMember,
        *,
        expected_parent_name: str | None = None,
        expected_member_field: str | None = None,
    ) -> _ParentClaim:
        """Require exactly one compatible vPC parent claim for a physical member."""

        policy = self._required_policy(member.record)
        parent_name = policy.get("primaryInterface")
        if not isinstance(parent_name, str) or not parent_name:
            raise MembershipValidationError(f"vPC member {member.interface_name!r} on switch {member.switch_id!r} " "lacks a valid primaryInterface")
        claims = self._claims_for(member.switch_id, member.interface_name)
        if not claims:
            raise MembershipValidationError(
                f"vPC member {member.interface_name!r} on switch {member.switch_id!r} is orphaned: " "no parent membership list contains it"
            )
        if len(claims) != 1:
            owners = ", ".join(f"{claim.interface_name} ({claim.policy_type})" for claim in claims)
            raise MembershipValidationError(f"vPC member {member.interface_name!r} on switch {member.switch_id!r} " f"has multiple parent owners: {owners}")
        claim = claims[0]
        descriptor = member.descriptor
        if descriptor is None or not descriptor.pair_aware:
            raise MembershipValidationError(
                f"Interface {member.interface_name!r} on switch {member.switch_id!r} " "does not use a supported pair-aware member policy"
            )
        if claim.interface_type != descriptor.parent_interface_type:
            raise MembershipValidationError(
                f"vPC member {member.interface_name!r} on switch {member.switch_id!r} is claimed by "
                f"interface type {claim.interface_type!r}; expected {descriptor.parent_interface_type!r}"
            )
        if claim.policy_type not in descriptor.parent_policy_types:
            raise MembershipValidationError(
                f"vPC member policy {member.policy_type!r} on {member.interface_name!r} is claimed by "
                f"incompatible parent policy {claim.policy_type!r}; expected one of {descriptor.parent_policy_types!r}"
            )
        if claim.interface_name.lower() != parent_name.lower():
            raise MembershipValidationError(
                f"vPC member {member.interface_name!r} on switch {member.switch_id!r} declares "
                f"primaryInterface {parent_name!r}, but its sole parent claim is {claim.interface_name!r}"
            )
        if expected_parent_name is not None and claim.interface_name.lower() != expected_parent_name.lower():
            raise MembershipValidationError(
                f"vPC member {member.interface_name!r} on switch {member.switch_id!r} is claimed by "
                f"parent {claim.interface_name!r}; expected {expected_parent_name!r}"
            )
        if expected_member_field is not None and expected_member_field not in claim.claim_fields:
            raise MembershipValidationError(
                f"vPC parent {claim.interface_name!r} on switch {member.switch_id!r} does not contain "
                f"member {member.interface_name!r} in assigned field {expected_member_field!r}"
            )
        return claim

    @staticmethod
    def _validate_parent_envelope(
        descriptor: MemberPolicyDescriptor,
        record: InterfaceRecord,
        *,
        switch_id: str,
        parent_name: str,
    ) -> None:
        """Require the parent's structural mode and network OS to match its policy."""

        config_data = record.get("configData")
        if not isinstance(config_data, Mapping):
            raise MembershipValidationError(f"Parent {parent_name!r} on switch {switch_id!r} lacks valid configData")
        actual_mode = config_data.get("mode")
        if actual_mode != descriptor.parent_wire_mode:
            raise MembershipValidationError(
                f"Parent {parent_name!r} on switch {switch_id!r} has mode {actual_mode!r}; "
                f"expected {descriptor.parent_wire_mode!r} for member policy {descriptor.policy_type!r}"
            )
        network_os = config_data.get("networkOS")
        if not isinstance(network_os, Mapping):
            raise MembershipValidationError(f"Parent {parent_name!r} on switch {switch_id!r} lacks valid networkOS data")
        actual_network_os = network_os.get("networkOSType")
        if actual_network_os != descriptor.parent_network_os:
            raise MembershipValidationError(
                f"Parent {parent_name!r} on switch {switch_id!r} has networkOSType {actual_network_os!r}; "
                f"expected {descriptor.parent_network_os!r} for member policy {descriptor.policy_type!r}"
            )

    def _validate_parent_claim(
        self,
        member: IndexedEthernetMember,
        claim: _ParentClaim,
        member_port_channel_id: int,
        *,
        local_member_field: str,
    ) -> MemberOwner:
        descriptor = member.descriptor
        if descriptor is None:
            raise MembershipValidationError(
                f"Interface {member.interface_name!r} on switch {member.switch_id!r} " f"uses protected or unsupported member policy {member.policy_type!r}"
            )
        if claim.interface_type != descriptor.parent_interface_type:
            raise MembershipValidationError(
                f"Member {member.interface_name!r} on switch {member.switch_id!r} "
                f"is claimed by interface type {claim.interface_type!r}; expected "
                f"{descriptor.parent_interface_type!r}"
            )
        if claim.policy_type not in descriptor.parent_policy_types:
            raise MembershipValidationError(
                f"Member policy {member.policy_type!r} on {member.interface_name!r} "
                f"is claimed by incompatible parent policy {claim.policy_type!r}; "
                f"expected one of {descriptor.parent_policy_types!r}"
            )
        self._validate_parent_envelope(
            descriptor,
            claim.record,
            switch_id=member.switch_id,
            parent_name=claim.interface_name,
        )
        if local_member_field not in claim.claim_fields:
            raise MembershipValidationError(
                f"Parent {claim.interface_name!r} on switch {member.switch_id!r} "
                f"does not contain member {member.interface_name!r} in required field "
                f"{local_member_field!r}"
            )

        parent_id = self._standalone_parent_port_channel_id(claim)
        if parent_id != member_port_channel_id:
            raise MembershipValidationError(
                f"Member {member.interface_name!r} on switch {member.switch_id!r} "
                f"declares port-channel ID {member_port_channel_id}, but parent "
                f"{claim.interface_name!r} resolves to ID {parent_id}"
            )

        return MemberOwner(
            switch_id=member.switch_id,
            interface_name=claim.interface_name,
            interface_type=claim.interface_type,
            policy_type=claim.policy_type,
            port_channel_id=parent_id,
            claim_fields=claim.claim_fields,
            record=claim.record,
        )

    def _standalone_parent_port_channel_id(self, claim: _ParentClaim) -> int:
        try:
            name_id = normalize_port_channel_id(claim.interface_name)
            policy = self._policy(claim.record) or {}
            configured_id = normalize_port_channel_id(policy.get("portChannelId"))
        except ValueError as exc:
            raise MembershipValidationError(
                f"Cannot resolve port-channel identity for parent " f"{claim.interface_name!r} on switch {claim.switch_id!r}: {exc}"
            ) from exc
        if name_id is None:
            raise MembershipValidationError(
                f"Parent {claim.interface_name!r} on switch {claim.switch_id!r} " "does not have a valid port-channel interface name"
            )
        if configured_id is not None and configured_id != name_id:
            raise MembershipValidationError(
                f"Parent {claim.interface_name!r} on switch {claim.switch_id!r} " f"has name ID {name_id} but policy portChannelId {configured_id}"
            )
        return name_id

    def _validate_vpc_pair(
        self,
        member: IndexedEthernetMember,
        claim: _ParentClaim,
    ) -> ValidatedMemberOwnership:
        descriptor = member.descriptor
        if descriptor is None or not descriptor.pair_aware:
            raise MembershipValidationError(
                f"Interface {member.interface_name!r} on switch {member.switch_id!r} " f"does not use a supported pair-aware member policy"
            )
        self._validate_vpc_parent_record(
            descriptor,
            claim.record,
            switch_id=member.switch_id,
            parent_name=claim.interface_name,
        )
        peer_switch_id = self._resolve_vpc_peer_switch_id(member.switch_id, claim.interface_name, claim.record)
        if peer_switch_id not in self._inventories:
            raise MissingPeerInventoryError(peer_switch_id)

        pair_ids = tuple(sorted((member.switch_id, peer_switch_id)))
        cache_key = (pair_ids, claim.interface_name.lower(), member.policy_type)
        cached_pair = self._vpc_pair_validation_cache.get(cache_key)
        if cached_pair is not None:
            cached_result = cached_pair.results.get(member.key)
            if cached_result is None:
                raise MembershipValidationError(
                    f"vPC member {member.interface_name!r} on switch {member.switch_id!r} " f"is not owned by validated parent {claim.interface_name!r}"
                )
            return cached_result

        peer_parent_record = self._inventories[peer_switch_id].get(claim.interface_name.lower())
        if peer_parent_record is None:
            raise MembershipValidationError(f"Peer switch {peer_switch_id!r} does not contain vPC parent copy " f"{claim.interface_name!r}")
        peer_parent_name = peer_parent_record.get("interfaceName")
        if not isinstance(peer_parent_name, str) or peer_parent_name.lower() != claim.interface_name.lower():
            raise MembershipValidationError(
                f"Peer parent record for {claim.interface_name!r} on switch {peer_switch_id!r} " f"has invalid interfaceName {peer_parent_name!r}"
            )
        self._validate_vpc_parent_record(
            descriptor,
            peer_parent_record,
            switch_id=peer_switch_id,
            parent_name=peer_parent_name,
        )
        reciprocal_peer_id = self._resolve_vpc_peer_switch_id(peer_switch_id, peer_parent_name, peer_parent_record)
        if reciprocal_peer_id != member.switch_id:
            raise MembershipValidationError(
                f"vPC parent copies are not reciprocal: {claim.interface_name!r} on "
                f"switch {peer_switch_id!r} resolves peerSwitchId "
                f"{reciprocal_peer_id!r}, expected {member.switch_id!r}"
            )

        local_signature = self._required_vpc_parent_signature(claim.record, member.switch_id, claim.interface_name)
        peer_signature = self._required_vpc_parent_signature(peer_parent_record, peer_switch_id, peer_parent_name)
        if local_signature != peer_signature:
            raise MembershipValidationError(
                f"vPC parent copies for {claim.interface_name!r} have inconsistent literal configured data; "
                "ND peer1/peer2 fields must retain the same meaning in both switch echoes"
            )

        slots = self._vpc_parent_slots(claim.record, member.switch_id, claim.interface_name)
        orientations = (
            {pair_ids[0]: slots[0], pair_ids[1]: slots[1]},
            {pair_ids[0]: slots[1], pair_ids[1]: slots[0]},
        )
        valid_orientations: list[tuple[dict[str, _VpcParentSlot], dict[str, tuple[_ValidatedVpcSlotMember, ...]]]] = []
        orientation_errors: list[str] = []
        for orientation in orientations:
            try:
                validated_by_switch = {
                    switch_id: self._validate_vpc_members_for_parent(
                        switch_id=switch_id,
                        member_names=slot.member_names,
                        expected_policy_type=member.policy_type,
                        expected_parent_name=claim.interface_name,
                        expected_port_channel_id=slot.port_channel_id,
                        expected_member_field=slot.member_field,
                    )
                    for switch_id, slot in orientation.items()
                }
                valid_orientations.append((orientation, validated_by_switch))
            except MembershipValidationError as exc:
                orientation_errors.append(str(exc))

        if not valid_orientations:
            raise MembershipValidationError(
                f"Cannot map literal peer1/peer2 slots for vPC parent {claim.interface_name!r} "
                f"onto switches {list(pair_ids)!r}: {'; '.join(orientation_errors)}"
            )
        if len(valid_orientations) > 1 and slots[0].fingerprint != slots[1].fingerprint:
            raise MembershipValidationError(
                f"Cannot unambiguously map non-equivalent peer1/peer2 slots for vPC parent " f"{claim.interface_name!r} onto switches {list(pair_ids)!r}"
            )

        orientation, validated_by_switch = valid_orientations[0]
        parent_records = {member.switch_id: claim.record, peer_switch_id: peer_parent_record}
        owners = {
            switch_id: MemberOwner(
                switch_id=switch_id,
                interface_name=str(parent_records[switch_id].get("interfaceName")),
                interface_type="vpc",
                policy_type=str(policy_type_from_interface_record(parent_records[switch_id])),
                port_channel_id=slot.port_channel_id,
                claim_fields=(slot.member_field,),
                record=parent_records[switch_id],
            )
            for switch_id, slot in orientation.items()
        }
        results: dict[MemberKey, ValidatedMemberOwnership] = {}
        for switch_id, validated_members in validated_by_switch.items():
            other_switch_id = pair_ids[1] if switch_id == pair_ids[0] else pair_ids[0]
            peer_members = tuple(item.member for item in validated_by_switch[other_switch_id])
            for validated_member in validated_members:
                result = ValidatedMemberOwnership(
                    member=validated_member.member,
                    owner=owners[switch_id],
                    configured_port_channel_id=validated_member.configured_port_channel_id,
                    operational_port_channel_id=validated_member.operational_port_channel_id,
                    peer_owner=owners[other_switch_id],
                    peer_members=peer_members,
                    pair_validated=True,
                )
                results[validated_member.member.key] = result

        proof = _ValidatedVpcParentPair(results=MappingProxyType(results))
        self._vpc_pair_validation_cache[cache_key] = proof
        self._validation_cache.update(results)
        target = results.get(member.key)
        if target is None:
            raise MembershipValidationError(
                f"vPC member {member.interface_name!r} on switch {member.switch_id!r} is not in the "
                f"validated local slot for parent {claim.interface_name!r}"
            )
        return target

    def _validate_vpc_parent_record(
        self,
        descriptor: MemberPolicyDescriptor,
        record: InterfaceRecord,
        *,
        switch_id: str,
        parent_name: str,
    ) -> None:
        """Validate one vPC parent copy without assigning its literal peer slot."""

        if record.get("interfaceType") != descriptor.parent_interface_type:
            raise MembershipValidationError(
                f"vPC parent {parent_name!r} on switch {switch_id!r} has interface type "
                f"{record.get('interfaceType')!r}; expected {descriptor.parent_interface_type!r}"
            )
        policy_type = policy_type_from_interface_record(record)
        if policy_type not in descriptor.parent_policy_types:
            raise MembershipValidationError(
                f"vPC parent {parent_name!r} on switch {switch_id!r} uses incompatible policy "
                f"{policy_type!r}; expected one of {descriptor.parent_policy_types!r}"
            )
        self._validate_parent_envelope(descriptor, record, switch_id=switch_id, parent_name=parent_name)

    def _vpc_parent_slots(self, record: InterfaceRecord, switch_id: str, parent_name: str) -> tuple[_VpcParentSlot, _VpcParentSlot]:
        """Return the two literal, pair-wide peer slots from one coherent parent copy."""

        policy = self._required_policy(record)
        slots = []
        for number in (1, 2):
            slots.append(
                _VpcParentSlot(
                    number=number,
                    port_channel_id=self._required_policy_port_channel_id(
                        record,
                        f"peer{number}PortChannelId",
                        parent_name=parent_name,
                        switch_id=switch_id,
                    ),
                    member_names=self._required_vpc_member_names(
                        record,
                        f"peer{number}MemberPorts",
                        switch_id,
                        parent_name,
                    ),
                    fingerprint=tuple(
                        sorted(
                            (key[5:], self._freeze_vpc_value(value, field_name=key))
                            for key, value in policy.items()
                            if isinstance(key, str) and key.startswith(f"peer{number}") and len(key) > 5
                        )
                    ),
                )
            )
        return slots[0], slots[1]

    def _validate_vpc_members_for_parent(
        self,
        *,
        switch_id: str,
        member_names: frozenset[str],
        expected_policy_type: str,
        expected_parent_name: str,
        expected_port_channel_id: int,
        expected_member_field: str,
    ) -> tuple[_ValidatedVpcSlotMember, ...]:
        actual_members = self._vpc_members_by_parent.get((switch_id, expected_parent_name.lower()), ())
        actual_names = frozenset(item.interface_name.lower() for item in actual_members)
        if actual_names != member_names:
            missing = sorted(member_names - actual_names)
            unlisted = sorted(actual_names - member_names)
            raise MembershipValidationError(
                f"vPC parent {expected_parent_name!r} on switch {switch_id!r} has member-set "
                f"mismatch for this slot: missing={missing!r}, unlisted={unlisted!r}"
            )

        validated: list[_ValidatedVpcSlotMember] = []
        for slot_member in actual_members:
            if slot_member.policy_type != expected_policy_type:
                raise MembershipValidationError(
                    f"vPC member {slot_member.interface_name!r} on switch "
                    f"{switch_id!r} uses policy {slot_member.policy_type!r}; expected "
                    f"{expected_policy_type!r}"
                )
            self._require_vpc_parent_claim(
                slot_member,
                expected_parent_name=expected_parent_name,
                expected_member_field=expected_member_field,
            )
            configured_id, operational_id = self._member_port_channel_ids(slot_member)
            if configured_id != expected_port_channel_id:
                raise MembershipValidationError(
                    f"vPC member {slot_member.interface_name!r} on switch "
                    f"{switch_id!r} declares port-channel ID {configured_id}; "
                    f"expected {expected_port_channel_id}"
                )
            self._validate_primary_interface(slot_member, expected_parent_name)
            validated.append(
                _ValidatedVpcSlotMember(
                    member=slot_member,
                    configured_port_channel_id=configured_id,
                    operational_port_channel_id=operational_id,
                )
            )
        return tuple(validated)

    @staticmethod
    def _validate_primary_interface(member: IndexedEthernetMember, expected_parent_name: str) -> None:
        policy = EthernetMembershipIndex._required_policy(member.record)
        primary_interface = policy.get("primaryInterface")
        if not isinstance(primary_interface, str) or (primary_interface.lower() != expected_parent_name.lower()):
            raise MembershipValidationError(
                f"vPC member {member.interface_name!r} on switch {member.switch_id!r} "
                f"declares primaryInterface {primary_interface!r}; expected "
                f"{expected_parent_name!r}"
            )

    @staticmethod
    def _required_policy_port_channel_id(
        record: InterfaceRecord,
        field: str,
        *,
        parent_name: str,
        switch_id: str,
    ) -> int:
        policy = EthernetMembershipIndex._required_policy(record)
        try:
            port_channel_id = normalize_port_channel_id(policy.get(field))
        except ValueError as exc:
            raise MembershipValidationError(f"vPC parent {parent_name!r} on switch {switch_id!r} has invalid " f"{field}: {exc}") from exc
        if port_channel_id is None:
            raise MembershipValidationError(f"vPC parent {parent_name!r} on switch {switch_id!r} lacks valid " f"{field}")
        return port_channel_id

    @staticmethod
    def _required_vpc_member_names(
        record: InterfaceRecord,
        field: str,
        switch_id: str,
        parent_name: str,
    ) -> frozenset[str]:
        policy = EthernetMembershipIndex._required_policy(record)
        raw_names = policy.get(field)
        names = EthernetMembershipIndex._normalized_member_names(raw_names)
        if not names:
            raise MembershipValidationError(f"vPC parent {parent_name!r} on switch {switch_id!r} lacks a " f"non-empty {field} list")
        return names

    @staticmethod
    def _normalized_member_names(value: object) -> frozenset[str]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return frozenset()
        names: set[str] = set()
        for name in value:
            if isinstance(name, str) and name.strip():
                names.add(name.strip().lower())
        return frozenset(names)

    @staticmethod
    def _mapping(value: object) -> Mapping[str, Any]:
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _policy(record: InterfaceRecord) -> Mapping[str, Any] | None:
        config_data = record.get("configData")
        if not isinstance(config_data, Mapping):
            return None
        network_os = config_data.get("networkOS")
        if not isinstance(network_os, Mapping):
            return None
        policy = network_os.get("policy")
        return policy if isinstance(policy, Mapping) else None

    @staticmethod
    def _required_policy(record: InterfaceRecord) -> Mapping[str, Any]:
        policy = EthernetMembershipIndex._policy(record)
        if policy is None:
            raise MembershipValidationError(f"Interface {record.get('interfaceName')!r} lacks a valid policy mapping")
        return policy
