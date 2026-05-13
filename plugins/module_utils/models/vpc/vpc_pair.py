# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
vPC pair Pydantic model for Nexus Dashboard.

Models the pair-level resource exposed at
`/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/vpcPair`. The pair owns
peer-link, keepalive, domain ID, and role-priority configuration; vPC member
interfaces (`accessVpcHost`, `trunkVpcHost`) live in a separate per-interface model
family.

## v1 scope

Direct peering only — `useVirtualPeerLink` is frozen to `False`. Fabric peering
(`useVirtualPeerLink=True`) will be a v2 follow-up that unfreezes the field; the
discriminated-union extension is non-breaking.

## Composite identifier

`(fabric_name, switch_ip, peer_switch_ip)` — `get_identifier_value()` canonicalizes
the peer pair via sort so user-supplied `(A, B)` and `(B, A)` collapse to the same
logical pair (a single switch can only ever be in at most one vPC pair per fabric).
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class VpcPairModel(NDBaseModel):
    """
    # Summary

    vPC pair configuration for Nexus Dashboard. Composite identifier `(fabric_name, switch_ip, peer_switch_ip)`. v1 freezes
    `useVirtualPeerLink=False` (direct peering). Pair-detail fields are nested under `vpcPairDetails` on the wire via
    `payload_nested_fields`.

    The orchestrator resolves `switch_ip` / `peer_switch_ip` (Ansible-facing) into wire serials (`switch_id`, `peer_switch_id`)
    before calling `to_payload()`.

    ## Raises

    ### ValidationError

    - If `fabric_name`, `switch_ip`, `peer_switch_ip`, or `domain_id` is missing.
    - If `domain_id` is outside `1..1000`.
    - If `switch_ip == peer_switch_ip` (peers must differ).
    - If `use_virtual_peer_link` is set to `True` (frozen, v1 direct peering only).
    - If `keep_alive_vrf` is not one of `"default"` or `"management"`.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["fabric_name", "switch_ip", "peer_switch_ip"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"fabric_name", "switch_ip", "peer_switch_ip"}

    payload_nested_fields: ClassVar[dict[str, list[str]]] = {
        "vpcPairDetails": [
            "pair_details_type",
            "domain_id",
            "keep_alive_vrf",
            "keep_alive_hold_timeout",
            "switch_keep_alive_local_ip",
            "peer_switch_keep_alive_local_ip",
            "switch_po_id",
            "peer_switch_po_id",
            "switch_member_interfaces",
            "peer_switch_member_interfaces",
            "enable_mirror_config",
            "is_vpc_plus",
            "is_vteps",
            "nve_interface",
            "po_mode",
            "admin_state",
            "allowed_vlans",
        ],
    }

    # --- Ansible-facing identifiers (not on the wire) ---

    fabric_name: str = Field(min_length=1)
    switch_ip: str = Field(min_length=1)
    peer_switch_ip: str = Field(min_length=1)

    # --- Wire-facing serial fields (orchestrator-injected) ---

    switch_id: str | None = Field(default=None, alias="switchId", description="Wire serial for the primary peer (resolved from switch_ip)")
    peer_switch_id: str | None = Field(default=None, alias="peerSwitchId", description="Wire serial for the secondary peer (resolved from peer_switch_ip)")

    # --- Discriminators ---

    use_virtual_peer_link: Literal[False] = Field(
        default=False,
        alias="useVirtualPeerLink",
        frozen=True,
        description="Direct peering (False, v1). Fabric peering (True) is a v2 follow-up; field will become bool at that time.",
    )
    vpc_action: Literal["pair", "unPair"] = Field(
        default="pair",
        alias="vpcAction",
        description="Pair lifecycle action carried in PUT body",
    )
    pair_details_type: Literal["default"] = Field(
        default="default",
        alias="type",
        frozen=True,
        description="vpcPairDetails discriminator. v1 supports only the default template; custom templates are a v2 follow-up.",
    )

    # --- Pair-detail fields (nested under vpcPairDetails on the wire) ---

    domain_id: int = Field(ge=1, le=1000, alias="domainId", description="vPC domain ID (1-1000)")
    keep_alive_vrf: Literal["default", "management"] = Field(
        default="management",
        alias="keepAliveVrf",
        description="VRF used for vPC peer keepalive",
    )
    keep_alive_hold_timeout: int | None = Field(default=None, alias="keepAliveHoldTimeout", description="Peer keepalive hold timeout in seconds")
    switch_keep_alive_local_ip: str | None = Field(
        default=None,
        alias="switchKeepAliveLocalIp",
        description="Peer-keepalive source IP on peer 1. Defaults to switch_ip when keep_alive_vrf is 'management'.",
    )
    peer_switch_keep_alive_local_ip: str | None = Field(
        default=None,
        alias="peerSwitchKeepAliveLocalIp",
        description="Peer-keepalive source IP on peer 2. Defaults to peer_switch_ip when keep_alive_vrf is 'management'.",
    )
    switch_po_id: int | None = Field(
        default=None,
        ge=1,
        le=4096,
        alias="switchPoId",
        description="Peer-link port-channel ID on peer 1",
    )
    peer_switch_po_id: int | None = Field(
        default=None,
        ge=1,
        le=4096,
        alias="peerSwitchPoId",
        description="Peer-link port-channel ID on peer 2",
    )
    switch_member_interfaces: list[str] | None = Field(default=None, alias="switchMemberInterfaces", description="Peer-link member ports on peer 1")
    peer_switch_member_interfaces: list[str] | None = Field(default=None, alias="peerSwitchMemberInterfaces", description="Peer-link member ports on peer 2")
    enable_mirror_config: bool | None = Field(default=None, alias="enableMirrorConfig", description="Mirror peer-1 config onto peer-2")
    is_vpc_plus: bool | None = Field(default=None, alias="isVpcPlus", description="Enable vPC+")
    is_vteps: bool | None = Field(default=None, alias="isVteps", description="Both peers act as VTEPs")
    nve_interface: int | None = Field(default=None, alias="nveInterface", description="NVE interface ID for VXLAN")
    po_mode: str | None = Field(default=None, alias="poMode", description="Peer-link port-channel mode (active/passive/on)")
    admin_state: bool | None = Field(default=None, alias="adminState", description="Peer-link admin state")
    allowed_vlans: str | None = Field(default=None, alias="allowedVlans", description="VLAN list permitted across the peer link")

    # --- Validators ---

    @model_validator(mode="before")
    @classmethod
    def flatten_vpc_pair_details(cls, data):
        """
        # Summary

        Lift `vpcPairDetails` nested fields up to the top level on input so that the round-trip between `to_payload()`
        (which nests under `vpcPairDetails`) and `from_response()` (which receives the nested wire shape) works
        through standard Pydantic validation. Top-level fields take precedence if both shapes are present.

        ## Raises

        None
        """
        if isinstance(data, dict) and isinstance(data.get("vpcPairDetails"), dict):
            details = data.pop("vpcPairDetails")
            for key, value in details.items():
                data.setdefault(key, value)
        return data

    @model_validator(mode="after")
    def default_keepalive_local_ips(self) -> "VpcPairModel":
        """
        # Summary

        Default `switch_keep_alive_local_ip` / `peer_switch_keep_alive_local_ip` to the corresponding management IPs
        when they are unset and `keep_alive_vrf == "management"`. ND requires both keepalive local IPs in the PUT
        body even though the OpenAPI schema marks them optional; for the management-VRF case, the management IP is
        the standard value and the user should not have to repeat it.

        ## Raises

        None
        """
        if self.keep_alive_vrf == "management":
            if self.switch_keep_alive_local_ip is None and self.switch_ip:
                self.switch_keep_alive_local_ip = self.switch_ip
            if self.peer_switch_keep_alive_local_ip is None and self.peer_switch_ip:
                self.peer_switch_keep_alive_local_ip = self.peer_switch_ip
        return self

    @model_validator(mode="after")
    def validate_peers_differ(self) -> "VpcPairModel":
        """
        # Summary

        Reject configurations where `switch_ip` and `peer_switch_ip` are the same — a switch cannot vPC-pair with itself.

        ## Raises

        ### ValueError

        - If `switch_ip == peer_switch_ip`.
        """
        if self.switch_ip == self.peer_switch_ip:
            raise ValueError("switch_ip and peer_switch_ip must differ - a switch cannot vPC-pair with itself")
        return self

    # --- Identifier ---

    def get_identifier_value(self) -> tuple:
        """
        # Summary

        Return the composite identifier as `(fabric_name, low_ip, high_ip)`. The peer IPs are sorted so that
        user-supplied `(A, B)` and `(B, A)` orderings collapse to the same logical pair (a switch can only ever
        be in one vPC pair per fabric).

        ## Raises

        ### ValueError

        - If any of `fabric_name`, `switch_ip`, `peer_switch_ip` is `None`.
        """
        for field in ("fabric_name", "switch_ip", "peer_switch_ip"):
            if getattr(self, field, None) is None:
                raise ValueError(f"Composite identifier field '{field}' is None")
        low, high = sorted([self.switch_ip, self.peer_switch_ip])
        return (self.fabric_name, low, high)

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_vpc_pair` module. Frozen / internal fields
        (`use_virtual_peer_link`, `vpc_action`) are intentionally NOT exposed.

        ## Raises

        None
        """
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                required=False,
                options=dict(
                    switch_ip=dict(type="str", required=True),
                    peer_switch_ip=dict(type="str", required=True),
                    domain_id=dict(type="int", required=True),
                    keep_alive_vrf=dict(type="str", default="management", choices=["default", "management"]),
                    keep_alive_hold_timeout=dict(type="int"),
                    switch_keep_alive_local_ip=dict(type="str"),
                    peer_switch_keep_alive_local_ip=dict(type="str"),
                    switch_po_id=dict(type="int"),
                    peer_switch_po_id=dict(type="int"),
                    switch_member_interfaces=dict(type="list", elements="str"),
                    peer_switch_member_interfaces=dict(type="list", elements="str"),
                    enable_mirror_config=dict(type="bool"),
                    is_vpc_plus=dict(type="bool"),
                    is_vteps=dict(type="bool"),
                    nve_interface=dict(type="int"),
                    po_mode=dict(type="str"),
                    admin_state=dict(type="bool"),
                    allowed_vlans=dict(type="str"),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted", "query"],
            ),
        )
