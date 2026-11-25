# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Public HA associations and wire models for the Manage API."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Annotated, Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field, field_validator, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

# Shared HA pair identity and state values

PairKey = tuple[str, str]
SwitchSerial = Annotated[str, Field(strict=True, min_length=1, max_length=32, pattern=r"^\S+$")]
SwitchName = Annotated[str, Field(strict=True, min_length=1, max_length=64)]
HaState = Literal["unpaired", "paired", "pairPending", "unpairPending"]
PRESENT_HA_STATES = frozenset({"paired", "pairPending"})


def _canonical_ha_pair_key(switch_id: str, peer_switch_id: str) -> PairKey:
    """Order the exact serials so both peer orientations share one identity."""
    return (switch_id, peer_switch_id) if switch_id <= peer_switch_id else (peer_switch_id, switch_id)


# Ansible desired-state model


class SmartSwitchHaPairModel(NDBaseModel):
    """An unordered pair of two exact switch serials."""

    model_config = ConfigDict(str_strip_whitespace=False, frozen=True)
    identifiers: ClassVar[list[str]] = ["switch_id", "peer_switch_id"]
    identifier_strategy: ClassVar[Literal["composite"]] = "composite"

    switch_id: SwitchSerial
    peer_switch_id: SwitchSerial

    # Pair validation and identity

    @model_validator(mode="after")
    def _validate_and_order_peers(self) -> SmartSwitchHaPairModel:
        if self.switch_id == self.peer_switch_id:
            raise ValueError("An HA pair requires two distinct switch IDs")
        first_switch_id, second_switch_id = _canonical_ha_pair_key(self.switch_id, self.peer_switch_id)
        if first_switch_id != self.switch_id:
            # Assign the canonical IDs during validation of the frozen model.
            object.__setattr__(self, "switch_id", first_switch_id)
            object.__setattr__(self, "peer_switch_id", second_switch_id)
        return self

    @property
    def peers(self) -> PairKey:
        """Return the canonical peer serials."""
        return self.switch_id, self.peer_switch_id

    # Ansible argument specification

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        return {
            "config": {
                "type": "list",
                "elements": "dict",
                "options": {"switch_id": {"type": "str", "required": True}, "peer_switch_id": {"type": "str", "required": True}},
            },
            "state": {"type": "str", "default": "replaced", "choices": ["replaced", "overridden", "deleted", "gathered"]},
        }


# Manage API topology rows and payloads


class SmartSwitchHaInfo(BaseModel):
    """Controller-supplied switch metadata used by pair and unpair requests."""

    switch_id: SwitchSerial = Field(alias="id")
    name: SwitchName
    ha_paired: HaState | None = Field(default=None, alias="haPaired")
    ip: IPv4Address | None = None
    oper_status: Literal["connected", "disconnected"] | None = Field(default=None, alias="operStatus")
    peer_id: SwitchSerial | None = Field(default=None, alias="peerId")
    peer_ip: IPv4Address | None = Field(default=None, alias="peerIp")
    peer_name: SwitchName | None = Field(default=None, alias="peerName")
    vpc_domain: int | None = Field(default=None, alias="vpcDomain", strict=True, ge=0, le=1000)
    vpc_role: Literal["primary", "secondary", "notApplicable"] | None = Field(default=None, alias="vpcRole")

    @field_validator("ip", "peer_ip", mode="before")
    @classmethod
    def _validate_ipv4_wire_value(cls, address: object) -> str | IPv4Address | None:
        """Check the wire type before Pydantic parses the IPv4 address."""
        if address is not None and not isinstance(address, (str, IPv4Address)):
            raise ValueError("IPv4 addresses must be strings")
        return address


class SmartSwitchHaRow(BaseModel):
    """One topology row in the Smart Switch HA API."""

    pairing_type: Literal["vpc", "nonVpc"] = Field(alias="pairingType")
    switch_info: SmartSwitchHaInfo = Field(alias="switchInfo")

    @property
    def peers(self) -> PairKey | None:
        """Return the reported topology peers, including inactive vPC peers."""
        switch_info = self.switch_info
        return _canonical_ha_pair_key(switch_info.switch_id, switch_info.peer_id) if switch_info.peer_id is not None else None


class SmartSwitchHaRows(BaseModel):
    """Rows envelope for inventory, recommendations, and pair and unpair payloads."""

    rows: list[SmartSwitchHaRow] = Field(strict=True)


# Manage API action results


class SmartSwitchHaResultEntry(BaseModel):
    """One action result keyed by pair identity or switch serial."""

    name: str = Field(strict=True, min_length=1)
    status: Literal["success", "failed"] | None = None
    message: str | None = Field(default=None, strict=True)
