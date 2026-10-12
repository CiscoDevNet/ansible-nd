# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pure input validation for the parent-oriented breakout contract."""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field, field_validator, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

_PARENT_INTERFACE = re.compile(r"Ethernet([0-9]+)/([0-9]+)", re.IGNORECASE)
_CHILD_INTERFACE = re.compile(r"Ethernet([0-9]+)/([0-9]+)/([0-9]+)", re.IGNORECASE)


class BreakoutInterfaceModel(NDBaseModel):
    """One canonical parent identity and switch selector; no hardware assumptions."""

    model_config = ConfigDict(extra="forbid", strict=True)
    identifiers: ClassVar[list[str]] = ["switch_id", "interface_name"]
    identifier_strategy: ClassVar[Literal["composite"]] = "composite"

    switch_id: str = Field(alias="switchId")
    interface_name: str = Field(alias="interfaceName")
    breakout_map: str | None = Field(default=None, alias="breakoutMap")
    requested_child: str | None = Field(default=None, exclude=True, repr=False)

    @field_validator("switch_id", mode="before")
    @classmethod
    def normalize_switch_id(cls, value: Any) -> str:
        """Preserve serial/IP input for the shared switch-identity resolver."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError("switch_id must be a non-empty serial number or management IP address")
        return value.strip()

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value: Any) -> str:
        """Keep logical identity parent-only; expansion handles deleted child aliases."""
        if not isinstance(value, str):
            raise ValueError("interface_name must be a native parent such as Ethernet1/50")
        match = _PARENT_INTERFACE.fullmatch(value.strip())
        if match is None:
            raise ValueError("interface_name must be a native parent such as Ethernet1/50; children and subinterfaces are not accepted")
        slot, port = (int(component) for component in match.groups())
        if slot < 1 or port < 1:
            raise ValueError("interface_name must have a positive slot and port")
        return f"Ethernet{slot}/{port}"

    @field_validator("breakout_map", mode="before")
    @classmethod
    def normalize_breakout_map(cls, value: Any) -> str | None:
        """Normalize spelling, leaving map support to Nexus Dashboard and the switch."""
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError("breakout_map must be a non-empty string")
        return value.strip().lower()

    @field_validator("requested_child", mode="before")
    @classmethod
    def normalize_requested_child(cls, value: Any) -> str | None:
        """Normalize the internal selector without claiming it is a physical child."""
        if value is None:
            return None
        match = _CHILD_INTERFACE.fullmatch(value.strip()) if isinstance(value, str) else None
        if match is None:
            raise ValueError("requested_child must have the form Ethernet<slot>/<port>/<lane>")
        slot, port, lane = (int(component) for component in match.groups())
        if min(slot, port, lane) < 1:
            raise ValueError("requested_child must have a positive slot, port and lane")
        return f"Ethernet{slot}/{port}/{lane}"

    @model_validator(mode="after")
    def validate_child_family(self) -> BreakoutInterfaceModel:
        """Require internal selector and canonical resource to name one family."""
        if self.requested_child is not None and self.requested_child.rsplit("/", 1)[0] != self.interface_name:
            raise ValueError("requested_child must belong to interface_name's parent family")
        return self

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        """Return the public grouped input specification without map enumeration."""
        return {
            "fabric_name": {"type": "str", "required": True},
            "state": {"type": "str", "choices": ["merged", "deleted"], "default": "merged"},
            "config": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {
                    "switch_id": {"type": "str", "required": True},
                    "interface_names": {"type": "list", "elements": "str", "required": True},
                    "breakout_map": {"type": "str"},
                },
            },
            "verify": {"type": "dict", "options": {"enabled": {"type": "bool", "default": False}}},
        }


def expand_config(raw_config: Any, state: str) -> list[BreakoutInterfaceModel]:
    """Expand grouped selectors without changing input or resolving IP addresses.

    ``merged`` ensures that a parent is broken out, not that its existing map
    equals the supplied map. The map is required only as the create argument.
    ``deleted`` accepts the same native parent or a child alias for its whole
    parent family. It never accepts a map or requests removal of just one lane.
    """
    if state not in {"merged", "deleted"}:
        raise ValueError("state must be merged or deleted")
    if not isinstance(raw_config, list) or not raw_config:
        raise ValueError("config must be a non-empty list")

    expanded: list[BreakoutInterfaceModel] = []
    seen: set[tuple[str, str]] = set()
    allowed = {"switch_id", "interface_names", "breakout_map"}
    for index, group in enumerate(raw_config):
        if not isinstance(group, dict):
            raise ValueError(f"config[{index}] must be a dictionary")
        unexpected = set(group) - allowed
        if unexpected:
            raise ValueError(f"Unsupported config[{index}] option(s): {', '.join(sorted(unexpected))}")
        names = group.get("interface_names")
        if not isinstance(names, list) or not names:
            raise ValueError(f"config[{index}].interface_names must be a non-empty list")
        breakout_map = group.get("breakout_map")
        if state == "merged" and (not isinstance(breakout_map, str) or not breakout_map.strip()):
            raise ValueError(f"config[{index}].breakout_map is required and must be non-empty for state={state}")
        if state == "deleted" and breakout_map is not None:
            raise ValueError(f"config[{index}].breakout_map must be omitted for state=deleted")
        for name in names:
            requested_child = None
            child_match = _CHILD_INTERFACE.fullmatch(name.strip()) if state == "deleted" and isinstance(name, str) else None
            if child_match is not None:
                requested_child = BreakoutInterfaceModel.normalize_requested_child(name)
                name = requested_child.rsplit("/", 1)[0]
            model = BreakoutInterfaceModel(switch_id=group.get("switch_id"), interface_name=name, breakout_map=breakout_map, requested_child=requested_child)
            key = (model.switch_id.casefold(), model.interface_name.casefold())
            if key in seen:
                raise ValueError(f"Interface {model.interface_name} on switch {model.switch_id} is specified more than once")
            seen.add(key)
            expanded.append(model)
    return expanded


def validate_module_params(params: dict[str, Any], raw_args: dict[str, Any] | None = None) -> list[BreakoutInterfaceModel]:
    """Validate the complete public input without opening a connection."""
    fabric_name = params.get("fabric_name")
    if not isinstance(fabric_name, str) or not fabric_name.strip():
        raise ValueError("fabric_name must be a non-empty string")
    state = params.get("state", "merged")
    expanded = expand_config(params.get("config"), state)
    raw_args = raw_args or {}
    if raw_args.get("config_actions", params.get("config_actions")) is not None:
        raise ValueError("config_actions is not supported; Nexus Dashboard applies breakout and unbreakout internally")
    verify = params.get("verify")
    if verify is not None:
        if not isinstance(verify, dict) or set(verify) - {"enabled"}:
            raise ValueError("verify accepts only a dictionary with the enabled option")
        if not isinstance(verify.get("enabled", False), bool):
            raise ValueError("verify.enabled must be a boolean")
    return expanded
