# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared top-level model behaviour for the port-channel interface modules (issue #549).

`PortChannelInterfaceBaseModel` carries what every port-channel interface model has in common regardless of mode (access, trunk,
routed): the composite `(switch_ip, interface_name)` identifier, the frozen `interface_type`, the lowercase `interface_name`
normalizer, the `policy_type` accessor, and the IOS-XE create-name rewrite. Subclasses declare `config_data` and the argument spec.
"""

from __future__ import annotations

import re
from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    SerializationInfo,
    field_validator,
    model_serializer,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

# The lowercase identifier form (`port-channel101`) with its numeric id captured, used to rebuild ND's IOS-XE
# create-side canonical spelling `Port-channel101` in payload-mode dumps only.
_XE_CREATE_NAME_RE = re.compile(r"^port-channel(\d+)$")

# ND's lowercase port-channel name prefix, and the ID range the controller accepts (the same bounds the vPC models use for
# `peer1_port_channel_id` / `peer2_port_channel_id`).
_PORT_CHANNEL_PREFIX = "port-channel"
_PORT_CHANNEL_ID_MIN = 1
_PORT_CHANNEL_ID_MAX = 4096


def normalize_port_channel_interface_name(value):
    """
    # Summary

    Normalize a port-channel interface name to the ND API convention (lowercase `port-channel` prefix, e.g. `Port-Channel501` ->
    `port-channel501`). Bare integers are accepted and prefixed (e.g. `501` -> `port-channel501`). Surrounding whitespace is stripped
    from every string form first, so a padded name is recognized and range-checked like an unpadded one. Shared by every port-channel
    model through `PortChannelInterfaceBaseModel` (issue #378; the helper issue #353 consolidates).

    When a numeric port-channel ID can be extracted from the input, it is range-checked against 1-4096 so an out-of-range ID fails
    early with a clear error instead of being rejected by ND. A platform may support fewer (a Catalyst 9000 accepts 1-128); that limit
    is left to the controller because the name is validated before the network OS is known. An input with no extractable ID (an
    abbreviation such as `po501`, a name with an inner space or a suffix) is only stripped and lowercased; abbreviations are not expanded, for
    parity with the SVI normalizer. Non-string, non-integer input, and `bool` (an `int` subclass), is returned untouched so Pydantic
    reports the type error.

    ## Raises

    ### ValueError

    - If the extracted port-channel ID is outside the range 1-4096.
    """
    normalized = value
    port_channel_id: int | None = None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        port_channel_id = value
        normalized = f"{_PORT_CHANNEL_PREFIX}{value}"
    elif isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            port_channel_id = int(stripped)
            normalized = f"{_PORT_CHANNEL_PREFIX}{stripped}"
        else:
            normalized = stripped.lower()
            remainder = normalized[len(_PORT_CHANNEL_PREFIX) :] if normalized.startswith(_PORT_CHANNEL_PREFIX) else ""
            if remainder.isdigit():
                port_channel_id = int(remainder)
    if port_channel_id is not None and not _PORT_CHANNEL_ID_MIN <= port_channel_id <= _PORT_CHANNEL_ID_MAX:
        raise ValueError(f"Port-channel ID must be in the range {_PORT_CHANNEL_ID_MIN}-{_PORT_CHANNEL_ID_MAX}, got {port_channel_id}.")
    return normalized


class PortChannelInterfaceBaseModel(NDBaseModel):
    """
    # Summary

    Base for the top-level port-channel interface models. Uses a composite identifier (`switch_ip`, `interface_name`), where
    `interface_name` is the port-channel's own name (e.g. `port-channel501`), not a member interface. Subclasses declare a
    `config_data` field whose `network_os` container carries `network_os_type` and an optional `policy`.

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["portChannel"] = Field(default="portChannel", alias="interfaceType", frozen=True)

    @property
    def policy_type(self) -> str | None:
        """
        # Summary

        The `policy_type` discriminator from `config_data.network_os.policy`, or `None` when `config_data` or `policy` is unset
        (e.g. a `state: deleted` identifier-only item).

        ## Raises

        None
        """
        config_data = getattr(self, "config_data", None)
        if config_data is None or config_data.network_os.policy is None:
            return None
        return config_data.network_os.policy.policy_type

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Normalize the port-channel interface name through `normalize_port_channel_interface_name`: lowercase to match ND API
        convention (e.g. `Port-Channel501` -> `port-channel501`), a bare ID prefixed (`501` -> `port-channel501`), and an extractable
        ID range-checked against 1-4096 (issue #378).

        ## Raises

        ### ValueError

        - If the extracted port-channel ID is outside the range 1-4096.
        """
        return normalize_port_channel_interface_name(value)

    @model_serializer(mode="wrap")
    def _canonical_xe_create_name(self, handler, info: SerializationInfo):
        """
        # Summary

        Emit the IOS-XE canonical spelling `Port-channel<N>` as `interfaceName` in payload-mode dumps of the `ios-xe` branch, leaving the
        lowercase identifier untouched in config and diff dumps and for the NX-OS branch. Also applies `payload_defaults` (this wrap
        serializer replaces `NDBaseModel._serialize_with_payload_defaults`).

        ## Raises

        ### AssertionError

        - If the wrapped handler returns a non-`dict` (model-level serialization always yields a dict).
        """
        # TODO(4.2.1) xe-port-channel-create-requires-canonical-name
        # ND rejects an IOS-XE port-channel create whose interfaceName is lowercase (generic policy-execution 500 / 207-failed) but echoes
        # the created interface lowercased; GET/PUT/remove accept the lowercase name. Rewrite only the write body.
        result = handler(self)
        if not isinstance(result, dict):
            raise AssertionError(f"Expected dict from model serialization, got {type(result).__name__}")
        result = self._apply_payload_defaults(result, info)
        if (info.context or {}).get("mode") != "payload":
            return result
        config_data = getattr(self, "config_data", None)
        network_os = config_data.network_os if config_data is not None else None
        if network_os is None or network_os.network_os_type != "ios-xe":
            return result
        name = result.get("interfaceName")
        match = _XE_CREATE_NAME_RE.match(name) if isinstance(name, str) else None
        if match:
            result["interfaceName"] = f"Port-channel{match.group(1)}"
        return result
