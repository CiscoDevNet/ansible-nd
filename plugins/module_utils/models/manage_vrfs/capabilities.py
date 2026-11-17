# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Release support for VRF definition fields, independent of observed state."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import Any

_RELEASE_FIELDS = (
    ("route_distinguisher_id", "core_data", "coreData", "routeDistinguisherId"),
    ("enable_vrf_vpn_route_leaking", "fabric_data", "fabricData", "enableVrfVpnRouteLeaking"),
)


def _supports_release_fields(version: str | None) -> bool:
    """Require a known ND release at or above 4.3.1."""
    if not isinstance(version, str):
        return False
    try:
        release = tuple(int(part) for part in version.split(".")[:3])
    except ValueError:
        return False
    return len(release) == 3 and release >= (4, 3, 1)


@dataclass(frozen=True)
class VrfWriteCapabilities:
    """The connected controller's VRF contract for Manage and OneManage writes."""

    controller_version: str | None

    @cached_property
    def supported(self) -> bool:
        """Whether the controller supports the release-specific VRF fields."""
        return _supports_release_fields(self.controller_version)

    def validate_config(self, config: dict[str, Any], fabric_name: str) -> None:
        """
        # Summary

        Reject explicit unsupported intent, including false and zero.

        ## Raises

        ### ValueError

        - If an explicitly requested field requires an unsupported or unknown release.
        """
        requested = [name for name, *_rest in _RELEASE_FIELDS if config.get(name) is not None]
        if not requested or self.supported:
            return
        raise ValueError(
            f"VRF on fabric '{fabric_name}': {', '.join(requested)} requires ND 4.3.1 or later (detected: {self.controller_version or 'unknown'})."
        )

    def validate_payload(self, data: dict[str, Any], fabric_name: str) -> None:
        """Validate direct orchestrator writes that did not pass through preparation."""
        config = {}
        for name, _model_key, section, key in _RELEASE_FIELDS:
            block = data.get(section)
            if isinstance(block, dict) and key in block:
                config[name] = block[key]
        self.validate_config(config, fabric_name)

    def filter_fields(self, data: dict[str, Any], *, by_alias: bool = True) -> None:
        """Scope an owned preparation/comparison/payload export, never raw readback."""
        if self.supported:
            return
        for _name, model_key, section, key in _RELEASE_FIELDS:
            section = section if by_alias else model_key
            block = data.get(section)
            if isinstance(block, dict):
                block.pop(key, None)
                if not block:
                    data.pop(section, None)
