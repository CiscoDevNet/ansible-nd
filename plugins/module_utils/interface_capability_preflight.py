# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Interface capability preflight for per-policy interface orchestrators.

Provides `InterfaceCapabilityPreflight`, a lazy-loaded cache + validator that pre-flights
which switches in a fabric are capable of hosting a given `interface_type` and `mode`. Used
by `NDBaseInterfaceOrchestrator.validate_switches_capable` to convert confusing ND HTTP 400s
on incapable switches into a single aggregate error naming the offending switches.

Uses the unpublished `/api/v1/manage/fabrics/{fabric_name}/capableSwitches?interfaceType=...&mode=...`
endpoint. See GitHub issue #273 for stability/risk discussion.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_capable_switches import (
    EpManageFabricsCapableSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class InterfaceCapabilityPreflight:
    """
    # Summary

    Cached interface capability validator for per-policy interface orchestrators.

    Lazily fetches the set of switches capable of hosting a given `(interface_type, mode)` pair from
    the ND Manage `capableSwitches` endpoint, caches by `(interface_type, mode)`, and validates a
    user-supplied set of switch IDs against that capable set. On failure, raises `RuntimeError` with a
    single aggregate message naming the offending switches (`switch_ip` / `switch_name` / `model` when
    `fabric_context` is injected).

    The `(interface_type, mode)` taxonomy is captured experimentally (ND 4.2, 2026-05-11) and enforced
    client-side before any API call — invalid combos raise `ValueError` without consuming a round trip.

    ## Taxonomy (captured ND 4.2, 2026-05-11)

    | interface_type | valid modes                                                              |
    |----------------|--------------------------------------------------------------------------|
    | `loopback`     | `managed`                                                                |
    | `svi`          | `managed`                                                                |
    | `tunnel`       | `managed`                                                                |
    | `ethernet`     | `trunk`, `access`, `routed`, `fex`, `pvlan`, `dot1qTunnel`, `unmanaged`  |
    | `portChannel`  | `trunk`, `access`, `routed`, `fex`, `pvlan`, `dot1qTunnel`, `unmanaged`  |

    `vpc` interfaces use a separate endpoint (`/api/v1/manage/fabrics/{fabric}/vpcPairs?view=intendedPairs`)
    and are handled by a sibling validator, not this class. `breakout` and `subinterface` have no
    pre-check endpoint and are out of scope.

    ## Raises

    ### RuntimeError

    - Via `validate` when one or more switch IDs are not in the capable set for `(interface_type, mode)`.
    - Via `get_capable_switches` if the underlying GET request fails (other than 404).

    ### ValueError

    - Via any method that takes `(interface_type, mode)` when the pair is not in the supported taxonomy.
    """

    _TAXONOMY: ClassVar[dict[str, frozenset[str]]] = {
        "loopback": frozenset({"managed"}),
        "svi": frozenset({"managed"}),
        "tunnel": frozenset({"managed"}),
        "ethernet": frozenset({"trunk", "access", "routed", "fex", "pvlan", "dot1qTunnel", "unmanaged"}),
        "portChannel": frozenset({"trunk", "access", "routed", "fex", "pvlan", "dot1qTunnel", "unmanaged"}),
    }

    def __init__(self, rest_send: RestSend, fabric_name: str, fabric_context: FabricContext | None = None):
        """
        # Summary

        Initialize the preflight with a `RestSend` instance, fabric name, and optional `FabricContext` for error enrichment.

        ## Parameters

        - rest_send: configured `RestSend` (sender, response handler, params already wired).
        - fabric_name: target fabric for the capability query.
        - fabric_context: optional `FabricContext` used to enrich error messages with `switch_ip` / `switch_name` / `model`.

        ## Raises

        None
        """
        self._rest_send = rest_send
        self._fabric_name = fabric_name
        self._fabric_context = fabric_context
        self._cache: dict[tuple[str, str], list[dict]] = {}
        self._id_cache: dict[tuple[str, str], set[str]] = {}

    @classmethod
    def supported_modes(cls, interface_type: str) -> frozenset[str]:
        """
        # Summary

        Return the set of valid modes for a given `interface_type` from the taxonomy.

        ## Raises

        ### ValueError

        - If `interface_type` is not present in the taxonomy.
        """
        try:
            return cls._TAXONOMY[interface_type]
        except KeyError as e:
            supported = ", ".join(sorted(cls._TAXONOMY))
            raise ValueError(f"Unsupported interface_type '{interface_type}'. Supported interface types: {supported}.") from e

    @classmethod
    def _check_taxonomy(cls, interface_type: str, mode: str) -> None:
        """
        # Summary

        Validate that `(interface_type, mode)` is a supported pair in the taxonomy. Raises before any API call.

        ## Raises

        ### ValueError

        - If `interface_type` is not in the taxonomy.
        - If `mode` is not valid for the given `interface_type`.
        """
        valid_modes = cls.supported_modes(interface_type)
        if mode not in valid_modes:
            modes = ", ".join(sorted(valid_modes))
            raise ValueError(f"Unsupported mode '{mode}' for interface_type '{interface_type}'. Supported modes: {modes}.")

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return the fabric name this preflight was created for.

        ## Raises

        None
        """
        return self._fabric_name

    def _query_get(self, path: str) -> dict:
        """
        # Summary

        Issue a GET request via `RestSend` and return the `DATA` dict. Returns `{}` on HTTP 404.

        ## Raises

        ### RuntimeError

        - If the request fails with any non-success status other than 404.
        """
        self._rest_send.path = path
        self._rest_send.verb = HttpVerbEnum.GET
        self._rest_send.commit()
        if self._rest_send.return_code == 404:
            return {}
        if not self._rest_send.success:
            raise RuntimeError(f"GET {path} failed {self._rest_send.error_summary}")
        return self._rest_send.response_current.get("DATA", {})

    def get_capable_switches(self, interface_type: str, mode: str) -> list[dict]:
        """
        # Summary

        Return the list of switch records capable of hosting `(interface_type, mode)` in this fabric. Each record contains
        at least `switchId`, `switchName`, and `model`. Lazily fetched and cached per `(interface_type, mode)`.

        ## Raises

        ### ValueError

        - If `(interface_type, mode)` is not a supported pair in the taxonomy.

        ### RuntimeError

        - If the underlying GET request fails (other than 404).
        """
        self._check_taxonomy(interface_type, mode)
        key = (interface_type, mode)
        if key in self._cache:
            return self._cache[key]
        ep = EpManageFabricsCapableSwitchesGet()
        ep.fabric_name = self._fabric_name
        ep.endpoint_params.interface_type = interface_type
        ep.endpoint_params.mode = mode
        result = self._query_get(ep.path)
        switches = (result.get("switches") or []) if result else []
        self._cache[key] = switches
        return switches

    def get_capable_switch_ids(self, interface_type: str, mode: str) -> set[str]:
        """
        # Summary

        Return the set of `switchId` values capable of hosting `(interface_type, mode)`. Derived from `get_capable_switches`.

        ## Raises

        ### ValueError

        - If `(interface_type, mode)` is not a supported pair in the taxonomy.

        ### RuntimeError

        - If the underlying GET request fails (other than 404).
        """
        key = (interface_type, mode)
        if key in self._id_cache:
            return self._id_cache[key]
        switch_ids = {sw["switchId"] for sw in self.get_capable_switches(interface_type, mode) if sw.get("switchId")}
        self._id_cache[key] = switch_ids
        return switch_ids

    def validate(self, interface_type: str, mode: str, switch_ids: set[str]) -> None:
        """
        # Summary

        Verify that every `switch_id` in `switch_ids` is in the capable set for `(interface_type, mode)`. On failure, raise
        `RuntimeError` with a single aggregate message naming the offending switches.

        When `fabric_context` was injected at construction, the error message enriches each offender with its
        `switch_ip`, `switch_name`, and `model`. When `fabric_context` is not available, the message names only the
        offending `switchId` values.

        ## Raises

        ### ValueError

        - If `(interface_type, mode)` is not a supported pair in the taxonomy.

        ### RuntimeError

        - If one or more switches in `switch_ids` are not in the capable set for `(interface_type, mode)`.
        - If the underlying GET request fails (other than 404).
        """
        capable_ids = self.get_capable_switch_ids(interface_type, mode)
        offenders = {sid for sid in switch_ids if sid not in capable_ids}
        if not offenders:
            return

        offender_descriptions: list[str] = []
        for sid in sorted(offenders):
            parts = [f"switchId={sid}"]
            if self._fabric_context is not None:
                switch_ip = self._fabric_context.switch_map_by_id.get(sid)
                if switch_ip:
                    parts.append(f"switch_ip={switch_ip}")
            offender_descriptions.append("(" + ", ".join(parts) + ")")

        endpoint_path = f"/api/v1/manage/fabrics/{self._fabric_name}/capableSwitches?interfaceType={interface_type}&mode={mode}"
        raise RuntimeError(
            f"The following switches are not capable of hosting interface_type='{interface_type}' "
            f"mode='{mode}' in fabric '{self._fabric_name}': {', '.join(offender_descriptions)}. "
            f"Verify via GET {endpoint_path}."
        )

    def invalidate(self) -> None:
        """
        # Summary

        Drop all cached capability data so the next access re-fetches from the API.

        ## Raises

        None
        """
        self._cache.clear()
        self._id_cache.clear()
