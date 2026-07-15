# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Reusable fabric context for pre-flight validation and switch resolution.

Provides `FabricContext`, a lazy-loaded cache of fabric metadata and switch mappings
that orchestrators use to validate preconditions before CRUD operations.

Uses the `/api/v1/manage/fabrics/{fabric_name}/summary` endpoint to verify fabric existence and read
the `local` and `fabricStatus` fields used by the pre-flight checks.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import EpManageFabricsSummaryGet
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import EpManageSwitchesListGet
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, PlatformTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class FabricContext:
    """
    # Summary

    Cached fabric metadata with pre-flight validation for fabric-level orchestrators.

    Lazily fetches fabric summary and switch inventory on first access. Provides simple
    boolean checks and a `validate_for_mutation` method that raises `RuntimeError` with
    a clear message when the fabric cannot be modified.

    ## Raises

    ### RuntimeError

    - Via `validate_for_mutation` if the fabric does not exist on any ND node.
    - Via `get_switch_id` if no switch matches the given management IP.
    - Via `get_switch_ip` if no switch matches the given switch ID.
    - Via `get_platform_type` if no switch matches the given management IP.
    - Via `fabric_summary` if the summary payload carries an embedded `code` error key.
    - Via the `switches` / `switch_map` accessors if the fabric does not exist.
    """

    def __init__(self, rest_send: RestSend, fabric_name: str):
        """
        # Summary

        Initialize `FabricContext` with a `RestSend` instance and fabric name. Metadata is not fetched until needed.

        ## Raises

        None
        """
        self._rest_send = rest_send
        self._fabric_name = fabric_name
        # `_fabric_summary_fetched` distinguishes "not yet fetched" from "fetched but the fabric does not exist" (None).
        self._fabric_summary: dict | None = None
        self._fabric_summary_fetched = False
        self._switches: list[dict] | None = None
        self._switch_map: dict[str, str] | None = None
        self._switch_map_by_id: dict[str, str] | None = None

    def _fabric_not_found_message(self) -> str:
        """
        # Summary

        Return the standard user-facing "fabric not found" message for this context's fabric name. Shared by
        `validate_for_mutation` and `_load_switch_maps` so both surface identical wording.

        ## Raises

        None
        """
        return f"Fabric '{self._fabric_name}' not found. Verify the fabric name and ensure you are targeting the correct ND node."

    def _query_get(self, path: str) -> dict:
        """
        # Summary

        Issue a GET request via `RestSend` and return the `DATA` dict from the response. Returns `{}` on HTTP 404.

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

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return the fabric name this context was created for.

        ## Raises

        None
        """
        return self._fabric_name

    @property
    def fabric_summary(self) -> dict | None:
        """
        # Summary

        Return the cached fabric detail dict, fetching it from the `/api/v1/manage/fabrics/{fabric_name}/summary` endpoint on first access.

        Returns `None` if the fabric does not exist.

        Fails closed: ND signals some errors by embedding `{"code": <N>, "message": "<reason>"}` in an otherwise-successful
        response body. Rather than accept such a payload as a valid summary (which would let every `validate_for_mutation`
        check default open), a payload carrying a `code` key is rejected with `RuntimeError`.

        ## Raises

        ### RuntimeError

        - If the summary payload carries an embedded `code` error key instead of a fabric summary.
        """
        if not self._fabric_summary_fetched:
            ep = EpManageFabricsSummaryGet()
            ep.fabric_name = self._fabric_name
            result = self._query_get(ep.path)
            if result and "code" in result:
                raise RuntimeError(f"GET {ep.path} returned an embedded error instead of a fabric summary: {result.get('message', result)}")
            self._fabric_summary = result if result else None
            self._fabric_summary_fetched = True
        return self._fabric_summary

    def fabric_exists(self) -> bool:
        """
        # Summary

        Check whether the fabric exists (on any ND node in the cluster).

        ## Raises

        None
        """
        return self.fabric_summary is not None

    def fabric_is_local(self) -> bool:
        """
        # Summary

        Check whether the fabric is owned by the controller this `RestSend` is logged in to.

        Reads the `local` boolean from the cached `fabric_summary`. In a multi-controller cluster, the same fabric is
        visible from every node but mutations must be issued against its owning controller — `local: false` means we
        are connected to a non-owner. If the field is absent (single-controller setups or older API variants), this
        method assumes the fabric is local rather than blocking valid operations.

        Returns `False` if the fabric does not exist.

        ## Raises

        None
        """
        summary = self.fabric_summary
        if summary is None:
            return False
        return bool(summary.get("local", True))

    def fabric_is_deployment_frozen(self) -> bool:
        """
        # Summary

        Check whether the fabric is in deployment freeze mode. When deployment freeze is enabled, configuration changes cannot be
        deployed from the controller to switches.

        Reads `fabricStatus` from the cached `fabric_summary` (`"frozen"` -> True, `"default"` -> False). The dedicated
        `/api/v1/manage/fabrics/{fabric_name}/deploymentFreeze` endpoint carries the same information but is reserved for
        callers that need a focused query or a corresponding PUT (e.g. a future `nd_fabric_deployment_freeze` module).

        Returns `False` if the fabric does not exist (the fabric-existence error is surfaced separately by `validate_for_mutation`).

        ## Raises

        None
        """
        summary = self.fabric_summary
        if summary is None:
            return False
        return summary.get("fabricStatus") == "frozen"

    def invalidate(self) -> None:
        """
        # Summary

        Drop all cached state so the next access to `fabric_summary`, `switches`, `switch_map`, `switch_map_by_id`, or the
        `platformType` lookup re-fetches from the API. Useful after a mutation that should be reflected on subsequent reads.

        ## Raises

        None
        """
        self._fabric_summary = None
        self._fabric_summary_fetched = False
        self._switches = None
        self._switch_map = None
        self._switch_map_by_id = None

    def _load_switch_maps(self) -> None:
        """
        # Summary

        Fetch the fabric switch inventory once, retain the raw switch records, and populate the IP-keyed and ID-keyed
        lookup maps. Per-switch `platformType` is read on demand from the retained records by `get_platform_type`.

        Fails closed on a nonexistent fabric: the switches endpoint returns HTTP 404 when the parent fabric is absent.
        `_query_get` maps that 404 to an empty dict, which would otherwise yield empty maps and surface a misleading
        "switch not found" error downstream. Instead, a 404 here is confirmed against `fabric_summary` and re-raised as a
        clear "fabric not found" error, matching `validate_for_mutation`.

        ## Raises

        ### RuntimeError

        - If the switches API query fails.
        - If the fabric does not exist (switches GET 404 confirmed by an absent `fabric_summary`).
        """
        if self._switch_map is not None:
            return
        ep = EpManageSwitchesListGet()
        ep.fabric_name = self._fabric_name
        result = self._query_get(ep.path)
        # Not an ND deviation (no TODO/vault note): ND correctly returns 404 for a missing fabric. `_query_get` swallows
        # that 404 into `{}`, so we confirm against `fabric_summary` and raise the fabric-level error here rather than
        # letting an empty switch map surface a misleading "switch not found" downstream (issue #399).
        if self._rest_send.return_code == 404 and not self.fabric_exists():
            raise RuntimeError(self._fabric_not_found_message())
        switches = (result.get("switches") or []) if result else []
        self._switches = switches
        self._switch_map = {sw["fabricManagementIp"]: sw["switchId"] for sw in switches if sw.get("fabricManagementIp") and sw.get("switchId")}
        self._switch_map_by_id = {sw["switchId"]: sw["fabricManagementIp"] for sw in switches if sw.get("switchId") and sw.get("fabricManagementIp")}

    @property
    def switches(self) -> list[dict]:
        """
        # Summary

        Return the raw switch records as returned by the ND Manage Switches API for this fabric.

        Fetches the switch inventory on first access and caches it. Retaining the full records (rather than only the
        derived lookup maps) lets callers read per-switch attributes such as `platformType` without a second API call.

        A shallow copy of the cached list is returned so a caller appending to or removing from it cannot corrupt the
        cache or desync it from `switch_map` / `switch_map_by_id` (the per-record dicts are still shared references).

        ## Raises

        ### RuntimeError

        - If the switches API query fails.
        - If the fabric does not exist.
        """
        self._load_switch_maps()
        if self._switches is None:
            raise AssertionError("switches is None after _load_switch_maps()")
        return list(self._switches)

    @property
    def switch_map(self) -> dict[str, str]:
        """
        # Summary

        Return a cached mapping of `fabricManagementIp` to `switchId` for all switches in the fabric.

        Fetches all switches from the ND Manage Switches API on first access and caches the result.

        ## Raises

        ### RuntimeError

        - If the switches API query fails.
        """
        self._load_switch_maps()
        if self._switch_map is None:
            raise AssertionError("switch_map is None after _load_switch_maps()")
        return self._switch_map

    @property
    def switch_map_by_id(self) -> dict[str, str]:
        """
        # Summary

        Return a cached mapping of `switchId` to `fabricManagementIp` for all switches in the fabric.

        Fetches all switches from the ND Manage Switches API on first access and caches the result alongside `switch_map`.

        ## Raises

        ### RuntimeError

        - If the switches API query fails.
        """
        self._load_switch_maps()
        if self._switch_map_by_id is None:
            raise AssertionError("switch_map_by_id is None after _load_switch_maps()")
        return self._switch_map_by_id

    def get_switch_id(self, switch_ip: str) -> str:
        """
        # Summary

        Resolve a switch management IP address to its `switchId` via the cached switch map.

        ## Raises

        ### RuntimeError

        - If no switch matches the given IP in the fabric.
        """
        try:
            return self.switch_map[switch_ip]
        except KeyError as e:
            raise RuntimeError(f"No switch found with fabricManagementIp '{switch_ip}' in fabric '{self._fabric_name}'.") from e

    def get_switch_ip(self, switch_id: str) -> str:
        """
        # Summary

        Resolve a `switchId` (serial number) to its `fabricManagementIp` via the cached switch map.

        ## Raises

        ### RuntimeError

        - If no switch matches the given switch ID in the fabric.
        """
        try:
            return self.switch_map_by_id[switch_id]
        except KeyError as e:
            raise RuntimeError(f"No switch found with switchId '{switch_id}' in fabric '{self._fabric_name}'.") from e

    def get_platform_type(self, switch_ip: str) -> PlatformTypeEnum | None:
        """
        # Summary

        Resolve a switch management IP address to its `platformType` (as a `PlatformTypeEnum`) via the cached switch
        inventory. Callers use this to select the platform-appropriate feature model (e.g. `loopback` vs `iosXeLoopback`).

        Returns `None` when the switch exists in the fabric but reports no recognizable `platformType` (the field is
        nested under a `oneOf` variant and may be absent, or ND may report a value newer than `PlatformTypeEnum`).

        ## Raises

        ### RuntimeError

        - If no switch matches the given IP in the fabric.
        """
        if switch_ip not in self.switch_map:
            raise RuntimeError(f"No switch found with fabricManagementIp '{switch_ip}' in fabric '{self._fabric_name}'.")
        for switch in self.switches:
            if switch.get("fabricManagementIp") == switch_ip:
                raw = (switch.get("additionalData") or {}).get("platformType")
                try:
                    return PlatformTypeEnum(raw)
                except ValueError:
                    # Absent (None) or a value newer than PlatformTypeEnum -> no recognizable platform type.
                    return None
        return None

    def validate_for_mutation(self) -> None:
        """
        # Summary

        Run pre-flight checks required before modifying resources in this fabric. Raises `RuntimeError` with a clear,
        actionable message on the first failing check.

        ## Checks

        1. Fabric exists (on any node in the cluster).
        2. Fabric is owned by the controller this `RestSend` is connected to.
        3. Fabric is not in deployment freeze mode.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist.
        - If the fabric is owned by a different controller in the cluster.
        - If the fabric is in deployment freeze mode.
        """
        if not self.fabric_exists():
            raise RuntimeError(self._fabric_not_found_message())
        if not self.fabric_is_local():
            raise RuntimeError(
                f"Fabric '{self._fabric_name}' is owned by a different controller in this cluster. "
                "Connect to the controller that owns this fabric to make configuration changes."
            )
        if self.fabric_is_deployment_frozen():
            raise RuntimeError(
                f"Fabric '{self._fabric_name}' is in deployment freeze mode. Configuration changes cannot be deployed to switches "
                "while deployment freeze is enabled. Disable deployment freeze on the fabric before retrying."
            )
