# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Reusable fabric context for pre-flight validation and switch resolution.

Provides `FabricContext`, a lazy-loaded cache of fabric metadata and switch mappings
that orchestrators use to validate preconditions before CRUD operations.

Uses the `/api/v1/manage/fabrics/{fabric_name}` endpoint to verify fabric existence.

NOTE: The `fabric_is_local` and `fabric_is_read_only` checks are stubbed to always return
True / False respectively until we identify the correct response fields from the fabric
detail endpoint. The fabric detail response does not include `local` or `meta.allowedActions`
fields that the original implementation assumed.
"""

from typing import Optional

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import EpManageFabricsSummaryGet
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import EpManageSwitchesListGet
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

# Sentinel to distinguish "not yet fetched" from "fetched but not found"
_NOT_FETCHED = object()


class FabricContext:
    """
    # Summary

    Cached fabric metadata with pre-flight validation for fabric-level orchestrators.

    Lazily fetches fabric summary and switch inventory on first access. Provides simple
    boolean checks and a `validate_for_mutation` method that raises `RuntimeError` with
    a clear message when the fabric cannot be modified.

    TODO: `fabric_is_local` and `fabric_is_read_only` are stubs. The `GET /api/v1/manage/fabrics/{fabricName}` response does
    not currently expose the fields the original implementation expected (`local`, `meta.allowedActions`). Until the correct
    fields or alternative endpoints are identified, these checks are intentionally excluded from `validate_for_mutation` to
    avoid silently passing pre-flight checks. Re-add them to `validate_for_mutation` once the underlying checks return
    real data.

    ## Raises

    ### RuntimeError

    - Via `validate_for_mutation` if the fabric does not exist on any ND node.
    - Via `get_switch_id` if no switch matches the given management IP.
    - Via `get_switch_ip` if no switch matches the given switch ID.
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
        self._fabric_summary = _NOT_FETCHED
        self._switch_map: Optional[dict[str, str]] = None
        self._switch_map_by_id: Optional[dict[str, str]] = None

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
    def fabric_summary(self) -> Optional[dict]:
        """
        # Summary

        Return the cached fabric detail dict, fetching it from the `/fabrics/{fabric_name}` endpoint on first access.

        Returns `None` if the fabric does not exist.

        ## Raises

        None
        """
        if self._fabric_summary is _NOT_FETCHED:
            ep = EpManageFabricsSummaryGet()
            ep.fabric_name = self._fabric_name
            result = self._query_get(ep.path)
            self._fabric_summary = result if result else None
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

        Check whether the fabric is local to the target ND node.

        TODO: The `GET /api/v1/manage/fabrics/{fabricName}` response does not include a `local` field. This check needs
        to be reimplemented once the correct field or endpoint is identified. Currently returns `True` if the fabric exists.

        ## Raises

        None
        """
        if not self.fabric_exists():
            return False
        # TODO: Implement local check once the correct response field is identified
        return True

    def fabric_is_read_only(self) -> bool:
        """
        # Summary

        Check whether the fabric is in a read-only state that prevents mutations.

        TODO: The `GET /api/v1/manage/fabrics/{fabricName}` response does not include `meta.allowedActions`. This check
        needs to be reimplemented once the correct field or endpoint is identified. Currently returns `False` (not
        read-only) if the fabric exists.

        ## Raises

        None
        """
        if not self.fabric_exists():
            return False
        # TODO: Implement read-only check once the correct response field is identified
        return False

    def _load_switch_maps(self) -> None:
        """
        # Summary

        Fetch the fabric switch inventory once and populate both the IP-keyed and ID-keyed lookup maps.

        ## Raises

        ### RuntimeError

        - If the switches API query fails.
        """
        if self._switch_map is not None:
            return
        ep = EpManageSwitchesListGet()
        ep.fabric_name = self._fabric_name
        result = self._query_get(ep.path)
        switches = (result.get("switches") or []) if result else []
        self._switch_map = {sw["fabricManagementIp"]: sw["switchId"] for sw in switches if sw.get("fabricManagementIp") and sw.get("switchId")}
        self._switch_map_by_id = {sw["switchId"]: sw["fabricManagementIp"] for sw in switches if sw.get("switchId") and sw.get("fabricManagementIp")}

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
        assert self._switch_map is not None
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
        assert self._switch_map_by_id is not None
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

    def validate_for_mutation(self) -> None:
        """
        # Summary

        Run pre-flight checks required before modifying resources in this fabric. Raises `RuntimeError` with a clear,
        actionable message on the first failing check.

        ## Checks

        1. Fabric exists (on any node in the cluster).

        See the class-level TODO: `fabric_is_local` and `fabric_is_read_only` are intentionally not invoked here while their
        underlying implementations are stubs. They will be re-added once the relevant fields are exposed by the API.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist.
        """
        if not self.fabric_exists():
            raise RuntimeError(f"Fabric '{self._fabric_name}' not found. Verify the fabric name and ensure you are targeting the correct ND node.")
