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

from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import EpManageFabricsSummaryGet
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import EpManageSwitchesListGet

# Sentinel to distinguish "not yet fetched" from "fetched but not found"
_NOT_FETCHED = object()


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
    - Via `validate_for_mutation` if the fabric is not local to the target ND node.
    - Via `validate_for_mutation` if the fabric is in deployment-freeze mode.
    - Via `get_switch_id` if no switch matches the given management IP.
    """

    def __init__(self, sender: NDModule, fabric_name: str):
        """
        # Summary

        Initialize `FabricContext` with a sender and fabric name. Metadata is not fetched until needed.

        ## Raises

        None
        """
        self._sender = sender
        self._fabric_name = fabric_name
        self._fabric_summary = _NOT_FETCHED
        self._switch_map: Optional[dict[str, str]] = None

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
            result = self._sender.query_obj(ep.path, ignore_not_found_error=True)
            # query_obj returns {} for 404 / not found
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
        if self._switch_map is None:
            ep = EpManageSwitchesListGet()
            ep.fabric_name = self._fabric_name
            result = self._sender.query_obj(ep.path, ignore_not_found_error=True)
            switches = (result.get("switches") or []) if result else []
            self._switch_map = {switch["fabricManagementIp"]: switch["switchId"] for switch in switches if "fabricManagementIp" in switch}
        return self._switch_map

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

    def validate_for_mutation(self) -> None:
        """
        # Summary

        Run all pre-flight checks required before modifying resources in this fabric. Raises `RuntimeError` with a clear,
        actionable message on the first failing check.

        ## Checks

        1. Fabric exists (on any node in the cluster).
        2. Fabric is local to this ND node (not a remote fabric visible via cluster forwarding).
        3. Fabric is not in a read-only state (deployment-freeze mode or empty `allowedActions`).

        ## Raises

        ### RuntimeError

        - If the fabric does not exist.
        - If the fabric is not local to this ND node.
        - If the fabric is in a read-only state.
        """
        if not self.fabric_exists():
            raise RuntimeError(f"Fabric '{self._fabric_name}' not found. " f"Verify the fabric name and ensure you are targeting the correct ND node.")
        if not self.fabric_is_local():
            raise RuntimeError(
                f"Fabric '{self._fabric_name}' is not local to this Nexus Dashboard node. "
                f"Target the ND node that owns the fabric (ownerCluster: "
                f"'{self.fabric_summary.get('ownerCluster', 'unknown')}')."
            )
        if self.fabric_is_read_only():
            raise RuntimeError(
                f"Fabric '{self._fabric_name}' is in a read-only state and cannot be modified. " f"Check that deployment-freeze mode is not enabled."
            )
