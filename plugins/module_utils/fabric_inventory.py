# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import logging
from typing import Any, Dict, List, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)

# =========================================================================
# Exceptions
# =========================================================================


class SwitchOperationError(Exception):
    """Raised when a switch operation fails."""


# =========================================================================
# API Response Validation
# =========================================================================


class ApiDataChecker:
    """Detect controller-embedded errors in API response DATA payloads.

    The Nexus Dashboard API signals certain errors by embedding an error
    object inside ``DATA`` as ``{"code": <N>, "message": "<reason>"}`` even
    when the transport-level result is marked successful.  Any payload dict
    that contains a ``"code"`` key is treated as an error; the absence of
    ``"code"`` means the payload is a genuine data body.
    """

    @staticmethod
    def check(
        data: Any,
        context: str,
        log: logging.Logger,
        fail_callback=None,
    ) -> None:
        """Fail or raise if the response DATA contains an embedded error code.

        Args:
            data: Value returned by ``nd.request()`` or extracted from
                  ``response_current["DATA"]``.
            context: Human-readable description of the operation.
            log: Logger instance.
            fail_callback: Optional callable (e.g. ``module.fail_json``) that
                           accepts a ``msg`` keyword argument.  When provided
                           it is called on error instead of raising
                           ``SwitchOperationError``.
        """
        if isinstance(data, dict) and "code" in data:
            error_msg = data.get("message", "Unknown error")
            msg = f"{context} failed \u2014 controller returned error: " f"{error_msg} (code={data['code']})"
            log.error(msg)
            if fail_callback is not None:
                fail_callback(msg=msg)
            else:
                raise SwitchOperationError(msg)


# =========================================================================
# Fabric Switch Inventory
# =========================================================================


class FabricSwitchInventory:
    """Index a list of switch model instances for fast lookup by IP or ID.

    Use :meth:`from_fabric` to fetch, parse, and index in a single call, or
    construct directly from an already-parsed list.  :meth:`by_ip` and
    :meth:`by_id` return keyed lookup dicts.

    Example::

        inventory = FabricSwitchInventory.from_fabric(nd, fabric, log, SwitchDataModel)
        switch = inventory.by_ip().get("192.0.2.1")
        switch = inventory.by_id().get("FDO123456AB")
        collection = inventory.collection  # NDConfigCollection
    """

    def __init__(self, switches: List) -> None:
        """Initialise the index from an already-parsed list of switch models.

        Args:
            switches: List of parsed switch model instances.
        """
        self.switches: List = switches
        self.collection: Optional[NDConfigCollection] = None

    @classmethod
    def from_fabric(cls, nd, fabric: str, log: logging.Logger, model_class: Type) -> "FabricSwitchInventory":
        """Fetch, parse, and index the switch inventory for a fabric in one call.

        Args:
            nd: NDModule instance used for the API request.
            fabric: Fabric name to query.
            log: Logger instance.
            model_class: Pydantic model class to parse switch entries into
                         (e.g. ``SwitchDataModel``).

        Returns:
            A new ``FabricSwitchInventory`` with ``switches`` and
            ``collection`` populated.
        """
        raw = cls.query_fabric_switches(nd, fabric, log)
        collection = NDConfigCollection.from_api_response(response_data=raw, model_class=model_class)
        instance = cls(list(collection))
        instance.collection = collection
        return instance

    def by_ip(self) -> Dict[str, Any]:
        """Return switches keyed by fabric management IP address.

        Returns:
            Dict mapping ``fabric_management_ip`` → model instance.
            Entries with an empty or ``None`` IP are excluded.
        """
        return {sw.fabric_management_ip: sw for sw in self.switches if sw.fabric_management_ip}

    def by_id(self) -> Dict[str, Any]:
        """Return switches keyed by switch ID (serial number).

        Returns:
            Dict mapping ``switch_id`` → model instance.
            Entries with an empty or ``None`` ID are excluded.
        """
        return {sw.switch_id: sw for sw in self.switches if sw.switch_id}

    @staticmethod
    def query_fabric_switches(nd, fabric: str, log: logging.Logger) -> List[Dict[str, Any]]:
        """Fetch the raw switch inventory list for a fabric from the controller.

        Args:
            nd: NDModule instance used for the API request.
            fabric: Fabric name to query.
            log: Logger instance.

        Returns:
            List of raw switch dicts as returned by the controller API.
        """
        endpoint = EpManageFabricsSwitchesGet()
        endpoint.fabric_name = fabric
        log.debug("query_fabric_switches: querying inventory for fabric '%s'", fabric)

        try:
            response = nd.request(path=endpoint.path, verb=endpoint.verb)
        except Exception as exc:
            msg = f"Failed to retrieve switch inventory for fabric '{fabric}': {exc}"
            log.error(msg)
            nd.module.fail_json(msg=msg)
            return []

        ApiDataChecker.check(
            response,
            f"Switch inventory query for fabric '{fabric}'",
            log,
            nd.module.fail_json,
        )

        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            return response.get("switches", [])
        return []
