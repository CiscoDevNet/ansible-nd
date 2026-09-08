# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Lazy cache for full Manage fabric details.

Provides `FabricDetailsCache`, a lazy-loaded cache of full fabric details
from `/api/v1/manage/fabrics/{fabric_name}` for switch fabric capability
validation.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import EpManageFabricsGet
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

_NOT_FETCHED = object()


class FabricDetailsCache:
    """
    Cached full fabric details for callers that need fabric properties.

    Fetches the full fabric details endpoint through RestSend and caches the
    response for the current module run.
    """

    def __init__(self, rest_send: RestSend, fabric_name: str):
        """
        # Summary

        Initialize the fabric details cache with a RestSend instance and
        fabric name.

        ## Raises

        None
        """
        self._rest_send = rest_send
        self._fabric_name = fabric_name
        self._fabric_details: dict[str, Any] | object = _NOT_FETCHED

    def _query_get(self, path: str) -> dict[str, Any] | None:
        """
        # Summary

        Issue a GET request via RestSend and return the response DATA dict.
        Returns ``None`` on HTTP 404 so callers can distinguish not-found from
        controller or transport failures.

        ## Raises

        - `RuntimeError`: Raised when RestSend reports a non-success response other
            than HTTP 404.
        - `ValueError`: Raised when the controller DATA payload is not a dictionary.
        """
        self._rest_send.path = path
        self._rest_send.verb = HttpVerbEnum.GET
        self._rest_send.commit()
        if self._rest_send.return_code == 404:
            return None
        if not self._rest_send.success:
            raise RuntimeError(f"GET {path} failed {self._rest_send.error_summary}")

        data = self._rest_send.response_current.get("DATA", {})
        if not isinstance(data, dict):
            raise ValueError(f"GET {path} returned {type(data).__name__}; expected dictionary DATA")
        return data

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return the fabric name this cache was created for.

        ## Raises

        None
        """
        return self._fabric_name

    @property
    def fabric_details(self) -> dict[str, Any] | None:
        """
        # Summary

        Return cached full fabric details from `/api/v1/manage/fabrics/{fabric_name}`.

        Returns `None` when the fabric endpoint returns 404.

        ## Raises

        - `RuntimeError`: Raised when the fabric details request fails with a
            non-404 controller or transport error.
        - `ValueError`: Raised when the controller DATA payload is not a
            dictionary.
        """
        if self._fabric_details is _NOT_FETCHED:
            ep = EpManageFabricsGet()
            ep.fabric_name = self._fabric_name
            self._fabric_details = self._query_get(ep.path)
        return self._fabric_details if isinstance(self._fabric_details, dict) else None

    def get_fabric_details(self) -> dict[str, Any]:
        """
        # Summary

        Return fabric details or raise when the fabric is not found.

        ## Raises

        - `ValueError`: Raised when the fabric details endpoint returns HTTP 404.
        """
        details = self.fabric_details
        if details is None:
            raise ValueError(f"Unable to determine fabric details for '{self._fabric_name}': fabric was not found")
        return details

    def get_fabric_type(self) -> str:
        """
        # Summary

        Return the canonical fabric type from full fabric details `management.type`.

        ## Raises

        - `ValueError`: Raised when fabric details are not found or the response
            does not contain a non-empty ``management.type`` value.
        """
        fabric_info = self.get_fabric_details()
        management = fabric_info.get("management")
        if not isinstance(management, dict):
            raise ValueError(f"Unable to determine fabric type for '{self._fabric_name}': response does not contain 'management.type'")

        fabric_type = management.get("type")
        if not isinstance(fabric_type, str) or not fabric_type.strip():
            raise ValueError(f"Unable to determine fabric type for '{self._fabric_name}': response does not contain a non-empty 'management.type'")
        return fabric_type.strip()

    def is_greenfield_debug_enabled(self) -> bool:
        """
        # Summary

        Return whether the fabric has greenfield debug enabled.

        ## Raises

        - `ValueError`: Raised when fabric details are not found.
        """
        fabric_info = self.get_fabric_details()
        management = fabric_info.get("management", {})
        if not isinstance(management, dict):
            return False
        flag = management.get("greenfieldDebugFlag", "")
        return isinstance(flag, str) and flag.lower() == "enable"

    def invalidate(self) -> None:
        """
        # Summary

        Drop cached fabric details.

        ## Raises

        None
        """
        self._fabric_details = _NOT_FETCHED
