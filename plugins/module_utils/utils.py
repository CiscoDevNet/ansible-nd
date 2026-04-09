# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import logging
import time
from copy import deepcopy
from typing import Any, Dict, List, Optional, Union

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricConfigDeployPost,
    EpManageFabricsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions import (
    EpManageFabricsActionsConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switchactions import (
    EpManageFabricsSwitchActionsDeployPost,
)


def sanitize_dict(dict_to_sanitize, keys=None, values=None, recursive=True, remove_none_values=True):
    if keys is None:
        keys = []
    if values is None:
        values = []

    result = deepcopy(dict_to_sanitize)
    for k, v in dict_to_sanitize.items():
        if k in keys:
            del result[k]
        elif v in values or (v is None and remove_none_values):
            del result[k]
        elif isinstance(v, dict) and recursive:
            result[k] = sanitize_dict(v, keys, values)
        elif isinstance(v, list) and recursive:
            for index, item in enumerate(v):
                if isinstance(item, dict):
                    result[k][index] = sanitize_dict(item, keys, values)
    return result


def issubset(subset: Any, superset: Any) -> bool:
    """Check if subset is contained in superset."""
    if type(subset) is not type(superset):
        return False

    if not isinstance(subset, dict):
        if isinstance(subset, list):
            if len(subset) != len(superset):
                return False

            remaining = list(superset)
            for item in subset:
                for index, candidate in enumerate(remaining):
                    if issubset(item, candidate) and issubset(candidate, item):
                        del remaining[index]
                        break
                else:
                    return False
            return True
        return subset == superset

    for key, value in subset.items():
        if value is None:
            continue

        if key not in superset:
            return False

        if not issubset(value, superset[key]):
            return False

    return True


def remove_unwanted_keys(data: Dict, unwanted_keys: List[Union[str, List[str]]]) -> Dict:
    """Remove unwanted keys from dict (supports nested paths)."""
    data = deepcopy(data)

    for key in unwanted_keys:
        if isinstance(key, str):
            if key in data:
                del data[key]

        elif isinstance(key, list) and len(key) > 0:
            try:
                parent = data
                for k in key[:-1]:
                    if isinstance(parent, dict) and k in parent:
                        parent = parent[k]
                    else:
                        break
                else:
                    if isinstance(parent, dict) and key[-1] in parent:
                        del parent[key[-1]]
            except (KeyError, TypeError, IndexError):
                pass

    return data


# =========================================================================
# Exceptions
# =========================================================================


class SwitchOperationError(Exception):
    """Raised when a switch operation fails."""


# =========================================================================
# Fabric Utilities
# =========================================================================


class FabricUtils:
    """Fabric-level operations: config save, deploy, and info retrieval."""

    def __init__(
        self,
        nd_module,
        fabric: str,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize FabricUtils.

        Args:
            nd_module: NDModule or NDNetworkResourceModule instance.
            fabric:    Fabric name.
            logger:    Optional logger; defaults to ``nd.FabricUtils``.
        """
        self.nd = nd_module
        self.fabric = fabric
        self.log = logger or logging.getLogger("nd.FabricUtils")

        # Pre-configure endpoints
        self.ep_config_save = EpManageFabricsActionsConfigSavePost()
        self.ep_config_save.fabric_name = fabric

        self.ep_config_deploy = EpManageFabricConfigDeployPost()
        self.ep_config_deploy.fabric_name = fabric

        self.ep_switch_deploy = EpManageFabricsSwitchActionsDeployPost()
        self.ep_switch_deploy.fabric_name = fabric

        self.ep_fabric_get = EpManageFabricsGet()
        self.ep_fabric_get.fabric_name = fabric

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def save_config(
        self,
        max_retries: int = 3,
        retry_delay: int = 600,
    ) -> Dict[str, Any]:
        """Save (recalculate) fabric configuration.

        Retries up to ``max_retries`` times with ``retry_delay`` seconds
        between attempts.

        Args:
            max_retries:  Maximum number of attempts (default ``3``).
            retry_delay:  Seconds to wait between failed attempts
                          (default ``600``).

        Returns:
            API response dict from the first successful attempt.

        Raises:
            SwitchOperationError: If all attempts fail.
        """
        last_error: Exception = SwitchOperationError(f"Config save produced no attempts for fabric {self.fabric}")
        for attempt in range(1, max_retries + 1):
            try:
                response = self._request_endpoint(self.ep_config_save, action="Config save")
                self.log.info(
                    "Config save succeeded on attempt %s/%s for fabric %s",
                    attempt,
                    max_retries,
                    self.fabric,
                )
                return response
            except SwitchOperationError as exc:
                last_error = exc
                self.log.warning(
                    "Config save attempt %s/%s failed for fabric %s: %s",
                    attempt,
                    max_retries,
                    self.fabric,
                    exc,
                )
                if attempt < max_retries:
                    self.log.info(
                        "Retrying config save in %ss (attempt %s/%s)",
                        retry_delay,
                        attempt + 1,
                        max_retries,
                    )
                    time.sleep(retry_delay)
        raise SwitchOperationError(f"Config save failed after {max_retries} attempt(s) " f"for fabric {self.fabric}: {last_error}")

    def deploy_config(self) -> Dict[str, Any]:
        """Deploy pending configuration to all switches in the fabric.

        The ``configDeploy`` endpoint requires no request body; it deploys
        all pending changes for the fabric.

        Returns:
            API response dict.

        Raises:
            SwitchOperationError: If the deploy request fails.
        """
        return self._request_endpoint(self.ep_config_deploy, action="Config deploy")

    def deploy_switches(self, serial_numbers: List[str]) -> Dict[str, Any]:
        """Deploy pending configuration for specific switches only.

        Uses the switch-level deploy endpoint which targets only the supplied
        switches rather than all pending changes for the entire fabric.

        Args:
            serial_numbers: Switch serial numbers (identifiers) to deploy.

        Returns:
            API response dict.

        Raises:
            SwitchOperationError: If the deploy request fails.
        """
        self.log.info(
            "Switch-level deploy for %s switch(es) in fabric: %s",
            len(serial_numbers),
            self.fabric,
        )
        try:
            response = self.nd.request(
                self.ep_switch_deploy.path,
                verb=self.ep_switch_deploy.verb,
                data={"switchIds": serial_numbers},
            )
            self.log.info("Switch-level deploy completed for fabric: %s", self.fabric)
            return response
        except Exception as e:
            self.log.error("Switch-level deploy failed for fabric %s: %s", self.fabric, e)
            raise SwitchOperationError(f"Switch-level deploy failed for fabric {self.fabric}: {e}") from e

    def get_fabric_info(self) -> Dict[str, Any]:
        """Retrieve fabric information.

        Returns:
            Fabric information dict.

        Raises:
            SwitchOperationError: If the request fails.
        """
        return self._request_endpoint(self.ep_fabric_get, action="Get fabric info")

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _request_endpoint(self, endpoint, action: str = "Request") -> Dict[str, Any]:
        """Execute a request against a pre-configured endpoint.

        Args:
            endpoint: Endpoint object with ``.path`` and ``.verb``.
            action:   Human-readable label for log messages.

        Returns:
            API response dict.

        Raises:
            SwitchOperationError: On any request failure.
        """
        self.log.info("%s for fabric: %s", action, self.fabric)
        try:
            response = self.nd.request(endpoint.path, verb=endpoint.verb)
            self.log.info("%s completed for fabric: %s", action, self.fabric)
            return response
        except Exception as e:
            self.log.error("%s failed for fabric %s: %s", action, self.fabric, e)
            raise SwitchOperationError(f"{action} failed for fabric {self.fabric}: {e}") from e
