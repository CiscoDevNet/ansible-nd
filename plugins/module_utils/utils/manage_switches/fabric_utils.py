# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Fabric-level operations: config save, deploy, and info retrieval."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import time
from typing import Any, Dict, Optional

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricConfigDeployPost,
    EpManageFabricGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions import (
    EpManageFabricsActionsConfigSavePost,
)

from .exceptions import SwitchOperationError


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

        self.ep_fabric_get = EpManageFabricGet()
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
        last_error: Exception = SwitchOperationError(
            f"Config save produced no attempts for fabric {self.fabric}"
        )
        for attempt in range(1, max_retries + 1):
            try:
                response = self._request_endpoint(
                    self.ep_config_save, action="Config save"
                )
                self.log.info(
                    f"Config save succeeded on attempt "
                    f"{attempt}/{max_retries} for fabric {self.fabric}"
                )
                return response
            except SwitchOperationError as exc:
                last_error = exc
                self.log.warning(
                    f"Config save attempt {attempt}/{max_retries} failed "
                    f"for fabric {self.fabric}: {exc}"
                )
                if attempt < max_retries:
                    self.log.info(
                        f"Retrying config save in {retry_delay}s "
                        f"(attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(retry_delay)
        raise SwitchOperationError(
            f"Config save failed after {max_retries} attempt(s) "
            f"for fabric {self.fabric}: {last_error}"
        )

    def deploy_config(self) -> Dict[str, Any]:
        """Deploy pending configuration to all switches in the fabric.

        The ``configDeploy`` endpoint requires no request body; it deploys
        all pending changes for the fabric.

        Returns:
            API response dict.

        Raises:
            SwitchOperationError: If the deploy request fails.
        """
        return self._request_endpoint(
            self.ep_config_deploy, action="Config deploy"
        )

    def get_fabric_info(self) -> Dict[str, Any]:
        """Retrieve fabric information.

        Returns:
            Fabric information dict.

        Raises:
            SwitchOperationError: If the request fails.
        """
        return self._request_endpoint(
            self.ep_fabric_get, action="Get fabric info"
        )

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _request_endpoint(
        self, endpoint, action: str = "Request"
    ) -> Dict[str, Any]:
        """Execute a request against a pre-configured endpoint.

        Args:
            endpoint: Endpoint object with ``.path`` and ``.verb``.
            action:   Human-readable label for log messages.

        Returns:
            API response dict.

        Raises:
            SwitchOperationError: On any request failure.
        """
        self.log.info(f"{action} for fabric: {self.fabric}")
        try:
            response = self.nd.request(endpoint.path, verb=endpoint.verb)
            self.log.info(
                f"{action} completed for fabric: {self.fabric}"
            )
            return response
        except Exception as e:
            self.log.error(
                f"{action} failed for fabric {self.fabric}: {e}"
            )
            raise SwitchOperationError(
                f"{action} failed for fabric {self.fabric}: {e}"
            ) from e


__all__ = [
    "FabricUtils",
]
