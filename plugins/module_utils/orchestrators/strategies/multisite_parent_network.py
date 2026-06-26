# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


import copy

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NetworkParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
    network_parent_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import (
    StandaloneNetworkStrategy,
)


class MultisiteParentNetworkStrategy(StandaloneNetworkStrategy):
    """
    Strategy for Multisite Parent (MSD) fabrics.

    Extends StandaloneNetworkStrategy with:
    - child_fabric_config in the argument spec
    - Child task construction that targets each member fabric

    API endpoints are the same as standalone (MSD parent Network operations
    use the same /api/v1/manage/fabrics/{fabricName}/networks surface).
    """

    @property
    def fabric_type(self) -> str:
        return "multisite_parent"

    @property
    def is_parent(self) -> bool:
        return True

    @property
    def is_multisite(self) -> bool:
        return True

    @property
    def config_model_cls(self) -> type:
        return NetworkParentConfigModel

    def get_argument_spec(self) -> dict[str, Any]:
        """Parent fabrics expose the child_fabric_config parameter."""
        return network_parent_argument_spec()

    def build_child_task_args(
        self,
        child_fabric_name: str,
        network_configs: list[dict],
        state: str,
    ) -> dict[str, Any]:
        """
        Build module_args for executing nd_manage_networks against a Multisite child fabric.

        The child task runs as a standalone operation (no further child splitting).
        deploy is forced to False — the parent handles deployment.
        nd_version is NOT passed; it is an internal detail not exposed to modules.
        """
        child_configs = copy.deepcopy(network_configs)
        for cfg in child_configs:
            cfg["deploy"] = False

        # Translate 'overridden' to 'replaced' for child fabric compatibility
        child_state = "replaced" if state == "overridden" else state

        return {
            "fabric_name": child_fabric_name,
            "state": child_state,
            "config": child_configs,
        }
