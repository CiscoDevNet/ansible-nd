# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsNetworksGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_resolver import (
    FabricResolverBase,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_network import (
    ChildNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_network import (
    MulticlusterParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_network import (
    MultisiteParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import (
    StandaloneNetworkStrategy,
)


class NetworkFabricResolver(FabricResolverBase):
    """
    Network adapter for the common ND Manage fabric resolver.

    The shared base owns topology detection and MCFG/MSD disambiguation.  This
    class supplies the Network-specific OneManage probe endpoint, enrichment
    key, and strategy classes.
    """

    resource_name = "Network"
    resource_type_key = "networkType"
    resource_get_cls = EpOneManageFabricsNetworksGet
    standalone_strategy_cls = StandaloneNetworkStrategy
    multisite_parent_strategy_cls = MultisiteParentNetworkStrategy
    multicluster_parent_strategy_cls = MulticlusterParentNetworkStrategy
    child_strategy_cls = ChildNetworkStrategy
