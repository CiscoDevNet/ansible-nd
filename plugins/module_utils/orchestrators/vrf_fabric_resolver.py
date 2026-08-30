# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_vrfs import (
    EpOneManageFabricsVrfsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_resolver import (
    FabricResolverBase,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_vrf import (
    ChildVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import (
    MulticlusterParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import (
    MultisiteParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import (
    StandaloneVrfStrategy,
)


class VrfFabricResolver(FabricResolverBase):
    """
    VRF adapter for the common ND Manage fabric resolver.

    The shared base owns topology detection and MCFG/MSD disambiguation.  This
    class supplies the VRF-specific OneManage probe endpoint, enrichment key,
    and strategy classes.
    """

    resource_name = "VRF"
    resource_type_key = "vrfType"
    resource_get_cls = EpOneManageFabricsVrfsGet
    standalone_strategy_cls = StandaloneVrfStrategy
    multisite_parent_strategy_cls = MultisiteParentVrfStrategy
    multicluster_parent_strategy_cls = MulticlusterParentVrfStrategy
    child_strategy_cls = ChildVrfStrategy
