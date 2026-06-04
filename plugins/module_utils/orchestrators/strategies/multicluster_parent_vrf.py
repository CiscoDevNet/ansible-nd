# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import (
    MultisiteParentVrfStrategy,
)


class MulticlusterParentVrfStrategy(MultisiteParentVrfStrategy):
    """
    Strategy for Multicluster Parent (MFD) fabrics.

    Identical to MultisiteParentVrfStrategy except fabric_type and
    is_multicluster / is_multisite identity flags.
    """

    @property
    def fabric_type(self) -> str:
        return "multicluster_parent"

    @property
    def is_multicluster(self) -> bool:
        return True

    @property
    def is_multisite(self) -> bool:
        return False
