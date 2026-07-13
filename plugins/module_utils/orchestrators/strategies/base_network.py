# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from abc import ABC, abstractmethod

from typing import Any


class BaseNetworkStrategy(ABC):
    """
    Abstract base for Network endpoint and workflow strategies.

    A strategy encapsulates:
    - Which API endpoints to use (fabric-type-specific paths)
    - Which Ansible argument spec variant is valid for this fabric type
    - How child fabric tasks are created and executed (parent types only)

    Concrete strategies are selected at runtime by NetworkFabricResolver
    based on the fabric type returned by the ND API.
    """

    def __init__(
        self,
        fabric_name: str,
        fabric_data: dict[str, Any] | None = None,
        **kwargs,
    ):
        """
        Args:
            fabric_name: The fabric this strategy operates on.
            fabric_data: Raw fabric association dict from the ND API.
        """
        self.fabric_name = fabric_name
        self.fabric_data = fabric_data or {}

    # ── Fabric type identity ────────────────────────────────────────

    @property
    @abstractmethod
    def fabric_type(self) -> str:
        """
        Human-readable fabric type tag used in result dicts.

        Examples: "standalone", "multisite_parent", "multicluster_child"
        """

    @property
    def is_parent(self) -> bool:
        """True for parent (MSD / MFD) fabric strategies."""
        return False

    @property
    def is_child(self) -> bool:
        """True for child member fabric strategies."""
        return False

    @property
    def is_multicluster(self) -> bool:
        """True for Multicluster (MFD) strategies."""
        return False

    @property
    def is_multisite(self) -> bool:
        """True for Multisite (MSD) strategies."""
        return False

    # ── Argument-spec selection ────────────────────────────────────

    @abstractmethod
    def get_argument_spec(self) -> dict[str, Any]:
        """
        Return the Ansible argument_spec dict appropriate for this fabric type.

        Parent fabrics include child_fabric_config; child/standalone do not.
        """

    @property
    @abstractmethod
    def config_model_cls(self) -> type:
        """
        The Pydantic config model class for this fabric topology.

        - Standalone / child → NetworkConfigModel
        - Parent (MSD / MFD) → NetworkParentConfigModel
        """

    # ── Endpoint class accessors ───────────────────────────────────
    # These return the *class* (not an instance) so the orchestrator
    # can instantiate them and set per-call identifiers.

    @abstractmethod
    def networks_get_cls(self) -> type:
        """Endpoint class for GET (list) Networks."""

    @abstractmethod
    def networks_post_cls(self) -> type:
        """Endpoint class for POST (create) Network(s)."""

    @abstractmethod
    def network_put_cls(self) -> type:
        """Endpoint class for PUT (replace) a single Network."""

    @abstractmethod
    def network_delete_cls(self) -> type:
        """Endpoint class for DELETE a single Network."""

    @abstractmethod
    def network_actions_deploy_post_cls(self) -> type:
        """Endpoint class for POST deploy Network action."""

    @abstractmethod
    def network_actions_remove_post_cls(self) -> type:
        """Endpoint class for POST bulk-remove Network action."""

    # ── Query param builders ───────────────────────────────────────

    @abstractmethod
    def build_query_all_params(self, **kwargs) -> dict[str, Any] | None:
        """Return query-string params dict for the list-Networks request."""

    # ── Endpoint configuration hook ─────────────────────────────────

    def configure_endpoint(self, ep) -> None:
        """
        Hook called by NDNetworkOrchestrator._make_endpoint after fabric_name is set.

        Override to inject extra per-call parameters into the endpoint (e.g.
        cluster_name for Multicluster child fabrics).  Default is a no-op.
        """

    # ── Child task helpers (no-ops for non-parent strategies) ──────

    def child_fabric_members(self) -> list[str]:
        """
        Return the list of member (child) fabric names.

        Returns [] for strategies that have no children.
        """
        return [m.get("fabricName", "") for m in self.fabric_data.get("members", []) if m.get("fabricName")]

    def build_child_task_args(self, child_fabric_name: str, network_configs: list[dict], state: str) -> dict[str, Any]:
        """
        Build the module_args dict for a child fabric invocation.

        Override in parent strategies to inject fabric_details.
        Default raises — non-parent strategies should never call this.
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support child fabric tasks.")
