# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel


class BaseLinkStrategy(ABC):
    """Abstract base for link endpoint strategies (single vs multi cluster scope)."""

    def __init__(
        self,
        fabric_name: str,
        cluster_name: str | None = None,
        ticket_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Store connection level context shared by every scope.

        ``fabric_name`` is required and becomes the ``fabricName`` query param on
        all reads. ``cluster_name`` and ``ticket_id`` are used only by the
        single cluster scope.
        """
        self.fabric_name = fabric_name
        self.cluster_name = cluster_name
        self.ticket_id = ticket_id

    @property
    @abstractmethod
    def links_get_cls(self) -> type[NDEndpointBaseModel]:
        """Endpoint class for GET (list/filter) links."""

    @property
    @abstractmethod
    def links_post_cls(self) -> type[NDEndpointBaseModel]:
        """Endpoint class for POST (bulk create) links."""

    @property
    @abstractmethod
    def link_put_cls(self) -> type[NDEndpointBaseModel]:
        """Endpoint class for PUT (single update) link."""

    @property
    @abstractmethod
    def link_actions_remove_post_cls(self) -> type[NDEndpointBaseModel]:
        """Endpoint class for POST (bulk delete) links."""

    @property
    @abstractmethod
    def identifier_fields(self) -> list[str]:
        """Model fields forming the composite identity for this scope."""

    @abstractmethod
    def configure_read(self, endpoint: Any, **kwargs: Any) -> None:
        """Populate ``endpoint.endpoint_params`` for a GET (read) request in this scope."""

    @abstractmethod
    def configure_mutation(self, endpoint: Any) -> None:
        """Populate ``endpoint.endpoint_params`` for a create/update/delete request in this scope."""
