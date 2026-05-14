# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Centralized base paths for top-down and resource-manager NDFC endpoints.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Final


class TopDownBasePath:
    """Base path helper for top-down lan-fabric APIs."""

    API: "Final" = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down"

    @classmethod
    def path(cls, *segments: str) -> str:
        if not segments:
            return cls.API
        return f"{cls.API}/{'/'.join(segments)}"


class ResourceManagerBasePath:
    """Base path helper for resource-manager APIs."""

    API: "Final" = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/resource-manager"

    @classmethod
    def path(cls, *segments: str) -> str:
        if not segments:
            return cls.API
        return f"{cls.API}/{'/'.join(segments)}"
