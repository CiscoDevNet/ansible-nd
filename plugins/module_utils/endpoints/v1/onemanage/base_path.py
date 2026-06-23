# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Centralized base paths for ND onemanage API endpoints.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Final


class BasePath:
    """
    # Summary

    API endpoints for ND onemanage.
    """

    API: Final = "/appcenter/cisco/ndfc/api/v1/onemanage"

    @classmethod
    def path(cls, *segments: str, proxy_path: str = "") -> str:
        """
        # Summary

        Build an onemanage API path with an optional ND proxy prefix.
        """
        base = f"{proxy_path}{cls.API}"
        if not segments:
            return base
        return f"{base}/{'/'.join(segments)}"

    @classmethod
    def manage(cls, *segments: str, proxy_path: str = "") -> str:
        """
        # Summary

        Build an onemanage manage API path with an optional ND proxy prefix.
        """
        return cls.path("manage", *segments, proxy_path=proxy_path)

    @classmethod
    def manage_fabrics(cls, *segments: str, proxy_path: str = "") -> str:
        """
        # Summary

        Build an onemanage manage fabrics API path with an optional ND proxy prefix.
        """
        return cls.manage("fabrics", *segments, proxy_path=proxy_path)

    @classmethod
    def top_down(cls, *segments: str, proxy_path: str = "") -> str:
        """
        # Summary

        Build an onemanage top-down API path with an optional ND proxy prefix.
        """
        return cls.path("top-down", *segments, proxy_path=proxy_path)

    @classmethod
    def top_down_fabrics(cls, *segments: str, proxy_path: str = "") -> str:
        """
        # Summary

        Build an onemanage top-down fabrics API path with an optional ND proxy prefix.
        """
        return cls.top_down("fabrics", *segments, proxy_path=proxy_path)
