# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

"""
Centralized base paths for ND API endpoints.

This module provides a single location to manage all API Infra base paths,
allowing easy modification when API paths change. All endpoint classes
should use these path builders for consistency.
"""
__author__ = "Allen Robel"

from typing import Final

# Root API paths
ND_ANALYZE_API: Final = "/api/v1/analyze"
ND_INFRA_API: Final = "/api/v1/infra"
ND_MANAGE_API: Final = "/api/v1/manage"
ND_ONEMANAGE_API: Final = "/api/v1/onemanage"
ND_MSO_API: Final = "/mso"
NDFC_API: Final = "/appcenter/cisco/ndfc/api"
LOGIN: Final = "/login"
