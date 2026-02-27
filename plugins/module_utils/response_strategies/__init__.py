# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Response validation strategies for different API versions.

This module provides version-specific response validation strategies
that can be injected into ResponseHandler to handle differences in
HTTP status codes and error message formats across API versions.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.response_strategies.base_strategy import ResponseValidationStrategy
from ansible_collections.cisco.nd.plugins.module_utils.response_strategies.nd_v1_strategy import NdV1Strategy

__all__ = [
    "ResponseValidationStrategy",
    "NdV1Strategy",
]
