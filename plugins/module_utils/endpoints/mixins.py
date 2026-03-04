# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Reusable mixin classes for endpoint models.

This module provides mixin classes that can be composed to add common
fields to endpoint models without duplication.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Optional
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import BaseModel, Field


class LoginIdMixin(BaseModel):
    """Mixin for endpoints that require login_id parameter."""

    login_id: Optional[str] = Field(default=None, min_length=1, description="Login ID")
