# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List, ClassVar
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class NDNestedModel(NDBaseModel):
    """
    Base for nested models without identifiers.
    """

    # NOTE: model_config, ClassVar, and Fields can be overwritten here if needed

    identifiers: ClassVar[List[str]] = []
