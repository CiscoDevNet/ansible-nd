# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akshayant Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""nd_manage_switches utilities package.

Re-exports all utility classes, functions, and exceptions so that
consumers can import directly from the package:

    from .utils.nd_manage_switches import (
        SwitchOperationError, PayloadUtils, FabricUtils, SwitchWaitUtils,
        mask_password, get_switch_field, determine_operation_type,
        group_switches_by_credentials, query_bootstrap_switches,
        build_bootstrap_index, build_poap_data_block,
    )
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from .exceptions import SwitchOperationError  # noqa: F401
from .payload_utils import PayloadUtils, mask_password  # noqa: F401
from .fabric_utils import FabricUtils  # noqa: F401
from .switch_wait_utils import SwitchWaitUtils  # noqa: F401
from .switch_helpers import (  # noqa: F401
    get_switch_field,
    determine_operation_type,
    group_switches_by_credentials,
)
from .bootstrap_utils import (  # noqa: F401
    query_bootstrap_switches,
    build_bootstrap_index,
    build_poap_data_block,
)


__all__ = [
    "SwitchOperationError",
    "PayloadUtils",
    "FabricUtils",
    "SwitchWaitUtils",
    "mask_password",
    "get_switch_field",
    "determine_operation_type",
    "group_switches_by_credentials",
    "query_bootstrap_switches",
    "build_bootstrap_index",
    "build_poap_data_block",
]
