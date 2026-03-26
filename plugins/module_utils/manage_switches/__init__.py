# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""nd_manage_switches package.

Re-exports the orchestrator and utility classes so that consumers can
import directly from the package.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources import (  # noqa: F401
    NDSwitchResourceModule,
)
from ansible_collections.cisco.nd.plugins.module_utils.utils import (  # noqa: F401
    SwitchOperationError,
    FabricUtils,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.utils import (  # noqa: F401
    PayloadUtils,
    SwitchWaitUtils,
    mask_password,
    get_switch_field,
    determine_operation_type,
    group_switches_by_credentials,
    query_bootstrap_switches,
    build_bootstrap_index,
    build_poap_data_block,
)
