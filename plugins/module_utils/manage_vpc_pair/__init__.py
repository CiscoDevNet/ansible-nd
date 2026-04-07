# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    ComponentTypeSupportEnum,
    VpcActionEnum,
    VpcFieldNames,
)

# pylint: disable=undefined-all-variable
__all__ = [
    "ComponentTypeSupportEnum",
    "VpcActionEnum",
    "VpcFieldNames",
    "VpcPairEndpoints",
    "VpcPairResourceService",
    "VpcPairStateMachine",
    "_build_vpc_pair_payload",
    "_get_api_field_value",
]


def __getattr__(name):
    """
    Lazy-load heavy symbols to avoid import-time cycles.
    """
    if name in ("VpcPairResourceService", "VpcPairStateMachine"):
        from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.resources import (
            VpcPairResourceService,
            VpcPairStateMachine,
        )

        return {
            "VpcPairResourceService": VpcPairResourceService,
            "VpcPairStateMachine": VpcPairStateMachine,
        }[name]

    if name == "VpcPairEndpoints":
        from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runtime_endpoints import (
            VpcPairEndpoints,
        )

        return VpcPairEndpoints

    if name in ("_build_vpc_pair_payload", "_get_api_field_value"):
        from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runtime_payloads import (
            _build_vpc_pair_payload,
            _get_api_field_value,
        )

        return {
            "_build_vpc_pair_payload": _build_vpc_pair_payload,
            "_get_api_field_value": _get_api_field_value,
        }[name]

    raise AttributeError("module '{}' has no attribute '{}'".format(__name__, name))
