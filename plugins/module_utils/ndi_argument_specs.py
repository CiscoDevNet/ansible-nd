# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.constants import MATCH_TYPES, OPERATORS, TCP_FLAGS


def compliance_base_spec():
    return dict(
        insights_group=dict(type="str", required=True, aliases=["fab_name", "ig_name"]),
        name=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        enabled=dict(type="bool"),
        sites=dict(type="list", elements="str"),
        state=dict(type="str", default="query", choices=["query", "absent", "present"]),
    )


def compliance_match_criteria_spec():
    return dict(
        match_criteria_type=dict(type="str", required=True, choices=["include", "exclude"]),
        matches=dict(type="list", required=True, elements="dict", options=compliance_match_spec()),
    )


def compliance_match_spec():
    return dict(
        object_type=dict(type="str", required=True, choices=list(MATCH_TYPES)),
        object_attribute=dict(type="str", default="DN", choices=["DN"]),
        matches_pattern=dict(type="list", required=True, elements="dict", options=compliance_match_pattern_spec()),
    )


def compliance_match_pattern_spec():
    return dict(
        match_type=dict(type="str", required=True, choices=list(MATCH_TYPES)),
        pattern_type=dict(type="str", required=True, choices=OPERATORS),
        pattern=dict(type="str"),
    )


def compliance_tcp_spec():
    return dict(
        source=dict(type="str"),
        destination=dict(type="str"),
        check_tcp_flags=dict(type="bool"),
        flags_set=dict(type="list", elements="str", choices=list(TCP_FLAGS)),
        flags_not_set=dict(type="list", elements="str", choices=list(TCP_FLAGS)),
    )
