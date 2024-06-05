# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.constants import MATCH_TYPES, OPERATORS, TCP_FLAGS


def compliance_base_spec():
    return dict(
        insights_group=dict(type="str", default="default", aliases=["fab_name", "ig_name"]),
        name=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        enabled=dict(type="bool"),
        sites=dict(type="list", elements="str"),
        state=dict(type="str", default="query", choices=["query", "absent", "present"]),
    )


def object_selector_spec(choices):
    return dict(
        type=dict(type="str", required=True, choices=choices),
        includes=dict(type="list", required=True, elements="dict", options=compliance_match_spec()),
        excludes=dict(type="list", elements="dict", options=compliance_match_spec()),
    )


def compliance_match_spec():
    return dict(
        type=dict(type="str", required=True, choices=list(MATCH_TYPES)),
        attribute=dict(type="str", default="DN", choices=["DN"]),
        patterns=dict(type="list", required=True, elements="dict", options=compliance_match_pattern_spec()),
    )


def compliance_match_pattern_spec():
    return dict(
        type=dict(type="str", required=True, choices=list(MATCH_TYPES)),
        operator=dict(type="str", required=True, choices=OPERATORS),
        value=dict(type="str"),
    )


def compliance_tcp_spec():
    return dict(
        source=dict(type="str"),
        destination=dict(type="str"),
        tcp_flags=dict(type="list", elements="str", choices=list(TCP_FLAGS), aliases=["tcp_flags_set"]),
        tcp_flags_not_set=dict(type="list", elements="str", choices=list(TCP_FLAGS)),
    )
