# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Any, Dict, Optional

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcActionEnum,
    VpcFieldNames,
)

"""
Payload helpers for vPC runtime operations.

Note:
- This file builds request/response payload structures only.
- Endpoint paths are resolved in `vpc_pair_runtime_endpoints.py`.
"""


def _get_template_config(vpc_pair_model) -> Optional[Dict[str, Any]]:
    """Extract template configuration from a vPC pair model if present."""
    if not hasattr(vpc_pair_model, "vpc_pair_details"):
        return None

    vpc_pair_details = vpc_pair_model.vpc_pair_details
    if not vpc_pair_details:
        return None

    return vpc_pair_details.model_dump(by_alias=True, exclude_none=True)


def _build_vpc_pair_payload(vpc_pair_model) -> Dict[str, Any]:
    """Build pair payload with vpcAction discriminator for ND 4.2 APIs."""
    if isinstance(vpc_pair_model, dict):
        switch_id = vpc_pair_model.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = vpc_pair_model.get(VpcFieldNames.PEER_SWITCH_ID)
        use_virtual_peer_link = vpc_pair_model.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, True)
    else:
        switch_id = vpc_pair_model.switch_id
        peer_switch_id = vpc_pair_model.peer_switch_id
        use_virtual_peer_link = vpc_pair_model.use_virtual_peer_link

    payload = {
        VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
        VpcFieldNames.SWITCH_ID: switch_id,
        VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
        VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_virtual_peer_link,
    }

    if not isinstance(vpc_pair_model, dict):
        template_config = _get_template_config(vpc_pair_model)
        if template_config:
            payload[VpcFieldNames.VPC_PAIR_DETAILS] = template_config

    return payload


# ND API versions use inconsistent field names. This mapping keeps one lookup API.
API_FIELD_ALIASES = {
    "useVirtualPeerLink": ["useVirtualPeerlink"],
    "serialNumber": ["serial_number", "serialNo"],
}


def _get_api_field_value(api_response: Dict[str, Any], field_name: str, default=None):
    """Get a field value across known ND API naming aliases."""
    if not isinstance(api_response, dict):
        return default

    if field_name in api_response:
        return api_response[field_name]

    aliases = API_FIELD_ALIASES.get(field_name, [])
    for alias in aliases:
        if alias in api_response:
            return api_response[alias]

    return default
