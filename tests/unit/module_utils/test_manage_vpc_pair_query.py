# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import query
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcActionEnum,
    VpcFieldNames,
)

SER_A = "SER-A"
SER_B = "SER-B"
SER_C = "SER-C"
SER_D = "SER-D"
SER_E = "SER-E"
SER_F = "SER-F"


def _present_pair(switch_id, peer_switch_id, use_vpl=False, details=None):
    """Build a pair dict shaped like a /vpcPairs list-query entry."""
    pair = {
        VpcFieldNames.SWITCH_ID: switch_id,
        VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
        VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
        VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
    }
    if details is not None:
        pair[VpcFieldNames.VPC_PAIR_DETAILS] = details
    return pair


def _config_item(switch_id, peer_switch_id):
    """Build a playbook-style (snake_case) requested delete config item."""
    return {"switch_id": switch_id, "peer_switch_id": peer_switch_id}


def _key(switch_id, peer_switch_id):
    return tuple(sorted([switch_id, peer_switch_id]))


def test_manage_vpc_pair_query_00010_build_delete_reconstructs_absent_pair_with_unrelated_present():
    """Staged delete: requested pair gone from /vpcPairs is reconstructed; unrelated pair excluded."""
    result = query._build_delete_existing_pairs([_present_pair(SER_C, SER_D)], [_config_item(SER_A, SER_B)])

    keys = {query._vpc_pair_identity_key(pair) for pair in result}
    assert keys == {_key(SER_A, SER_B)}
    assert result[0][VpcFieldNames.VPC_ACTION] == VpcActionEnum.PAIR.value


def test_manage_vpc_pair_query_00020_build_delete_keeps_present_requested_and_excludes_unrelated():
    """A requested pair still present is kept with real details; an unrelated pair is dropped."""
    present_ab = _present_pair(SER_A, SER_B, use_vpl=True)

    result = query._build_delete_existing_pairs([present_ab, _present_pair(SER_C, SER_D)], [_config_item(SER_A, SER_B)])

    assert result == [present_ab]


def test_manage_vpc_pair_query_00030_build_delete_empty_config_returns_all_pairs():
    """Empty config preserves prior behavior: all queried pairs are returned unchanged."""
    pairs = [_present_pair(SER_A, SER_B), _present_pair(SER_C, SER_D)]

    result = query._build_delete_existing_pairs(pairs, [])

    assert result == pairs


def test_manage_vpc_pair_query_00040_build_delete_mixes_present_and_reconstructed():
    """Present requested pair is retained; absent requested pair is reconstructed; unrelated excluded."""
    present_ab = _present_pair(SER_A, SER_B)

    result = query._build_delete_existing_pairs(
        [present_ab, _present_pair(SER_C, SER_D)],
        [_config_item(SER_A, SER_B), _config_item(SER_E, SER_F)],
    )

    keys = {query._vpc_pair_identity_key(pair) for pair in result}
    assert keys == {_key(SER_A, SER_B), _key(SER_E, SER_F)}
    assert present_ab in result
    reconstructed_ef = next(pair for pair in result if query._vpc_pair_identity_key(pair) == _key(SER_E, SER_F))
    assert reconstructed_ef[VpcFieldNames.VPC_ACTION] == VpcActionEnum.PAIR.value


def test_manage_vpc_pair_query_00050_reconstruct_skips_incomplete_and_carries_fields():
    """Reconstruction skips incomplete pairs and carries use_virtual_peer_link and pair details."""
    config = [
        {
            "switch_id": SER_A,
            "peer_switch_id": SER_B,
            "use_virtual_peer_link": True,
            VpcFieldNames.VPC_PAIR_DETAILS: {"detail": "value"},
        },
        {"switch_id": SER_C},
    ]

    result = query._reconstruct_requested_delete_pairs(config)

    assert len(result) == 1
    pair = result[0]
    assert pair[VpcFieldNames.SWITCH_ID] == SER_A
    assert pair[VpcFieldNames.PEER_SWITCH_ID] == SER_B
    assert pair[VpcFieldNames.USE_VIRTUAL_PEER_LINK] is True
    assert pair[VpcFieldNames.VPC_ACTION] == VpcActionEnum.PAIR.value
    assert pair[VpcFieldNames.VPC_PAIR_DETAILS] == {"detail": "value"}
