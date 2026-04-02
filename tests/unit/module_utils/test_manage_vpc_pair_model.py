# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_vpc_pair model layer.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import VpcFieldNames

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_model import (
    VpcPairModel,
    VpcPairPlaybookConfigModel,
    VpcPairPlaybookItemModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_manage_vpc_pair_model_00010():
    """Verify VpcPairModel.from_config accepts snake_case keys."""
    with does_not_raise():
        model = VpcPairModel.from_config(
            {
                "switch_id": "SN01",
                "peer_switch_id": "SN02",
                "use_virtual_peer_link": True,
            }
        )
    assert model.switch_id == "SN01"
    assert model.peer_switch_id == "SN02"
    assert model.use_virtual_peer_link is True


def test_manage_vpc_pair_model_00020():
    """Verify VpcPairModel identifier is order-independent."""
    with does_not_raise():
        model = VpcPairModel.from_config(
            {
                "switch_id": "SN02",
                "peer_switch_id": "SN01",
            }
        )
    assert model.get_identifier_value() == ("SN01", "SN02")


def test_manage_vpc_pair_model_00030():
    """Verify merge handles reversed switch order without transient validation failure."""
    with does_not_raise():
        base = VpcPairModel.from_config(
            {
                "switch_id": "SN01",
                "peer_switch_id": "SN02",
                "use_virtual_peer_link": True,
            }
        )
        incoming = VpcPairModel.from_config(
            {
                "switch_id": "SN02",
                "peer_switch_id": "SN01",
                "use_virtual_peer_link": False,
            }
        )
        merged = base.merge(incoming)

    assert merged.switch_id == "SN02"
    assert merged.peer_switch_id == "SN01"
    assert merged.use_virtual_peer_link is False


def test_manage_vpc_pair_model_00040():
    """Verify playbook item normalization includes both snake_case and API keys."""
    with does_not_raise():
        item = VpcPairPlaybookItemModel(
            peer1_switch_id="SN01",
            peer2_switch_id="SN02",
            use_virtual_peer_link=False,
        )
        runtime = item.to_runtime_config()

    assert runtime["switch_id"] == "SN01"
    assert runtime["peer_switch_id"] == "SN02"
    assert runtime["use_virtual_peer_link"] is False
    assert runtime[VpcFieldNames.SWITCH_ID] == "SN01"
    assert runtime[VpcFieldNames.PEER_SWITCH_ID] == "SN02"
    assert runtime[VpcFieldNames.USE_VIRTUAL_PEER_LINK] is False


def test_manage_vpc_pair_model_00050():
    """Verify playbook item model rejects identical peer switch IDs."""
    with pytest.raises(ValidationError):
        VpcPairPlaybookItemModel(peer1_switch_id="SN01", peer2_switch_id="SN01")


def test_manage_vpc_pair_model_00060():
    """Verify argument_spec keeps vPC pair config aliases."""
    with does_not_raise():
        spec = VpcPairPlaybookConfigModel.get_argument_spec()

    config_options = spec["config"]["options"]
    assert config_options["peer1_switch_id"]["aliases"] == ["switch_id"]
    assert config_options["peer2_switch_id"]["aliases"] == ["peer_switch_id"]
