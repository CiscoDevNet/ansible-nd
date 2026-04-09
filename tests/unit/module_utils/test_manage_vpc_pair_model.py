# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_vpc_pair model layer.
"""

from __future__ import annotations


import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import VpcFieldNames

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_model import (
    VpcPairModel,
    VpcPairPlaybookConfigModel,
    VpcPairPlaybookItemModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_manage_vpc_pair_model_00010() -> None:
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


def test_manage_vpc_pair_model_00020() -> None:
    """Verify VpcPairModel identifier is order-independent."""
    with does_not_raise():
        model = VpcPairModel.from_config(
            {
                "switch_id": "SN02",
                "peer_switch_id": "SN01",
            }
        )
    assert model.get_identifier_value() == ("SN01", "SN02")


def test_manage_vpc_pair_model_00030() -> None:
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


def test_manage_vpc_pair_model_00040() -> None:
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


def test_manage_vpc_pair_model_00045() -> None:
    """Verify omitted optional fields are not materialized in runtime config."""
    with does_not_raise():
        item = VpcPairPlaybookItemModel(
            peer1_switch_id="SN01",
            peer2_switch_id="SN02",
        )
        runtime = item.to_runtime_config()

    assert runtime["switch_id"] == "SN01"
    assert runtime["peer_switch_id"] == "SN02"
    assert "use_virtual_peer_link" not in runtime
    assert VpcFieldNames.USE_VIRTUAL_PEER_LINK not in runtime
    assert "vpc_pair_details" not in runtime
    assert VpcFieldNames.VPC_PAIR_DETAILS not in runtime


def test_manage_vpc_pair_model_00046() -> None:
    """Verify merged semantics keep existing value when optional field is omitted."""
    with does_not_raise():
        existing = VpcPairModel.from_config(
            {
                "switch_id": "SN01",
                "peer_switch_id": "SN02",
                "use_virtual_peer_link": True,
            }
        )
        incoming_item = VpcPairPlaybookItemModel(
            peer1_switch_id="SN01",
            peer2_switch_id="SN02",
        )
        incoming = VpcPairModel.from_config(incoming_item.to_runtime_config())
        merged = existing.merge(incoming)

    assert VpcFieldNames.USE_VIRTUAL_PEER_LINK not in incoming.to_diff_dict(exclude_unset=True)
    assert merged.use_virtual_peer_link is True


def test_manage_vpc_pair_model_00050() -> None:
    """Verify playbook item model rejects identical peer switch IDs."""
    with pytest.raises(ValidationError):
        VpcPairPlaybookItemModel(peer1_switch_id="SN01", peer2_switch_id="SN01")


def test_manage_vpc_pair_model_00060() -> None:
    """Verify argument_spec keeps vPC pair config aliases."""
    with does_not_raise():
        spec = VpcPairPlaybookConfigModel.get_argument_spec()

    config_options = spec["config"]["options"]
    assert config_options["peer1_switch_id"]["aliases"] == ["switch_id"]
    assert config_options["peer2_switch_id"]["aliases"] == ["peer_switch_id"]


def test_manage_vpc_pair_model_00070() -> None:
    """Verify verify/config_actions schema is accepted and normalized."""
    with does_not_raise():
        model = VpcPairPlaybookConfigModel.model_validate(
            {
                "state": "merged",
                "fabric_name": "fab1",
                "verify": {"enabled": True, "retries": 7, "timeout": 11},
                "config_actions": {"save": True, "deploy": False, "type": "global"},
            }
        )

    assert model.verify is not None
    assert model.verify.enabled is True
    assert model.verify.retries == 7
    assert model.verify.timeout == 11
    assert model.config_actions is not None
    assert model.config_actions.save is True
    assert model.config_actions.deploy is False
    assert model.config_actions.type == "global"


def test_manage_vpc_pair_model_00080() -> None:
    """Verify config_actions.deploy requires config_actions.save."""
    with pytest.raises(ValidationError):
        VpcPairPlaybookConfigModel.model_validate(
            {
                "state": "merged",
                "fabric_name": "fab1",
                "config_actions": {"save": False, "deploy": True, "type": "switch"},
            }
        )


def test_manage_vpc_pair_model_00090() -> None:
    """Verify empty verify dict normalizes to default values."""
    with does_not_raise():
        model = VpcPairPlaybookConfigModel.model_validate(
            {
                "state": "merged",
                "fabric_name": "fab1",
                "verify": {},
            }
        )

    assert model.verify is not None
    assert model.verify.enabled is True
    assert model.verify.retries == 5
    assert model.verify.timeout == 10
