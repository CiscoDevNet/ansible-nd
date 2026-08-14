# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `FabricGroupMemberModel`.

Tests the Pydantic model for a fabric group member: alias mapping (name/type),
payload/config round-tripping, the read-only fabric_type field, identifier
configuration, and the argument spec.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_fabric_group_member_from_response() -> None:
    """from_response maps API aliases (name/type) onto the model fields."""
    with does_not_raise():
        model = FabricGroupMemberModel.from_response({"name": "member-1", "type": "vxlanIbgp"})
    assert model.member_name == "member-1"
    assert model.fabric_type == "vxlanIbgp"


def test_fabric_group_member_to_payload_excludes_fabric_type() -> None:
    """to_payload emits only {'name': ...}; fabric_type is read-only and excluded."""
    model = FabricGroupMemberModel.from_response({"name": "member-1", "type": "vxlanIbgp"})
    assert model.to_payload() == {"name": "member-1"}


def test_fabric_group_member_to_config_round_trip() -> None:
    """to_config exposes the member using the model (snake_case) field names."""
    model = FabricGroupMemberModel.from_response({"name": "member-1", "type": "vxlanIbgp"})
    config = model.to_config()
    assert config["member_name"] == "member-1"
    assert config["fabric_type"] == "vxlanIbgp"


def test_fabric_group_member_identifier() -> None:
    """The member is identified by its name (single identifier)."""
    model = FabricGroupMemberModel(member_name="member-1")
    assert FabricGroupMemberModel.identifiers == ["member_name"]
    assert FabricGroupMemberModel.identifier_strategy == "single"
    assert model.get_identifier_value() == "member-1"


def test_fabric_group_member_identifier_multicluster() -> None:
    """A multi-cluster member is identified by the (cluster_name, member_name) pair."""
    model = FabricGroupMemberModel.from_response(
        {"clusterName": "cluster-a", "name": "member-1", "type": "vxlanIbgp"}
    )
    assert model.cluster_name == "cluster-a"
    assert model.get_identifier_value() == ("cluster-a", "member-1")


def test_fabric_group_member_to_payload_includes_cluster_name() -> None:
    """to_payload includes clusterName when set (multi-cluster fabric group member)."""
    model = FabricGroupMemberModel(member_name="member-1", cluster_name="cluster-a")
    assert model.to_payload() == {"name": "member-1", "clusterName": "cluster-a"}


def test_fabric_group_member_fabric_type_excluded_from_diff() -> None:
    """fabric_type is excluded from the diff so present members are not seen as changed."""
    assert "fabric_type" in FabricGroupMemberModel.exclude_from_diff
    assert "fabric_type" in FabricGroupMemberModel.payload_exclude_fields


def test_fabric_group_member_argument_spec() -> None:
    """get_argument_spec contributes fabric_name, config(member_name), and state."""
    spec = FabricGroupMemberModel.get_argument_spec()
    assert spec["fabric_name"]["required"] is True
    assert spec["config"]["options"]["member_name"]["required"] is True
    assert spec["config"]["options"]["cluster_name"]["required"] is False
    assert spec["state"]["choices"] == ["merged", "deleted", "gathered"]
    assert spec["config_actions"]["options"]["save"]["type"] == "bool"
    assert spec["config_actions"]["options"]["deploy"]["type"] == "bool"
    assert spec["config_actions"]["options"]["type"]["choices"] == ["switch", "global"]
