# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for plugins/module_utils/models/vpc/vpc_pair.py

Tests the VpcPairModel Pydantic model.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=too-many-lines
__metaclass__ = type
# pylint: enable=invalid-name

import copy
from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.models.vpc.vpc_pair import VpcPairModel
from pydantic import ValidationError  # pylint: disable=unused-import


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# Lab-captured PUT payload (minimal direct-peering pair) — see project_vpc_module_design.md
SAMPLE_ANSIBLE_CONFIG = {
    "fabric_name": "SITE1",
    "switch_ip": "192.168.12.151",
    "peer_switch_ip": "192.168.12.155",
    "domain_id": 1,
    "keep_alive_vrf": "management",
}

# Lab-captured GET response from /api/v1/manage/fabrics/SITE1/switches/9ASNKH8T9DJ/vpcPair
SAMPLE_API_RESPONSE = {
    "switchId": "9ASNKH8T9DJ",
    "peerSwitchId": "9SJKCSQND07",
    "useVirtualPeerLink": False,
    "vpcAction": "pair",
    "vpcPairDetails": {
        "domainId": 1,
        "keepAliveVrf": "management",
        "keepAliveHoldTimeout": 3,
        "enableMirrorConfig": False,
        "isVpcPlus": False,
        "isVteps": False,
        "nveInterface": 1,
        "poMode": "active",
        "adminState": True,
        "allowedVlans": "all",
        "fabricName": "SITE1",
    },
}


# =============================================================================
# Test 00000-00009: Instantiation defaults
# =============================================================================


def test_vpc_pair_00000():
    """
    # Summary

    Verify minimal instantiation with required fields succeeds and defaults are applied.

    ## Test

    - VpcPairModel can be created with required fields
    - use_virtual_peer_link defaults to False (v1 direct peering)
    - keep_alive_vrf defaults to "management"
    - vpc_action defaults to "pair"

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with does_not_raise():
        instance = VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.155",
            domain_id=1,
        )
    assert instance.fabric_name == "SITE1"
    assert instance.switch_ip == "192.168.12.151"
    assert instance.peer_switch_ip == "192.168.12.155"
    assert instance.domain_id == 1
    assert instance.use_virtual_peer_link is False
    assert instance.keep_alive_vrf == "management"
    assert instance.vpc_action == "pair"


def test_vpc_pair_00001():
    """
    # Summary

    Verify model has correct ClassVar configuration for composite identifier.

    ## Test

    - identifiers ClassVar is ["fabric_name", "switch_ip", "peer_switch_ip"]
    - identifier_strategy is "composite"

    ## Classes and Methods

    - VpcPairModel
    """
    assert VpcPairModel.identifiers == ["fabric_name", "switch_ip", "peer_switch_ip"]
    assert VpcPairModel.identifier_strategy == "composite"


# =============================================================================
# Test 00010-00099: Validation
# =============================================================================


def test_vpc_pair_00010():
    """
    # Summary

    Verify missing fabric_name raises ValidationError.

    ## Test

    - Missing fabric_name field raises ValidationError

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with pytest.raises(ValidationError):
        VpcPairModel(switch_ip="192.168.12.151", peer_switch_ip="192.168.12.155", domain_id=1)


def test_vpc_pair_00020():
    """
    # Summary

    Verify missing switch_ip raises ValidationError.

    ## Test

    - Missing switch_ip raises ValidationError

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with pytest.raises(ValidationError):
        VpcPairModel(fabric_name="SITE1", peer_switch_ip="192.168.12.155", domain_id=1)


def test_vpc_pair_00030():
    """
    # Summary

    Verify missing peer_switch_ip raises ValidationError.

    ## Test

    - Missing peer_switch_ip raises ValidationError

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with pytest.raises(ValidationError):
        VpcPairModel(fabric_name="SITE1", switch_ip="192.168.12.151", domain_id=1)


def test_vpc_pair_00040():
    """
    # Summary

    Verify missing domain_id raises ValidationError.

    ## Test

    - Missing domain_id raises ValidationError

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with pytest.raises(ValidationError):
        VpcPairModel(fabric_name="SITE1", switch_ip="192.168.12.151", peer_switch_ip="192.168.12.155")


@pytest.mark.parametrize(
    "domain_id",
    [0, -1, 1001, 9999],
    ids=["zero", "negative", "above_max", "well_above_max"],
)
def test_vpc_pair_00050(domain_id):
    """
    # Summary

    Verify domain_id outside 1-1000 raises ValidationError.

    ## Test

    - domain_id values outside [1, 1000] are rejected

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with pytest.raises(ValidationError):
        VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.155",
            domain_id=domain_id,
        )


@pytest.mark.parametrize("domain_id", [1, 100, 1000], ids=["min", "mid", "max"])
def test_vpc_pair_00060(domain_id):
    """
    # Summary

    Verify domain_id boundary values 1, 100, 1000 are accepted.

    ## Test

    - domain_id boundary values are accepted

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with does_not_raise():
        instance = VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.155",
            domain_id=domain_id,
        )
    assert instance.domain_id == domain_id


def test_vpc_pair_00070():
    """
    # Summary

    Verify switch_ip == peer_switch_ip raises a ValueError indicating peers must differ.

    ## Test

    - peer_switch_ip identical to switch_ip is rejected

    ## Classes and Methods

    - VpcPairModel.__init__() (model_validator)
    """
    with pytest.raises(ValidationError, match=r"switch_ip.*peer_switch_ip.*differ"):
        VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.151",
            domain_id=1,
        )


def test_vpc_pair_00080():
    """
    # Summary

    Verify use_virtual_peer_link is frozen (cannot mutate after construction).

    ## Test

    - Attempting to set use_virtual_peer_link to True raises ValidationError

    ## Classes and Methods

    - VpcPairModel.use_virtual_peer_link (frozen field)
    """
    instance = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.151",
        peer_switch_ip="192.168.12.155",
        domain_id=1,
    )
    with pytest.raises(ValidationError):
        instance.use_virtual_peer_link = True


def test_vpc_pair_00090():
    """
    # Summary

    Verify use_virtual_peer_link cannot be constructed with True (frozen + default).

    ## Test

    - Constructing with use_virtual_peer_link=True raises ValidationError because the field is frozen with default False

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with pytest.raises(ValidationError):
        VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.155",
            domain_id=1,
            use_virtual_peer_link=True,
        )


@pytest.mark.parametrize("vrf", ["default", "management"])
def test_vpc_pair_00100(vrf):
    """
    # Summary

    Verify keep_alive_vrf accepts the two enum values.

    ## Test

    - "default" and "management" are accepted

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with does_not_raise():
        instance = VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.155",
            domain_id=1,
            keep_alive_vrf=vrf,
        )
    assert instance.keep_alive_vrf == vrf


def test_vpc_pair_00110():
    """
    # Summary

    Verify keep_alive_vrf rejects unknown values.

    ## Test

    - keep_alive_vrf="bogus" raises ValidationError

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with pytest.raises(ValidationError):
        VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.155",
            domain_id=1,
            keep_alive_vrf="bogus",
        )


@pytest.mark.parametrize("action", ["pair", "unPair"])
def test_vpc_pair_00120(action):
    """
    # Summary

    Verify vpc_action accepts the two enum values.

    ## Test

    - "pair" and "unPair" are accepted

    ## Classes and Methods

    - VpcPairModel.__init__()
    """
    with does_not_raise():
        instance = VpcPairModel(
            fabric_name="SITE1",
            switch_ip="192.168.12.151",
            peer_switch_ip="192.168.12.155",
            domain_id=1,
            vpc_action=action,
        )
    assert instance.vpc_action == action


# =============================================================================
# Test 00200-00299: Composite identifier (canonical sort)
# =============================================================================


def test_vpc_pair_00200():
    """
    # Summary

    Verify get_identifier_value returns a 3-tuple with canonical-sorted peer IPs.

    ## Test

    - get_identifier_value() returns (fabric_name, sorted_low_ip, sorted_high_ip)

    ## Classes and Methods

    - VpcPairModel.get_identifier_value()
    """
    instance = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.155",
        peer_switch_ip="192.168.12.151",
        domain_id=1,
    )
    assert instance.get_identifier_value() == ("SITE1", "192.168.12.151", "192.168.12.155")


def test_vpc_pair_00210():
    """
    # Summary

    Verify (A, B) and (B, A) produce the same identifier (canonical sort collapses ordering).

    ## Test

    - Two instances with peer IPs swapped have identical get_identifier_value()

    ## Classes and Methods

    - VpcPairModel.get_identifier_value()
    """
    a = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.151",
        peer_switch_ip="192.168.12.155",
        domain_id=1,
    )
    b = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.155",
        peer_switch_ip="192.168.12.151",
        domain_id=1,
    )
    assert a.get_identifier_value() == b.get_identifier_value()


# =============================================================================
# Test 00300-00399: to_payload (alias + nesting)
# =============================================================================


def test_vpc_pair_00300():
    """
    # Summary

    Verify to_payload uses camelCase aliases at the top level.

    ## Test

    - to_payload returns switchId, peerSwitchId, useVirtualPeerLink, vpcAction at top level

    ## Classes and Methods

    - VpcPairModel.to_payload()
    """
    instance = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.151",
        peer_switch_ip="192.168.12.155",
        switch_id="9ASNKH8T9DJ",
        peer_switch_id="9SJKCSQND07",
        domain_id=1,
    )
    result = instance.to_payload()
    assert "switchId" in result
    assert "peerSwitchId" in result
    assert "useVirtualPeerLink" in result
    assert "vpcAction" in result
    assert result["switchId"] == "9ASNKH8T9DJ"
    assert result["peerSwitchId"] == "9SJKCSQND07"
    assert result["useVirtualPeerLink"] is False
    assert result["vpcAction"] == "pair"


def test_vpc_pair_00310():
    """
    # Summary

    Verify to_payload nests pair-detail fields under vpcPairDetails.

    ## Test

    - to_payload places domainId, keepAliveVrf under vpcPairDetails

    ## Classes and Methods

    - VpcPairModel.to_payload()
    """
    instance = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.151",
        peer_switch_ip="192.168.12.155",
        switch_id="9ASNKH8T9DJ",
        peer_switch_id="9SJKCSQND07",
        domain_id=1,
        keep_alive_vrf="management",
    )
    result = instance.to_payload()
    assert "vpcPairDetails" in result
    details = result["vpcPairDetails"]
    assert details["domainId"] == 1
    assert details["keepAliveVrf"] == "management"
    # Top-level keys must NOT also contain the nested fields
    assert "domainId" not in result
    assert "keepAliveVrf" not in result


def test_vpc_pair_00320():
    """
    # Summary

    Verify to_payload excludes ansible-only fields (fabric_name, switch_ip, peer_switch_ip) from the wire payload.

    ## Test

    - fabric_name, switch_ip, peer_switch_ip aliases NOT present in payload

    ## Classes and Methods

    - VpcPairModel.to_payload()
    """
    instance = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.151",
        peer_switch_ip="192.168.12.155",
        switch_id="9ASNKH8T9DJ",
        peer_switch_id="9SJKCSQND07",
        domain_id=1,
    )
    result = instance.to_payload()
    # These three are Ansible-facing identifiers, not wire fields
    assert "fabric_name" not in result
    assert "fabricName" not in result
    assert "switch_ip" not in result
    assert "switchIp" not in result
    assert "peer_switch_ip" not in result
    assert "peerSwitchIp" not in result


def test_vpc_pair_00330():
    """
    # Summary

    Verify to_payload(vpc_action="unPair") produces a minimal unPair body.

    ## Test

    - When vpc_action is "unPair", vpcAction key is present in payload

    ## Classes and Methods

    - VpcPairModel.to_payload()
    """
    instance = VpcPairModel(
        fabric_name="SITE1",
        switch_ip="192.168.12.151",
        peer_switch_ip="192.168.12.155",
        switch_id="9ASNKH8T9DJ",
        peer_switch_id="9SJKCSQND07",
        domain_id=1,
        vpc_action="unPair",
    )
    result = instance.to_payload()
    assert result["vpcAction"] == "unPair"


# =============================================================================
# Test 00400-00499: from_response (wire -> model)
# =============================================================================


def test_vpc_pair_00400():
    """
    # Summary

    Verify from_response parses a lab-captured GET shape into a populated model.

    ## Test

    - from_response constructs an instance from the SAMPLE_API_RESPONSE shape
    - Top-level wire fields are accessible via Python field names
    - Nested vpcPairDetails fields are accessible via Python field names

    ## Classes and Methods

    - VpcPairModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    # from_response needs the orchestrator to also inject ansible identifiers
    # The orchestrator does this; we mimic it here.
    response["fabric_name"] = "SITE1"
    response["switch_ip"] = "192.168.12.151"
    response["peer_switch_ip"] = "192.168.12.155"
    with does_not_raise():
        instance = VpcPairModel.from_response(response)
    assert instance.switch_id == "9ASNKH8T9DJ"
    assert instance.peer_switch_id == "9SJKCSQND07"
    assert instance.use_virtual_peer_link is False
    assert instance.vpc_action == "pair"
    assert instance.domain_id == 1
    assert instance.keep_alive_vrf == "management"
    assert instance.keep_alive_hold_timeout == 3


# =============================================================================
# Test 00500-00599: get_argument_spec
# =============================================================================


def test_vpc_pair_00500():
    """
    # Summary

    Verify get_argument_spec returns a dict with fabric_name + config + state keys.

    ## Test

    - argument_spec has fabric_name, config, state at top level
    - state choices include merged/replaced/overridden/deleted/query

    ## Classes and Methods

    - VpcPairModel.get_argument_spec()
    """
    spec = VpcPairModel.get_argument_spec()
    assert "fabric_name" in spec
    assert "config" in spec
    assert "state" in spec
    state_choices = spec["state"]["choices"]
    for required_state in ("merged", "replaced", "overridden", "deleted", "query"):
        assert required_state in state_choices


def test_vpc_pair_00510():
    """
    # Summary

    Verify get_argument_spec exposes pair fields under config.options but does NOT expose
    use_virtual_peer_link or vpc_action (those are internal/frozen).

    ## Test

    - config.options contains switch_ip, peer_switch_ip, domain_id, keep_alive_vrf
    - config.options does NOT contain use_virtual_peer_link or vpc_action

    ## Classes and Methods

    - VpcPairModel.get_argument_spec()
    """
    spec = VpcPairModel.get_argument_spec()
    options = spec["config"]["options"]
    for required_field in ("switch_ip", "peer_switch_ip", "domain_id", "keep_alive_vrf"):
        assert required_field in options, f"Expected {required_field} in config.options"
    assert "use_virtual_peer_link" not in options, "Frozen field should not be exposed in argspec"
    assert "vpc_action" not in options, "Internal action discriminator should not be exposed in argspec"
