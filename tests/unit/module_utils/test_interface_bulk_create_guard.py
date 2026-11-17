"""Canonical identity boundaries for ND 4.3.1 mixed-policy create."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.interface_bulk_create_guard import (
    bulk_create_identity_qualified,
)


def payload(name: str, interface_type: str, policy_type: str, **fields) -> dict:
    return {
        "interfaceName": name,
        "interfaceType": interface_type,
        "configData": {
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": policy_type, **fields},
            },
        },
    }


@pytest.mark.parametrize(
    "record",
    [
        payload("port-channel1", "portChannel", "accessPoHost", ports=[]),
        payload("port-channel4096", "portChannel", "l3Po", ports=[]),
        payload("port-channel20", "portChannel", "trunkPoHost", ports=[]),
        payload(
            "vpc100", "vpc", "accessVpcHost", peer1PortChannelId=100, peer2PortChannelId=100, peerSwitchId="PEER", peer1MemberPorts=[], peer2MemberPorts=[]
        ),
        payload(
            "vpc101", "vpc", "trunkVpcHost", peer1PortChannelId=101, peer2PortChannelId=101, peerSwitchId="PEER", peer1MemberPorts=[], peer2MemberPorts=[]
        ),
        payload("loopback0", "loopback", "loopback", ip="198.18.1.1"),
        payload("loopback1023", "loopback", "loopback", ip="198.18.1.2"),
        payload("vlan4094", "svi", "svi"),
        payload("Ethernet1/64.100", "subInterface", "subinterface", vlanId=100, ip="198.18.2.1", prefix=30),
        payload("port-channel10.200", "subInterface", "monitorSubinterface"),
    ],
)
def test_qualified_logical_identities(record: dict) -> None:
    assert bulk_create_identity_qualified(record)


@pytest.mark.parametrize(
    "record",
    [
        payload("Ethernet1/999", "ethernet", "accessHost"),
        payload("port-channel0", "portChannel", "accessPoHost", ports=[]),
        payload("port-channel4097", "portChannel", "l3Po", ports=[]),
        payload("port-channel10", "portChannel", "trunkPoHost", ports=["Ethernet1/1"]),
        payload("vpc0", "vpc", "accessVpcHost", peer1PortChannelId=0, peer2PortChannelId=0, peerSwitchId="PEER"),
        payload("vpc100", "vpc", "trunkVpcHost", peer1PortChannelId=101, peer2PortChannelId=100, peerSwitchId="PEER"),
        payload("vpc100", "vpc", "accessVpcHost", peer1PortChannelId=100, peer2PortChannelId=100, peerSwitchId="PEER", peer1MemberPorts=["Ethernet1/1"]),
        payload("loopback1024", "loopback", "loopback", ip="198.18.1.1"),
        payload("loopback10", "loopback", "loopback"),
        payload("vlan4095", "svi", "svi"),
        payload("Ethernet1/64.4095", "subInterface", "subinterface", vlanId=4095, ip="198.18.2.1", prefix=30),
        payload("Ethernet1/64.100", "subInterface", "subinterface", vlanId=101, ip="198.18.2.1", prefix=30),
        payload("EthernetX/999.10", "subInterface", "monitorSubinterface"),
        payload("Ethernet1/64.0", "subInterface", "monitorSubinterface"),
    ],
)
def test_unqualified_identities_use_established_create_path(record: dict) -> None:
    assert not bulk_create_identity_qualified(record)


def test_ios_xe_never_enters_nxos_create_fast_path() -> None:
    record = payload("loopback10", "loopback", "loopback", ip="198.18.1.1")
    xe = deepcopy(record)
    xe["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    assert not bulk_create_identity_qualified(xe)
