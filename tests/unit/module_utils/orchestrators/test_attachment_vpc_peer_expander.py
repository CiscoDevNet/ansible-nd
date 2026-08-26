# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for shared attachment vPC peer expansion helpers."""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.attachment_vpc_peer_expander import (
    expand_desired_attachments_with_vpc_peers,
)


def test_expand_desired_attachments_with_vpc_peers_adds_missing_peer() -> None:
    desired = {
        ("BLUE", "SERIAL1"): {
            "vrfName": "BLUE",
            "switchId": "SERIAL1",
            "attach": True,
        }
    }
    attachment_details = [
        {
            "vrfName": "BLUE",
            "switchId": "SERIAL1",
            "peerSwitchId": "SERIAL2",
            "attach": False,
        }
    ]

    expanded = expand_desired_attachments_with_vpc_peers(desired, attachment_details, "vrfName")

    assert expanded == {
        ("BLUE", "SERIAL1"): {
            "vrfName": "BLUE",
            "switchId": "SERIAL1",
            "attach": True,
        },
        ("BLUE", "SERIAL2"): {
            "vrfName": "BLUE",
            "switchId": "SERIAL2",
            "attach": True,
        },
    }


def test_expand_desired_attachments_with_vpc_peers_applies_peer_payload_mutator() -> None:
    desired = {
        ("BLUE_NET", "SERIAL1"): {
            "networkName": "BLUE_NET",
            "switchId": "SERIAL1",
            "interfaces": [{"interfaceRange": "Ethernet1/1", "mode": "trunk"}],
            "attach": True,
        }
    }
    attachment_details = [
        {
            "networkName": "BLUE_NET",
            "switchId": "SERIAL1",
            "peerSwitchId": "SERIAL2",
            "attach": False,
        }
    ]

    def clear_interfaces(peer_payload: dict[str, Any]) -> None:
        peer_payload["interfaces"] = []

    expanded = expand_desired_attachments_with_vpc_peers(
        desired,
        attachment_details,
        "networkName",
        peer_payload_mutator=clear_interfaces,
    )

    assert expanded[("BLUE_NET", "SERIAL2")] == {
        "networkName": "BLUE_NET",
        "switchId": "SERIAL2",
        "interfaces": [],
        "attach": True,
    }


def test_expand_desired_attachments_with_vpc_peers_preserves_existing_peer_payload() -> None:
    desired = {
        ("BLUE", "SERIAL1"): {"vrfName": "BLUE", "switchId": "SERIAL1", "attach": True},
        ("BLUE", "SERIAL2"): {"vrfName": "BLUE", "switchId": "SERIAL2", "attach": True, "vlanId": 2001},
    }
    attachment_details = [{"vrfName": "BLUE", "switchId": "SERIAL1", "peerSwitchId": "SERIAL2"}]

    expanded = expand_desired_attachments_with_vpc_peers(desired, attachment_details, "vrfName")

    assert expanded == desired
