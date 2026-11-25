# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Public pair identity and nd-4.3.1-manage wire model contracts."""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_ha_pair.pairing import SmartSwitchHaPairModel, SmartSwitchHaRows

# Ansible pair identity and validation


def test_pair_identity_and_diff_are_order_independent_and_case_sensitive():
    configured = SmartSwitchHaPairModel.from_config({"switch_id": "B", "peer_switch_id": "A"})
    observed = SmartSwitchHaPairModel.from_response({"switch_id": "A", "peer_switch_id": "B"})
    assert configured.get_identifier_value() == observed.get_identifier_value() == ("A", "B")
    assert observed.to_gathered_config() == {"switch_id": "A", "peer_switch_id": "B"}
    assert observed.get_diff(configured) is True  # The shared comparator returns True for equivalent intent.
    different_case = SmartSwitchHaPairModel(switch_id="b", peer_switch_id="A")
    assert different_case.get_identifier_value() == ("A", "b")
    assert observed.get_diff(different_case) is False


@pytest.mark.parametrize("serial", ["", " ", "A B", "A\n", "a" * 33, None, 42])
def test_invalid_switch_serials(serial):
    with pytest.raises(ValidationError, match="switch_id"):
        SmartSwitchHaPairModel(switch_id=serial, peer_switch_id="PEER")


def test_pair_requires_distinct_switch_serials():
    with pytest.raises(ValidationError, match="requires two distinct switch IDs"):
        SmartSwitchHaPairModel(switch_id="PEER", peer_switch_id="PEER")


# Manage API row serialization


@pytest.mark.parametrize(
    "status, peer_id",
    [
        pytest.param("unpaired", None, id="unpaired"),
        pytest.param("paired", "FDO292005DD", id="paired"),
        pytest.param("pairPending", "FDO292005DD", id="pair-pending"),
        pytest.param("unpairPending", None, id="unpair-pending"),
    ],
)
def test_non_vpc_rows_preserve_request_fields_and_omit_preview_metadata(status, peer_id):
    request_switch_info = {
        "id": "FDO292005CC",
        "name": "leaf-5",
        "ip": "10.1.1.5",
        "operStatus": "connected",
        "peerId": peer_id,
        "peerIp": "10.1.1.6" if peer_id else None,
        "peerName": "leaf-6" if peer_id else None,
        "vpcRole": "notApplicable",
        "haPaired": status,
    }
    response = {
        "rows": [{"pairingType": "nonVpc", "switchInfo": {**request_switch_info, "configStatus": "outOfSync"}}],
        "configPreviewRows": [],
    }
    model = SmartSwitchHaRows.model_validate(response)
    assert model.rows[0].switch_info.ha_paired == status
    assert model.model_dump(by_alias=True, mode="json", exclude_unset=True) == {"rows": [{"pairingType": "nonVpc", "switchInfo": request_switch_info}]}


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"rows": []}, id="empty-recommendations"),
        pytest.param({"rows": [{"pairingType": "vpc", "switchInfo": {"id": "B", "name": "leaf-b"}}]}, id="sparse-recommendation"),
    ],
)
def test_recommendations_preserve_omitted_fields(response):
    assert SmartSwitchHaRows.model_validate(response).model_dump(by_alias=True, mode="json", exclude_unset=True) == response


# Manage API row validation


@pytest.mark.parametrize(
    "switch_info, invalid_field",
    [
        pytest.param({}, "id", id="missing-id"),
        pytest.param({"id": "A"}, "name", id="missing-name"),
        pytest.param({"id": "A", "name": "leaf", "haPaired": "waiting"}, "haPaired", id="unknown-ha-status"),
        pytest.param({"id": "A", "name": "leaf", "ip": "999.0.0.1"}, "ip", id="invalid-address"),
        pytest.param({"id": "A", "name": "leaf", "vpcDomain": 1001}, "vpcDomain", id="vpc-domain-out-of-range"),
        pytest.param({"id": "A", "name": "leaf", "operStatus": "error"}, "operStatus", id="unknown-oper-status"),
        pytest.param({"id": "A", "name": "leaf", "vpcRole": "leader"}, "vpcRole", id="unknown-vpc-role"),
    ],
)
def test_schema_rejects_malformed_switch_information(switch_info, invalid_field):
    with pytest.raises(ValidationError, match=rf"switchInfo\.{invalid_field}"):
        SmartSwitchHaRows.model_validate({"rows": [{"pairingType": "vpc", "switchInfo": switch_info}]})


@pytest.mark.parametrize("field", ["ip", "peerIp"])
def test_wire_model_rejects_numeric_ipv4_addresses(field):
    switch_info = {"id": "A", "name": "leaf", field: 42}
    with pytest.raises(ValidationError, match=field):
        SmartSwitchHaRows.model_validate({"rows": [{"pairingType": "nonVpc", "switchInfo": switch_info}]})


def test_rows_envelope_requires_an_array():
    with pytest.raises(ValidationError, match="rows"):
        SmartSwitchHaRows.model_validate({"rows": {"pairingType": "nonVpc", "switchInfo": {"id": "A", "name": "leaf-a"}}})
