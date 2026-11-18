# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Explicit VRF text clears use omission only at the wire boundary."""

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import VrfDataModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator


@pytest.mark.parametrize("field", ["vrfVlanName", "vrfDescription", "vrfInterfaceDescription"])
def test_merged_clear_is_detected_sent_as_omission_and_idempotent(field):
    existing = VrfDataModel.from_response(
        {"fabricName": "FAB", "vrfName": "BLUE", "vrfType": "vxlanIbgp", "vrfId": 50001, "vlanId": 2001, "coreData": {field: "OLD", "mtu": 9000}}
    )
    proposed = VrfDataModel.from_config({"fabricName": "FAB", "vrfName": "BLUE", "vrfType": "vxlanIbgp", "coreData": {field: ""}})
    assert not existing.get_diff(proposed, exclude_unset=True)
    effective = existing.model_copy(deep=True).merge(proposed)
    assert effective.core_data[field] == ""
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", StandaloneVrfStrategy(fabric_name="FAB"))
    object.__setattr__(orchestrator, "rest_send", SimpleNamespace(controller_version="4.3.1.175"))
    payload = orchestrator._create_or_update_payload(effective, updating=True)
    assert field not in payload["coreData"]
    assert payload["coreData"]["mtu"] == 9000
    assert payload["vrfId"] == 50001 and payload["vlanId"] == 2001
    readback = VrfDataModel.from_response(payload)
    assert readback.get_diff(proposed, exclude_unset=True)
