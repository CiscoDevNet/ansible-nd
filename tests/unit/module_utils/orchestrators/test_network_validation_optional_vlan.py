# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Optional attachment VLANs remain absent until the controller allocates them."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_attachment_models import NetworkAttachmentModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy


class _Coordinator:
    module = SimpleNamespace(check_mode=False)

    def __init__(self):
        self.requests = []
        self.orchestrator = SimpleNamespace(_make_endpoint=self._endpoint, _request=self._request)

    @staticmethod
    def _endpoint(endpoint_type):
        return endpoint_type(fabric_name="fab1")

    def _request(self, **kwargs):
        self.requests.append(deepcopy(kwargs))
        return {"results": [{"status": "success"}]}

    def _new_network_orchestrator(self, _args, _strategy):
        return self.orchestrator, None

    @staticmethod
    def _finalize_api_trace(_results, deploy_targets):
        return {"changed": True, "failed": False, "deploy_targets": deploy_targets}


@pytest.mark.parametrize("vlan", ["omitted", None, 2, 198, 4094])
def test_actual_manager_validation_and_attach_serializers_preserve_optional_vlan(vlan):
    coordinator = _Coordinator()
    manager = NetworkAttachmentManager(coordinator)
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    payload = {
        "networkName": "BLUE_NET",
        "switchId": "SERIAL1",
        "interfaces": [{"mode": "trunk", "interfaceRange": "Ethernet1/46"}],
        "attach": True,
    }
    if vlan != "omitted":
        payload["vlanId"] = vlan
    before = deepcopy(payload)
    manager.post_network_attachments({}, strategy, [payload], {}, OperationType.CREATE)
    assert payload == before
    assert len(coordinator.requests) == 2
    validate, attach = coordinator.requests
    assert "/networkAttachments/validateInterfaces?" in validate["path"]
    assert validate["operation_type"] == OperationType.QUERY
    assert attach["path"] == "/api/v1/manage/fabrics/fab1/networkAttachments"
    for request in (validate, attach):
        row = request["data"]["attachments"][0]
        assert row["networkName"] == "BLUE_NET"
        assert row["switchId"] == "SERIAL1"
        assert row["attach"] is True
        assert row["interfaces"] == [{"mode": "trunk", "interfaceRange": "Ethernet1/46", "nativeVlan": False}]
        if vlan is None or vlan == "omitted":
            assert "vlanId" not in row
        else:
            assert row["vlanId"] == vlan
        # The official attachment schema makes VLAN optional, range 2..4094.
        # Use the existing write-strict model to check that emitted values fit
        # the same portable contract without depending on a local spec path.
        NetworkAttachmentModel.model_validate(row)
        assert "vlanId" not in row or type(row["vlanId"]) is int and 2 <= row["vlanId"] <= 4094
    assert all("deploy" not in request["path"] for request in coordinator.requests)


def test_helper_never_turns_an_explicit_invalid_value_into_an_allocation_guess():
    payload = {"networkName": "BLUE_NET", "switchId": "SERIAL1", "vlanId": -1, "attach": True}
    assert NetworkAttachmentManager._validation_payload(payload)["vlanId"] == -1
