# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Contract tests for bounded vPC final-state readback."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators import manage_vpc_pair
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vpc_pair import VpcPairOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import FinalizationContext
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.retry_policy import RestRetryPolicy


def _orchestrator(monkeypatch, responses):
    request_paths: list[str] = []
    policies: list[RestRetryPolicy | None] = []
    request_responses = iter(responses)

    class FakeNDModule:
        def __init__(self, module) -> None:
            self.module = module
            self._rest_send = RestSend({"check_mode": False})

        def get_rest_send(self):
            return self._rest_send

        def request(self, path, verb):
            del verb
            request_paths.append(path)
            policies.append(self._rest_send.retry_policy)
            return next(request_responses)

    monkeypatch.setattr(manage_vpc_pair, "NDModuleV2", FakeNDModule)
    module = SimpleNamespace(params={"fabric_name": "fab1"}, check_mode=False)
    orchestrator = VpcPairOrchestrator(rest_send=RestSend({"check_mode": False}))
    orchestrator.state_machine = SimpleNamespace(module=module)
    return orchestrator, request_paths, policies


def test_vpc_final_state_uses_paginated_intended_list_and_direct_details(monkeypatch) -> None:
    responses = [
        {
            "meta": {"counts": {"remaining": 1, "total": 2}},
            "vpcPairs": [{"switchId": "A01", "peerSwitchId": "B01", "type": "intendedPairs"}],
        },
        {
            "meta": {"counts": {"remaining": 0, "total": 2}},
            "vpcPairs": [{"switchId": "C01", "peerSwitchId": "D01", "type": "intendedPairs"}],
        },
        {"switchId": "A01", "peerSwitchId": "B01", "useVirtualPeerLink": True},
        {"switchId": "C01", "peerSwitchId": "D01", "useVirtualPeerLink": False},
    ]
    orchestrator, paths, policies = _orchestrator(monkeypatch, responses)
    policy = RestRetryPolicy(attempts=3, interval=0, retry_transport_errors=True)

    result = orchestrator.query_final_state(FinalizationContext(state="merged"), policy)

    assert result == responses[2:]
    assert "view=intendedPairs" in paths[0]
    assert "offset=0" in paths[0]
    assert "offset=1" in paths[1]
    assert paths[2].endswith("/fabrics/fab1/switches/A01/vpcPair")
    assert paths[3].endswith("/fabrics/fab1/switches/C01/vpcPair")
    assert policies == [policy, policy, policy, policy]


def test_vpc_final_state_deduplicates_reversed_pairs(monkeypatch) -> None:
    responses = [
        {
            "meta": {"counts": {"remaining": 0, "total": 2}},
            "vpcPairs": [
                {"switchId": "A01", "peerSwitchId": "B01"},
                {"switchId": "B01", "peerSwitchId": "A01"},
            ],
        },
        {"switchId": "A01", "peerSwitchId": "B01", "useVirtualPeerLink": True},
    ]
    orchestrator, paths, policies = _orchestrator(monkeypatch, responses)
    policy = RestRetryPolicy(attempts=1, interval=0)

    result = orchestrator.query_final_state(FinalizationContext(state="merged"), policy)

    assert result == [responses[1]]
    assert len(paths) == 2
    assert policies == [policy, policy]


def test_vpc_final_state_rejects_list_detail_disagreement(monkeypatch) -> None:
    responses = [
        {
            "meta": {"counts": {"remaining": 0, "total": 1}},
            "vpcPairs": [{"switchId": "A01", "peerSwitchId": "B01"}],
        },
        {"switchId": "A01", "peerSwitchId": "C01", "useVirtualPeerLink": True},
    ]
    orchestrator, paths, policies = _orchestrator(monkeypatch, responses)
    policy = RestRetryPolicy(attempts=1, interval=0)

    with pytest.raises(ValueError, match="disagree"):
        orchestrator.query_final_state(FinalizationContext(state="merged"), policy)

    assert len(paths) == 2
    assert policies == [policy, policy]
