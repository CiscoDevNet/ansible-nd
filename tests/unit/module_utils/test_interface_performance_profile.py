"""Regression tests for opt-in interface-workflow measurement."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.interface_performance_profile import InterfacePerformanceProfile


def test_profile_records_phase_and_request_without_retaining_payload() -> None:
    """Aggregate sizes/counts are returned but request and response content is not."""
    profile = InterfacePerformanceProfile()
    with profile.phase("planning"):
        profile.record_request(
            verb="GET",
            path="/api/v1/manage/fabrics/test/switches/S1/interfaces?max=500",
            payload={"secret": "do-not-return"},
            response={"interfaces": [{"interfaceName": "Ethernet1/1"}]},
            start_wall=0.0,
            start_cpu=0.0,
        )

    result = profile.to_dict()
    assert result["phases"]["planning"]["calls"] == 1
    assert result["requests"]["planning:interface_inventory:GET"]["count"] == 1
    assert result["requests"]["planning:interface_inventory:GET"]["request_json_bytes"] > 0
    assert "do-not-return" not in str(result)
    assert "Ethernet1/1" not in str(result)


def test_profile_distinguishes_safety_and_write_attempts() -> None:
    """A 207 write remains one request; phase and category are independent."""
    profile = InterfacePerformanceProfile()
    with profile.phase("planning"):
        profile.record_request(verb="GET", path="/interfacesSummary", payload=None, response={"interfaces": []}, start_wall=0.0, start_cpu=0.0)
    with profile.phase("execution"):
        profile.record_request(
            verb="POST", path="/interfaceActions/modify", payload={"interfaces": []}, response={"results": []}, start_wall=0.0, start_cpu=0.0
        )

    result = profile.to_dict()
    assert result["requests"]["planning:safety_summary:GET"]["count"] == 1
    assert result["requests"]["execution:write:POST"]["count"] == 1


def test_profile_distinguishes_exact_interface_read_from_inventory_page() -> None:
    profile = InterfacePerformanceProfile()
    with profile.phase("exact_interface_read"):
        profile.record_request(
            verb="GET",
            path="/fabrics/test/switches/S1/interfaces/Ethernet1%2F2",
            payload=None,
            response={"interfaceName": "Ethernet1/2"},
            start_wall=0.0,
            start_cpu=0.0,
        )

    assert profile.to_dict()["requests"]["exact_interface_read:exact_interface:GET"]["count"] == 1


def test_profile_counts_bulk_fallback_reasons_without_interface_details() -> None:
    profile = InterfacePerformanceProfile()
    profile.record_bulk_update_decision("eligible")
    profile.record_bulk_update_decision("eligible")
    profile.record_bulk_update_decision("other_semantic_change")

    assert profile.to_dict()["bulk_update_decisions"] == {"eligible": 2, "other_semantic_change": 1}
