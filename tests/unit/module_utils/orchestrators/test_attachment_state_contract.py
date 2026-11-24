# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Writable attachment state semantics from one existing inventory snapshot."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import NetworkAttachmentOptionsConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import VrfAttachmentOptionsConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_attachment_manager import VrfAttachmentManager


def attachment(kind):
    options = (
        {
            "loopbackId": 700,
            "loopbackIpv4Address": "198.18.1.1",
            "loopbackIpv6Address": "2001:db8::1",
            "routeTargetImport": ["65000:1"],
            "routeTargetExport": ["65000:2"],
            "evpnRouteTargetImport": ["65000:3"],
            "evpnRouteTargetExport": ["65000:4"],
        }
        if kind == "vrf"
        else {"sviEnabled": False, "switchRouteTargetImport": ["65000:1"], "switchRouteTargetExport": ["65000:2"]}
    )
    row = {
        kind + "Name": "BLUE",
        "switchId": "SW1",
        "vlanId": 2001,
        "attach": True,
        "instanceValues": options,
        "extraConfig": "! retained",
        "status": "inSync",
        "switchName": "leaf1",
    }
    if kind == "network":
        row["interfaces"] = [{"mode": "trunk", "interfaceRange": "Ethernet1/4"}]
    return row


def plan(kind, current, desired, state="merged"):
    if kind == "network":
        return NetworkAttachmentManager.planned_attach_payloads(current, desired, state=state)
    coordinator = SimpleNamespace(_attachment_matches=VrfAttachmentManager.attachment_matches)
    return VrfAttachmentManager(coordinator).planned_attach_payloads(current, desired, state=state)


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
def test_ip_only_attachment_obeys_state_and_preserves_identity_without_mutating_inputs(kind, state):
    saved = attachment(kind)
    desired = {kind + "Name": "BLUE", "switchId": "SW1", "attach": True}
    before = deepcopy((saved, desired))
    payloads = plan(kind, {("BLUE", "SW1"): saved}, {("BLUE", "SW1"): desired}, state)
    assert (saved, desired) == before
    if state == "merged":
        assert payloads == []
    else:
        payload = payloads[0]
        assert payload["vlanId"] == 2001
        assert payload["extraConfig"] == ""
        assert payload["instanceValues"] == {}
        if kind == "network":
            assert payload["interfaces"] == []
        assert "status" not in payload and "switchName" not in payload


@pytest.mark.parametrize("kind,key", [("vrf", "routeTargetImport"), ("network", "switchRouteTargetImport")])
@pytest.mark.parametrize("value", [["65000:9"], []])
def test_merged_changed_or_cleared_target_retains_every_omitted_sibling(kind, key, value):
    saved = attachment(kind)
    desired = {kind + "Name": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {key: value}}
    payload = plan(kind, {("BLUE", "SW1"): saved}, {("BLUE", "SW1"): desired})[0]
    assert payload["instanceValues"] == {**saved["instanceValues"], key: value}
    assert payload["extraConfig"] == saved["extraConfig"]
    if kind == "network":
        assert payload["interfaces"] == saved["interfaces"]
    readback = deepcopy(payload)
    if not value:
        readback["instanceValues"].pop(key)
    assert plan(kind, {("BLUE", "SW1"): readback}, {("BLUE", "SW1"): desired}) == []


@pytest.mark.parametrize("kind", ["vrf", "network"])
def test_freeform_only_preserves_omitted_options_in_merged(kind):
    saved = attachment(kind)
    desired = {kind + "Name": "BLUE", "switchId": "SW1", "attach": True, "extraConfig": "! new"}
    payload = plan(kind, {("BLUE", "SW1"): saved}, {("BLUE", "SW1"): desired})[0]
    assert payload["instanceValues"] == saved["instanceValues"]
    assert payload["extraConfig"] == "! new"


@pytest.mark.parametrize("options", [{"loopbackId": 0}, {"loopbackIpv4Address": "198.18.1.2"}, {"loopbackIpv6Address": "2001:db8::2"}])
def test_merged_loopback_updates_include_existing_dependent_tuple(options):
    saved = attachment("vrf")
    desired = {"vrfName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": options}
    payload = plan("vrf", {("BLUE", "SW1"): saved}, {("BLUE", "SW1"): desired})[0]
    assert payload["instanceValues"] == {**saved["instanceValues"], **options}


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("options", [{"loopbackId": 0}, {"loopbackIpv4Address": "198.18.1.2"}])
def test_incomplete_new_or_authoritative_loopback_is_rejected_before_request(state, options):
    desired = {"vrfName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": options}
    with pytest.raises(ValueError, match="requires loopback_id and at least one loopback address"):
        plan("vrf", {}, {("BLUE", "SW1"): desired}, state)


@pytest.mark.parametrize("state", ["replaced", "overridden", "staged"])
@pytest.mark.parametrize("options", [{"loopbackId": 0}, {"loopbackIpv4Address": "198.18.1.2"}])
def test_authoritative_loopback_does_not_inherit_an_omitted_companion(state, options):
    desired = {"vrfName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": options}
    with pytest.raises(ValueError, match="requires loopback_id and at least one loopback address"):
        plan("vrf", {("BLUE", "SW1"): attachment("vrf")}, {("BLUE", "SW1"): desired}, state)


def test_unchanged_svi_only_is_noop_and_false_is_not_treated_as_omitted():
    saved = attachment("network")
    desired = {"networkName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {"sviEnabled": False}}
    assert plan("network", {("BLUE", "SW1"): saved}, {("BLUE", "SW1"): desired}) == []
    desired["instanceValues"]["sviEnabled"] = True
    assert plan("network", {("BLUE", "SW1"): saved}, {("BLUE", "SW1"): desired})[0]["instanceValues"]["sviEnabled"] is True


@pytest.mark.parametrize("kind", ["vrf", "network"])
def test_explicit_empty_options_reset_managed_options_but_preserve_omitted_freeform(kind):
    saved = attachment(kind)
    desired = {kind + "Name": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {}}
    payload = plan(kind, {("BLUE", "SW1"): saved}, {("BLUE", "SW1"): desired})[0]
    assert payload["instanceValues"] == {}
    assert payload["extraConfig"] == saved["extraConfig"]
    assert plan(kind, {("BLUE", "SW1"): payload}, {("BLUE", "SW1"): desired}) == []


def test_authoritative_missing_ports_detach_only_the_explicitly_targeted_switch():
    saved = attachment("network")
    current = {("BLUE", "SW1"): saved, ("BLUE", "SW2"): {**saved, "switchId": "SW2"}}
    desired = {
        ("BLUE", "SW1"): {"networkName": "BLUE", "switchId": "SW1", "attach": True},
        ("BLUE", "SW2"): {"networkName": "BLUE", "switchId": "SW2", "attach": True, "interfaces": []},
    }
    payloads = NetworkAttachmentManager.planned_detach_payloads("replaced", [{"network_name": "BLUE"}], current, desired, {("BLUE", "SW1")})
    assert [payload["switchId"] for payload in payloads] == ["SW1"]


@pytest.mark.parametrize("kind", ["vrf", "network"])
def test_reset_scope_covers_every_public_attachment_option(kind):
    options = {"dpu_secure": True, "dpu_affinity": "dynamic"}
    if kind == "vrf":
        options.update(
            loopback_id=0,
            loopback_ipv4_address="198.18.1.1",
            loopback_ipv6_address="2001:db8::1",
            import_vpn_rt=["65000:1"],
            export_vpn_rt=["65000:2"],
            import_evpn_rt=["65000:3"],
            export_evpn_rt=["65000:4"],
        )
        manager = VrfAttachmentManager
        config_model = VrfAttachmentOptionsConfigModel
    else:
        options.update(svi_enabled=False, switch_route_target_import=["65000:1"], switch_route_target_export=["65000:2"], is_active=True)
        manager = NetworkAttachmentManager
        config_model = NetworkAttachmentOptionsConfigModel
    assert set(options) == set(config_model.model_fields)
    mapped = manager.attachment_instance_values({"attachment_options": options})
    assert set(mapped) == manager.managed_instance_fields


def test_passive_vpc_peer_retains_its_existing_ports_when_source_attachment_changes():
    saved = attachment("network")
    peer = {**saved, "switchId": "SW2", "interfaces": [{"mode": "trunk", "interfaceRange": "Ethernet1/9"}]}
    desired = {("BLUE", "SW1"): {"networkName": "BLUE", "switchId": "SW1", "attach": True, "interfaces": []}}
    expanded = NetworkAttachmentManager.expand_desired_attachments_with_vpc_peers(desired, [{**saved, "peerSwitchId": "SW2"}, peer])
    assert expanded[("BLUE", "SW2")]["interfaces"] == peer["interfaces"]
    assert peer["interfaces"] == [{"mode": "trunk", "interfaceRange": "Ethernet1/9"}]


@pytest.mark.parametrize("kind,key,default", [("network", "sviEnabled", True), ("network", "dpuSecure", False), ("vrf", "dpuSecure", False)])
def test_unreported_schema_default_does_not_create_a_false_attachment_change(kind, key, default):
    current = {kind + "Name": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {}}
    desired = {**current, "instanceValues": {key: default}}
    assert plan(kind, {("BLUE", "SW1"): current}, {("BLUE", "SW1"): desired}) == []
    desired["instanceValues"][key] = not default
    assert plan(kind, {("BLUE", "SW1"): current}, {("BLUE", "SW1"): desired})


def test_layer2_attachment_does_not_inject_an_inapplicable_svi_default():
    current = {"networkName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {}, "extraConfig": "! saved"}
    desired = {"networkName": "BLUE", "switchId": "SW1", "attach": True}
    payload = plan("network", {("BLUE", "SW1"): current}, {("BLUE", "SW1"): desired}, "replaced")[0]
    assert "instanceValues" not in payload
    assert payload["extraConfig"] == ""


def test_network_option_reset_rejects_unrecognized_saved_fields_before_writes():
    current = attachment("network")
    current["instanceValues"]["unsupportedOption"] = "preserve"
    desired = {"networkName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {"switchRouteTargetImport": []}}
    with pytest.raises(ValueError, match="unrecognized saved fields: unsupportedOption"):
        plan("network", {("BLUE", "SW1"): current}, {("BLUE", "SW1"): desired})


class _NetworkOptionMergeController:
    """Reproduce the observed nonempty-map merge and empty-map reset contract."""

    def __init__(self, saved, scope, check=False, failure=None, version="4.3.1.175"):
        self.saved = deepcopy(saved)
        self.calls = []
        self.failure = failure
        self.strategy = SimpleNamespace(is_parent=scope != "standalone", is_multicluster=scope == "mcfg")
        self.orchestrator = SimpleNamespace(
            _make_endpoint=lambda cls: cls(fabric_name="FAB"), _request=self.request, rest_send=SimpleNamespace(controller_version=version)
        )
        self.manager = NetworkAttachmentManager(
            SimpleNamespace(
                module=SimpleNamespace(check_mode=check),
                _new_network_orchestrator=lambda *_args: (self.orchestrator, None),
                _finalize_api_trace=lambda *_args: {"changed": True},
            )
        )

    def request(self, **request):
        self.calls.append(deepcopy(request))
        rows = request["data"]["attachments"]
        reset = all(row.get("instanceValues") == {} for row in rows)
        if self.failure == ("reset" if reset else "restore"):
            return {"results": [{"status": "failed", "message": "controller rejection"}]}
        for row in rows:
            current = self.saved[(row["networkName"], row["switchId"])]
            values = row.get("instanceValues")
            if values == {}:
                current["instanceValues"] = {}
            elif values is not None:
                current.setdefault("instanceValues", {}).update({key: value for key, value in values.items() if value not in (None, "", [], {})})
            current.update({key: value for key, value in row.items() if key != "instanceValues"})
        return {"results": [{"status": "success"} for row in rows]}

    def readback(self):
        observed = deepcopy(self.saved)
        for row in observed.values():
            if row.get("instanceValues", {}).get("sviEnabled") is True:
                row["instanceValues"].pop("sviEnabled")
        return observed


@pytest.mark.parametrize("scope", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("version", ["4.2.1.10", "4.3.1.175"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("count", [1, 2000])
def test_network_option_removals_restore_only_nondefaults_and_converge(scope, version, state, count):
    from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType

    current, desired = {}, {}
    for index in range(count):
        name = "BLUE" + str(index)
        key = (name, "SW1")
        current[key] = {**attachment("network"), "networkName": name, "vlanId": 2001 + index, "interfaces": []}
        desired[key] = {"networkName": name, "switchId": "SW1", "attach": True, "instanceValues": {"switchRouteTargetImport": []}}
    controller = _NetworkOptionMergeController(current, scope, version=version)
    before = deepcopy(desired)
    payloads = plan("network", current, desired, state)
    controller.manager.post_network_attachments({}, controller.strategy, payloads, {}, OperationType.CREATE)
    assert desired == before
    assert len(controller.calls) == (2 if state == "merged" else 1)
    assert len(controller.calls[0]["data"]["attachments"]) == count
    assert len(controller.calls[-1]["data"]["attachments"]) == count
    for row in controller.calls[0]["data"]["attachments"]:
        assert row["instanceValues"] == {}
        assert row["attach"] is True
        assert row["interfaces"] == []
    for row in controller.calls[-1]["data"]["attachments"]:
        assert NetworkAttachmentManager.reset_instance_values_intent_key not in row
    observed = controller.readback()
    for row in observed.values():
        assert row["instanceValues"].get("switchRouteTargetImport", []) == []
        assert row["instanceValues"].get("switchRouteTargetExport", []) == (["65000:2"] if state == "merged" else [])
        assert row["extraConfig"] == ("! retained" if state == "merged" else "")
    assert plan("network", observed, desired, state) == []


@pytest.mark.parametrize("scope", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("version", ["4.2.1.10", "4.3.1.175"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("options", [{}, {"switchRouteTargetImport": []}, {"switchRouteTargetImport": [], "sviEnabled": True, "dpuSecure": False}])
@pytest.mark.parametrize("count", [1, 2000])
def test_completely_empty_network_options_clear_in_one_batch_without_a_restore(scope, version, state, options, count):
    from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType

    current, desired = {}, {}
    for index in range(count):
        name = "BLUE" + str(index)
        key = (name, "SW1")
        current[key] = {**attachment("network"), "networkName": name, "interfaces": [], "instanceValues": {"switchRouteTargetImport": ["65000:1"]}}
        desired[key] = {"networkName": name, "switchId": "SW1", "attach": True, "instanceValues": deepcopy(options)}
    controller = _NetworkOptionMergeController(current, scope, version=version)
    payloads = plan("network", current, desired, state)
    controller.manager.post_network_attachments({}, controller.strategy, payloads, {}, OperationType.CREATE)
    assert len(controller.calls) == 1
    assert len(controller.calls[0]["data"]["attachments"]) == count
    assert all(row["instanceValues"] == {} for row in controller.calls[0]["data"]["attachments"])
    assert plan("network", controller.readback(), desired, state) == []


@pytest.mark.parametrize("failure,calls", [("reset", 1), ("restore", 2)])
def test_network_option_reset_or_restore_failure_stops_the_operation(failure, calls):
    from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType

    current = attachment("network")
    current["interfaces"] = []
    desired = {"networkName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {"switchRouteTargetImport": []}}
    payloads = plan("network", {("BLUE", "SW1"): current}, {("BLUE", "SW1"): desired})
    controller = _NetworkOptionMergeController({("BLUE", "SW1"): current}, "standalone", failure=failure)
    with pytest.raises(Exception, match="Network attachment .*failed"):
        controller.manager.post_network_attachments({}, controller.strategy, payloads, {}, OperationType.CREATE)
    assert len(controller.calls) == calls


def test_network_option_reset_check_mode_previews_both_steps_without_requests():
    from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType

    current = attachment("network")
    desired = {"networkName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {"switchRouteTargetImport": []}}
    controller = _NetworkOptionMergeController({("BLUE", "SW1"): current}, "standalone", check=True)
    payloads = plan("network", {("BLUE", "SW1"): current}, {("BLUE", "SW1"): desired})
    trace = controller.manager.post_network_attachments({}, controller.strategy, payloads, {}, OperationType.CREATE)
    assert controller.calls == []
    assert trace["check_mode_instance_value_reset_payloads"][0]["instanceValues"] == {}
    assert trace["check_mode_attachment_payloads"][0]["instanceValues"]["switchRouteTargetExport"] == ["65000:2"]
    assert trace["check_mode_attachment_payloads"][0]["interfaces"] == current["interfaces"]


def test_network_reset_preview_survives_workflow_result_aggregation():
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator

    coordinator = NetworkWorkflowCoordinator.__new__(NetworkWorkflowCoordinator)
    coordinator.module = SimpleNamespace(params={}, _verbosity=0)
    reset = {"networkName": "BLUE", "switchId": "SW1", "attach": True, "instanceValues": {}}
    result = {}
    coordinator._merge_api_trace(result, {"changed": True, "check_mode_instance_value_reset_payloads": [reset]})
    assert result["changed"] is True
    assert result["check_mode_instance_value_reset_payloads"] == [reset]
