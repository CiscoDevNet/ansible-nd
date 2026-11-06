"""Pipeline profile selection and live-state planner contracts; no ND calls."""
import copy
import json
from pathlib import Path
import stat

import pytest
import yaml

import nd_prerequisite_orchestrator as orchestrator
from test_fabric_rounds import canonical_texts, load_validator
from test_nd_prerequisite_orchestrator import interface_state_for_profile
from validate_nd_prerequisites import load_registry, render_round_texts

ROOT = Path(__file__).resolve().parents[1]
SINGLE_TARGETS = ("loopback", "svi", "ethernet_access", "ethernet_trunk_host", "ethernet_routed",
                  "port_channel_access", "port_channel_trunk_host", "port_channel_routed",
                  "subinterface_managed", "subinterface_unmanaged")


@pytest.fixture(params=["ibgp", "ebgp"])
def contract(request, monkeypatch):
    texts = canonical_texts()
    if request.param == "ebgp":
        texts = render_round_texts(texts, "VXLAN_EVPN_Fabric_eBGP", "vxlanEbgp")
    validator = load_validator(texts["validate_nd_prerequisites.py"])
    monkeypatch.setattr(orchestrator, "validate_registry", validator.validate_registry)
    monkeypatch.setattr(orchestrator, "validate_selected_profiles", validator.validate_selected_profiles)
    return (yaml.safe_load(texts["nd_prerequisite_profiles.yaml"]),
            yaml.safe_load(texts["fixtures/nd_prerequisite/valid_state.yaml"]))


@pytest.mark.parametrize("target", SINGLE_TARGETS)
def test_defaults_preserve_every_profile_and_canonical_lab(contract, target):
    registry, _ = contract
    before = copy.deepcopy(registry)
    profile = "integration.nd_interface_" + target
    selected, variables = orchestrator.select_interface(registry, profile)
    assert selected == before == registry
    assert variables["nd_test_switch_ip"] == "192.0.2.195"
    assert variables["nd_interface_selection_changed"] is False
    assert "nd_prerequisite_repair_baseline" not in variables


@pytest.mark.parametrize("target", ["loopback", "svi"])
@pytest.mark.parametrize("address, switch_ref", [("192.0.2.196", "vxlan_leaf_2"),
                                               ("192.0.2.85", "vxlan_leaf_3")])
def test_switch_selection_changes_only_the_selected_profile(contract, target, address, switch_ref):
    registry, _ = contract
    before = copy.deepcopy(registry)
    profile_id = "integration.nd_interface_" + target
    selected, variables = orchestrator.select_interface(registry, profile_id, "  " + address + "  ")
    assert registry == before
    assert selected["lab"] == before["lab"]
    assert selected["runtime_defaults"] == before["runtime_defaults"]
    for key in before["profiles"]:
        if key != profile_id:
            assert selected["profiles"][key] == before["profiles"][key]
    profile = selected["profiles"][profile_id]
    assert profile["switches"]["members"][0]["ref"] == switch_ref
    assert {row["switch_ref"] for row in profile["resources"]} == {switch_ref}
    assert profile["runtime_vars"]["nd_test_switch_ip"] == address
    assert variables["nd_interface_selection_changed"] is True
    assert variables["nd_prerequisite_repair_baseline"] is False


@pytest.mark.parametrize("target", ["subinterface_managed", "subinterface_unmanaged"])
def test_custom_parent_keeps_logical_suffixes_and_port_channel_parent(contract, target):
    registry, _ = contract
    profile_id = "integration.nd_interface_" + target
    selected, variables = orchestrator.select_interface(registry, profile_id, ethernet_parent="Ethernet1/35")
    profile = selected["profiles"][profile_id]
    parent = next(row for row in profile["resources"] if row["kind"] == "ensure_routed_parent")
    namespace = next(row for row in profile["resources"] if row["kind"] == "verify_logical_interface_namespace")
    old_namespace = next(row for row in registry["profiles"][profile_id]["resources"]
                         if row["kind"] == "verify_logical_interface_namespace")
    assert parent["interface"] == "Ethernet1/35" and "existing_link" not in parent
    assert namespace["interfaces"] == [value.replace("Ethernet1/1.", "Ethernet1/35.", 1)
                                        for value in old_namespace["interfaces"]]
    assert variables["nd_test_ethernet_parent"] == "Ethernet1/35"
    assert variables["nd_test_port_channel_parent"] == "Port-channel10"
    assert variables["nd_prerequisite_repair_baseline"] is False
    assert registry["profiles"][profile_id]["runtime_vars"]["nd_test_ethernet_parent"] == "Ethernet1/1"


def test_explicit_existing_values_keep_the_known_link_contract(contract):
    registry, _ = contract
    selected, variables = orchestrator.select_interface(
        registry, "integration.nd_interface_subinterface_managed", "192.0.2.195", "Ethernet1/1")
    assert selected == registry
    assert not variables["nd_interface_selection_changed"]


@pytest.mark.parametrize("profile", ["integration.nd_interface_vpc_access", "integration.nd_interface_vpc_trunk_host",
                                      "integration.nd_manage_policy"])
def test_multi_switch_or_unrelated_profiles_cannot_be_retargeted(contract, profile):
    with pytest.raises(orchestrator.OrchestrationError, match="single-switch"):
        orchestrator.select_interface(contract[0], profile, "192.0.2.196")


@pytest.mark.parametrize("address", ["not-an-ip", "192.0.2.10", "192.0.2.89", "192.0.2.88", "192.0.2.194", None, 42])
def test_invalid_unknown_or_nonleaf_switches_are_rejected(contract, address):
    with pytest.raises(orchestrator.OrchestrationError):
        orchestrator.select_interface(contract[0], "integration.nd_interface_loopback", address)


@pytest.mark.parametrize("parent", ["Ethernet1/3", "Ethernet1/2", "Ethernet0/1", "Ethernet1/0",
                                     "Port-channel10", "Ethernet1/35; echo unsafe", "Ethernet1/35.2"])
def test_unsafe_or_nonphysical_parent_is_rejected_before_capture(contract, parent):
    with pytest.raises(orchestrator.OrchestrationError):
        orchestrator.select_interface(contract[0], "integration.nd_interface_subinterface_managed", ethernet_parent=parent)


@pytest.mark.parametrize("target", ["ethernet_access", "port_channel_access", "port_channel_routed"])
def test_switch_selection_does_not_expand_the_canonical_port_allowlist(contract, target):
    registry = contract[0]
    before = copy.deepcopy(registry)
    with pytest.raises(orchestrator.OrchestrationError, match="allowlist"):
        orchestrator.select_interface(registry, "integration.nd_interface_" + target, "192.0.2.196")
    assert registry == before


@pytest.mark.parametrize("problem", ["none", "missing", "port-channel-member", "fabric-link", "occupied-parent", "namespace"])
def test_custom_parent_still_passes_the_real_live_state_planner(contract, problem):
    registry, valid_state = contract
    profile_id = "integration.nd_interface_subinterface_managed"
    selected, variables = orchestrator.select_interface(registry, profile_id, ethernet_parent="Ethernet1/35")
    state = interface_state_for_profile(selected, valid_state, profile_id)
    parent = state["interfaces"]["vxlan_leaf_1"]["Ethernet1/35"]
    if problem == "missing":
        parent["exists"] = False
    elif problem == "port-channel-member":
        parent["port_channel_member"] = True
    elif problem == "fabric-link":
        state["physical_links"].append({"srcSwitchId": selected["lab"]["switches"]["vxlan_leaf_1"]["serial"],
                                        "srcInterfaceName": "Ethernet1/35", "dstSwitchId": "FOREIGN", "dstInterfaceName": "Ethernet1/9"})
    elif problem == "occupied-parent":
        parent.update(configured=True, policy="int_access_host", nv_pairs={"ACCESS_VLAN": "100"})
    elif problem == "namespace":
        state["logical_interfaces"]["vxlan_leaf_1"]["Ethernet1/35.2"]["exists"] = True
    resolved = orchestrator.resolve_execution(selected, profile_id, allow_auto_confirm=True)
    assert variables["nd_prerequisite_repair_baseline"] is False
    if problem == "none":
        operations = orchestrator.plan_topology_delta(selected, resolved, state)
        assert operations[0]["operation"] == "ensure_routed_parent"
        assert operations[0]["interface"] == "Ethernet1/35"
    else:
        with pytest.raises(orchestrator.OrchestrationError):
            orchestrator.plan_topology_delta(selected, resolved, state)


def test_cli_creates_restricted_selected_registry_and_ansible_vars(tmp_path, capsys):
    source = ROOT / "tests/nd_prerequisite_profiles.yaml"
    before = source.read_bytes()
    directory = tmp_path / ".nd-prerequisite-recovery" / "fixture"
    selected, variables = directory / "registry.json", directory / "vars.json"
    assert orchestrator.main(["select-interface", "--registry", str(source), "--execution-id",
                              "integration.nd_interface_subinterface_managed", "--ethernet-parent", "Ethernet1/35",
                              "--output", str(selected), "--vars-output", str(variables)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["changed"] is True
    payload = json.loads(variables.read_text())
    assert payload["nd_prerequisite_registry"] == str(selected)
    assert payload["nd_prerequisite_repair_baseline"] is False
    assert payload["nd_interface_selection_changed"] is True
    for path in (selected, variables):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert source.read_bytes() == before


@pytest.mark.parametrize("invalid", ["same-path", "existing", "outside", "symlink"])
def test_cli_refuses_unsafe_output_paths_without_overwriting(tmp_path, capsys, invalid):
    directory = tmp_path / ".nd-prerequisite-recovery"
    directory.mkdir()
    selected, variables = directory / "registry.json", directory / "vars.json"
    if invalid == "same-path":
        variables = selected
    elif invalid == "existing":
        variables.write_text("preserve me")
    elif invalid == "outside":
        variables = tmp_path / "outside.json"
    else:
        variables.symlink_to(tmp_path / "target")
    assert orchestrator.main(["select-interface", "--registry", str(ROOT / "tests/nd_prerequisite_profiles.yaml"),
                              "--execution-id", "integration.nd_interface_loopback", "--output", str(selected),
                              "--vars-output", str(variables)]) == 1
    assert "orchestration error" in capsys.readouterr().err
    assert not selected.exists()
    if invalid == "existing":
        assert variables.read_text() == "preserve me"
