# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Validate runnable VRF/Network fixtures against Ansible and the public models."""

from copy import deepcopy
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import yaml
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.block import Block
from ansible.playbook.conditional import Conditional
from ansible.template import Templar
from ansible.vars.manager import VariableManager
from ansible_collections.cisco.nd.plugins.action.nd4x_module_test import ActionModule
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import RESOURCE_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import NetworkConfigModel, NetworkParentConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import VrfConfigModel, VrfParentConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import network_module_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import vrf_parent_argument_spec, vrf_standalone_argument_spec
from jinja2 import Environment, FileSystemLoader
from jsonpath_ng.ext import parse
from ansible.plugins.filter.core import to_nice_yaml

TARGETS = Path(__file__).resolve().parents[2] / "integration/targets"
RESOURCES = ("network", "vrf")
TOPOLOGIES = ("standalone", "msd", "mcfg")
RELEASES = ("4.2.1", "4.3.1")


def fixture_context(resource, topology, release):
    """Use target defaults and vars rather than a second copy of the fixtures."""
    target = TARGETS / ("nd_manage_networks" if resource == "network" else "nd_manage_vrfs")
    variables = yaml.safe_load((target / "defaults/main.yaml").read_text())
    variables.update(yaml.safe_load((target / "vars/main.yaml").read_text()))
    variables.update(
        {
            "ansible_it_fabric": "UNIT_FABRIC",
            "ansible_msd_parent_fabric": "UNIT_PARENT",
            "ansible_msd_child_fabric": "UNIT_CHILD",
            "ansible_mcfg_parent_fabric": "UNIT_MCFG",
            "ansible_mcfg_child_fabric": "UNIT_CHILD",
            "ansible_switch1": "192.0.2.10",
            "nd_network_harness_vlan_monitor": "UNIT_L2_MONITOR",
            "nd_network_harness_interface_monitor": "UNIT_L3_MONITOR",
            "nd_vrf_harness_monitor": "UNIT_MONITOR",
            f"nd_{resource}_test_topology": topology,
            f"nd4x_{resource}_run_id": "unit1234",
            f"nd4x_{resource}_version": {"current": {"platformVersion": release}},
        }
    )
    templar = Templar(loader=DataLoader(), variables=variables)
    return target, variables, templar


def validate_actions(config, actions, state="merged"):
    """Use the real shared parser, including explicit false override tracking."""
    raw_args = {"config_actions": deepcopy(actions), "config": deepcopy(config)}
    result = ArgumentSpecValidator(config_actions_spec(RESOURCE_CONFIG_ACTIONS)).validate({"config_actions": actions})
    assert not result.error_messages, result.error_messages
    return parse_config_actions(params={**result.validated_parameters, "config": config}, raw_args=raw_args, policy=RESOURCE_CONFIG_ACTIONS, state=state)


def validate_config(resource, topology, config, state="merged", defer_dependencies=False):
    """Run real argument conversion before the public input-model validators."""
    assert "deploy_type" not in config
    validate_actions([config], {"type": "resource", "deploy": False}, state)
    if resource == "network":
        spec = network_module_argument_spec()
        model = NetworkConfigModel if topology == "standalone" else NetworkParentConfigModel
    else:
        spec = vrf_standalone_argument_spec() if topology == "standalone" else vrf_parent_argument_spec()
        model = VrfConfigModel if topology == "standalone" else VrfParentConfigModel
    result = ArgumentSpecValidator(spec).validate(deepcopy(config))
    assert not result.error_messages, result.error_messages
    return model.from_config(
        result.validated_parameters,
        context={"state": state, "defer_omitted_layer": True, "defer_dependencies": defer_dependencies},
    )


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("topology", TOPOLOGIES)
@pytest.mark.parametrize("release", RELEASES)
def test_harness_seed_fixtures_match_module_contract(resource, topology, release):
    target, variables, templar = fixture_context(resource, topology, release)
    fixture_names = ["seed", "extra"] + (["l3", "pvlan_primary"] if resource == "network" else [])
    if resource == "network" and topology != "mcfg":
        fixture_names.append("pvlan_secondaries")
    template_name = "nd_network_conf.j2" if resource == "network" else "nd_vrf_conf.j2"
    environment = Environment(loader=FileSystemLoader(target / "templates"))
    environment.filters["to_nice_yaml"] = to_nice_yaml
    for name in fixture_names:
        if topology == "mcfg" and name.startswith("pvlan"):
            continue
        rendered = templar.template(variables[f"nd4x_{resource}_{name}"])
        configs = rendered if isinstance(rendered, list) else [rendered]
        forwarded = yaml.safe_load(environment.get_template(template_name).render(**{f"{resource}_conf": configs}))
        assert forwarded == configs
        for config in forwarded:
            validate_config(resource, topology, config)


@pytest.mark.parametrize("topology", TOPOLOGIES)
@pytest.mark.parametrize("release", RELEASES)
@pytest.mark.parametrize("state", ("replaced", "overridden", "staged"))
def test_authoritative_network_fixtures_exercise_omitted_layer_with_native_readback(topology, release, state):
    target, variables, templar = fixture_context("network", topology, release)
    variables["ansible_search_path"] = [str(target)]
    templar = Templar(loader=DataLoader(), variables=variables)
    tasks = yaml.safe_load((target / f"tasks/nd4x_{state}.yaml").read_text())
    task = next(task for task in tasks if task.get("name", "").startswith(state.upper() + ":"))
    harness = task["cisco.nd.nd4x_module_test"]
    config = templar.template(harness["config"])
    assert len(config) == 1
    assert "layer" not in config[0]
    assert "vrf_name" not in config[0]
    assert config[0]["vlan_name"]
    validate_config("network", topology, config[0], state)
    assert templar.template(harness["expected"])["idempotency"] == {"changed": False, "failed": False}
    expectations = [expectation for query in harness["nd_queries"] for expectation in query.get("expect", [])]
    assert {"jsonpath": "$.current.networkMode", "equals": "layer2"} in expectations
    assert {"jsonpath": "$.current.vrfName", "equals": "NA"} in expectations
    assert "check_mode_queries" in harness


@pytest.mark.parametrize("topology", TOPOLOGIES)
@pytest.mark.parametrize("release", RELEASES)
@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_l3_network_reset_fixture_omits_layer_and_required_vrf_association(topology, release, state):
    target, variables, templar = fixture_context("network", topology, release)
    variables.update(ansible_search_path=[str(target)], nd4x_definition_state=state)
    templar = Templar(loader=DataLoader(), variables=variables)
    tasks = yaml.safe_load((target / "tasks/nd4x_definition_state.yaml").read_text())
    task = next(task for task in tasks if "L3: Retain omitted layer" in task.get("name", ""))
    harness = task["cisco.nd.nd4x_module_test"]
    config = templar.template(harness["config"])
    assert len(config) == 1
    assert "layer" not in config[0]
    assert "vrf_name" not in config[0]
    assert config[0]["routing_tag"] == 12345
    assert "mtu" not in config[0]
    validate_config("network", topology, config[0], state)
    assert {"jsonpath": "$.current.networkMode", "equals": "layer3"} in harness["nd_queries"][0]["expect"]
    assert {"jsonpath": "$.current.vrfName", "equals": "{{ nd4x_network_vrf_name }}"} in harness["nd_queries"][0]["expect"]
    assert templar.template(harness["expected"])["idempotency"] == {"changed": False, "failed": False}


@pytest.mark.parametrize("topology", ("standalone", "msd"))
@pytest.mark.parametrize("release", RELEASES)
def test_primary_pvlan_layer_regression_stays_in_opt_in_suite(topology, release):
    target, variables, templar = fixture_context("network", topology, release)
    tasks = yaml.safe_load((target / "tasks/nd4x_pvlan.yaml").read_text())
    task = next(task for task in tasks if "omitted layer preserves the primary PVLAN" in task.get("name", ""))
    assert task["loop"] == ["merged", "replaced", "staged"]
    assert any("privateVlan" in str(prerequisite.get("ansible.builtin.assert", {})) for prerequisite in tasks)
    for state in task["loop"]:
        variables["item"] = state
        templar = Templar(loader=DataLoader(), variables=variables)
        harness = task["cisco.nd.nd4x_module_test"]
        config = templar.template(harness["config"])
        assert "layer" not in config[0]
        assert "vlan_network_type" not in config[0]
        assert "vrf_name" not in config[0]
        validate_config("network", topology, config[0], state)
        assert {"jsonpath": "$.current.networkMode", "equals": "layer3"} in harness["nd_queries"][0]["expect"]
        assert {"jsonpath": "$.current.vlanNetworkType", "equals": "privatePrimary"} in harness["nd_queries"][0]["expect"]
        assert templar.template(harness["expected"])["idempotency"] == {"changed": False, "failed": False}


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("topology", TOPOLOGIES)
@pytest.mark.parametrize("release", RELEASES)
def test_harness_property_fixtures_respect_ownership_and_dependencies(resource, topology, release):
    target, variables, templar = fixture_context(resource, topology, release)
    del target
    for case in templar.template(variables[f"nd4x_{resource}_property_cases"]):
        if case.get("minimum_version", "4.2.1") > release:
            continue
        config = {f"{resource}_name": "UNIT_RESOURCE", "deploy": False}
        if topology != "standalone" and case["scope"] == "fabric":
            config["child_fabric_config"] = [{"fabric_name": "UNIT_CHILD", **case["settings"]}]
        else:
            config.update(case["settings"])
        validate_config(resource, topology, config)
        if "followup_settings" in case:
            followup = {f"{resource}_name": "UNIT_RESOURCE", "deploy": False}
            if topology != "standalone" and case["scope"] == "fabric":
                followup["child_fabric_config"] = [{"fabric_name": "UNIT_CHILD", **case["followup_settings"]}]
            else:
                followup.update(case["followup_settings"])
            validate_config(resource, topology, followup, defer_dependencies=resource == "vrf" and topology == "standalone")
            effective = deepcopy(config)
            if "child_fabric_config" in followup:
                effective["child_fabric_config"][0].update(case["followup_settings"])
            else:
                effective.update(case["followup_settings"])
            validate_config(resource, topology, effective)


@pytest.mark.parametrize("resource", RESOURCES)
def test_configuration_template_preserves_explicit_false_zero_empty_and_nested_intent(resource):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del variables, templar
    config = (
        {
            "network_name": "N",
            "deploy": False,
            "secondary_gateway_ipv4_collection": [],
            "attach": [{"ip_address": "192.0.2.10", "attachment_options": {"svi_enabled": False}}],
        }
        if resource == "network"
        else {
            "vrf_name": "V",
            "deploy": False,
            "route_distinguisher_id": 0,
            "enable_vrf_vpn_route_leaking": False,
            "import_vpn_rt": [],
            "child_fabric_config": [{"fabric_name": "CHILD", "v6_rp_external": False}],
            "attach": [{"ip_address": "192.0.2.10", "attachment_options": {"loopback_id": 0}}],
        }
    )
    environment = Environment(loader=FileSystemLoader(target / "templates"))
    environment.filters["to_nice_yaml"] = to_nice_yaml
    template_name = "nd_network_conf.j2" if resource == "network" else "nd_vrf_conf.j2"
    assert yaml.safe_load(environment.get_template(template_name).render(**{f"{resource}_conf": [config]})) == [config]


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("topology", TOPOLOGIES)
def test_negative_fixtures_fail_for_the_documented_reason(resource, topology):
    target, variables, templar = fixture_context(resource, topology, "4.3.1")
    del target
    for case in templar.template(variables[f"nd4x_{resource}_negative_cases"]):
        if case.get("standalone_only") and topology != "standalone" or case.get("parent_only") and topology == "standalone":
            continue
        with pytest.raises((ValueError, AssertionError)) as error:
            if "module_args" in case:
                validate_actions([case["config"]], case["module_args"]["config_actions"], case.get("state", "merged"))
            else:
                validate_config(resource, topology, case["config"])
        assert case["message"] in str(error.value)


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("topology", TOPOLOGIES)
def test_common_args_explicitly_disable_resource_deployment(resource, topology):
    target, variables, templar = fixture_context(resource, topology, "4.3.1")
    del target
    common = templar.template(variables[f"nd4x_{resource}_common_args"])
    assert common["config_actions"] == {"type": "resource", "deploy": False}
    actions = validate_actions([{f"{resource}_name": "UNIT"}], common["config_actions"])
    assert actions.type == "resource"
    assert actions.deploy is False
    assert actions.resource_deploy_overrides == (None,)


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden", "staged", "deleted", "gathered"))
def test_resource_override_and_inheritance_contract(resource, state):
    config = [{f"{resource}_name": "UNIT"}]
    actions = validate_actions(config, {"type": "resource", "deploy": state != "gathered"}, state)
    assert actions.resource_deploy_overrides == (None,)
    assert actions.resource_deploy_enabled(0) is (state != "gathered")
    if state != "gathered":
        config[0]["deploy"] = False
        actions = validate_actions(config, {"type": "resource", "deploy": True}, state)
        assert actions.resource_deploy_enabled(0) is False
        config[0]["deploy"] = True
        actions = validate_actions(config, {"type": "resource", "deploy": False}, state)
        assert actions.resource_deploy_enabled(0) is True


@pytest.mark.parametrize("resource", RESOURCES)
def test_gathered_template_strips_deployment_and_definition_intent(resource):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del variables, templar
    configs = [{f"{resource}_name": "A", "deploy": False}, {f"{resource}_name": "B", "deploy": True, "attach": []}]
    environment = Environment(loader=FileSystemLoader(target / "templates"))
    environment.filters["to_nice_yaml"] = to_nice_yaml
    template_name = "nd_network_conf.j2" if resource == "network" else "nd_vrf_conf.j2"
    selectors = yaml.safe_load(environment.get_template(template_name).render(**{f"{resource}_conf": configs, "name_only": True}))
    assert selectors == [{f"{resource}_name": "A"}, {f"{resource}_name": "B"}]
    validate_actions(selectors, {"type": "resource", "deploy": False}, "gathered")


def native_resource_calls(node, seen=None):
    """Traverse parsed tasks and aliased mappings without counting aliases twice."""
    if seen is None:
        seen = set()
    if id(node) in seen:
        return
    seen.add(id(node))
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("cisco.nd.nd_manage_networks", "cisco.nd.nd_manage_vrfs"):
                yield value
            else:
                yield from native_resource_calls(value, seen)
    elif isinstance(node, list):
        for value in node:
            yield from native_resource_calls(value, seen)


@pytest.mark.parametrize("resource", RESOURCES)
def test_native_setup_and_legacy_calls_use_explicit_resource_actions(resource):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del variables, templar
    count = 0
    for path in target.rglob("*.yaml"):
        for args in native_resource_calls(yaml.safe_load(path.read_text())):
            count += 1
            assert args["config_actions"] == {"type": "resource", "deploy": False}, path
            validate_actions([], args["config_actions"], args.get("state", "merged"))
    assert count > 0


@pytest.mark.parametrize("resource", RESOURCES)
def test_all_target_yaml_and_static_harness_contracts_parse(resource):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del variables, templar
    plugin = ActionModule.__new__(ActionModule)
    for path in sorted((target / "tasks").glob("nd4x_*.yaml")):
        tasks = yaml.safe_load(path.read_text())
        assert isinstance(tasks, list), path
        for task in tasks:
            if "cisco.nd.nd4x_module_test" in task:
                args = deepcopy(task["cisco.nd.nd4x_module_test"])
                args["common_args"] = {"fabric_name": "UNIT_FABRIC"}
                args["config"] = [{"network_name" if resource == "network" else "vrf_name": "UNIT_RESOURCE"}]
                args["check_mode_queries"] = []
                if isinstance(args.get("module_args"), str):
                    args["module_args"] = {}
                if isinstance(args.get("expected"), str):
                    args["expected"] = {"check_mode": {"changed": True}, "apply": {"changed": True}}
                args.pop("nd_queries", None)
                plugin._validate_arguments(args)


def walk_tasks(block):
    """Walk Ansible's inherited blocks, not just YAML tag strings."""
    for section in (block.block, block.rescue, block.always):
        for item in section:
            if isinstance(item, Block):
                yield from walk_tasks(item)
            else:
                yield item


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("selected", ("merged", "replaced", "gathered", "deleted", "staged", "overridden", "negative", "properties", "attachments"))
def test_tag_selection_keeps_state_includes_isolated_and_cleanup_selected(resource, selected):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del variables, templar
    tasks = yaml.safe_load((target / "tasks/main.yaml").read_text())
    loader = DataLoader()
    block = Block.load(data={"block": tasks}, loader=loader, variable_manager=VariableManager(loader=loader))
    selected_tasks = [task for task in walk_tasks(block) if task.evaluate_tags([f"nd4x_{selected}"], [], {})]
    includes = [task.args for task in selected_tasks if task.action == "ansible.builtin.include_tasks"]
    filenames = [args.get("file", args.get("_raw_params")) for args in includes]
    assert "nd4x_preflight.yaml" in filenames
    assert f"nd4x_{selected}.yaml" in filenames
    assert "nd4x_cleanup.yaml" in filenames
    state_includes = [name for name in filenames if name and name.startswith("nd4x_") and name not in ("nd4x_preflight.yaml", "nd4x_cleanup.yaml")]
    assert state_includes == [f"nd4x_{selected}.yaml"]
    cleanup = next(args for args in includes if args.get("file", args.get("_raw_params")) == "nd4x_cleanup.yaml")
    assert cleanup["apply"]["tags"] == ["always"]


def assert_conditions(conditions, variables):
    """Evaluate the target's real safety expressions with Ansible's evaluator."""
    loader = DataLoader()
    conditional = Conditional(loader=loader)
    conditional.when = conditions
    templar = Templar(loader=loader, variables=variables)
    return conditional.evaluate_conditional(templar, variables)


@pytest.mark.parametrize("resource", RESOURCES)
def test_destructive_scope_guard_rejects_unowned_members(resource):
    target, variables, templar = fixture_context(resource, "msd", "4.3.1")
    del templar
    tasks = yaml.safe_load((target / "tasks/nd4x_scope_preflight.yaml").read_text())
    guard = next(task["ansible.builtin.assert"]["that"] for task in tasks if "ansible.builtin.assert" in task)
    name_key = "networkName" if resource == "network" else "vrfName"
    variables.update(
        {
            f"nd4x_{resource}_destructive_enabled": True,
            f"nd4x_{resource}_names": ["OWNED"],
            f"nd4x_{resource}_inventory_by_scope": {"parent": [{name_key: "OWNED"}], "member": []},
        }
    )
    assert assert_conditions(guard, variables)
    variables[f"nd4x_{resource}_inventory_by_scope"]["member"] = [{name_key: "SOMEONE_ELSE"}]
    assert not assert_conditions(guard, variables)
    variables[f"nd4x_{resource}_inventory_by_scope"]["member"] = []
    variables[f"nd4x_{resource}_destructive_enabled"] = False
    assert not assert_conditions(guard, variables)


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("fault", (None, "scope", "switches", "resources", "different_apply_targets", "switch_endpoint"))
def test_deploy_assertions_enforce_scope_and_identical_predictive_targets(resource, fault):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del templar
    tasks = yaml.safe_load((target / "tasks/nd4x_attachments.yaml").read_text())
    guard = next(
        task["ansible.builtin.assert"]["that"] for task in tasks if task.get("name") == "Require resource-scoped predictive and applied deployment targets"
    )
    index = 1 if resource == "network" else 0
    names = ["L2", "L3"] if resource == "network" else ["VRF"]
    targets = {"resources": [names[index]], "switches": ["SWITCH1"]}
    planned = {"status": "planned", "effective": {"type": "resource"}, "targets": targets}
    applied = {**deepcopy(planned), "status": "completed"}
    check_result = {"config_actions": [planned]}
    apply_result = {"config_actions": [applied], "api_paths": [f"/api/v1/manage/fabrics/FAB/{resource}Actions/deploy"]}
    if fault == "scope":
        planned["effective"]["type"] = "switch"
    elif fault in ("switches", "resources"):
        planned["targets"][fault] = ["UNREQUESTED"]
    elif fault == "different_apply_targets":
        applied["targets"]["switches"] = ["OTHER_SWITCH"]
    elif fault == "switch_endpoint":
        apply_result["api_paths"] = ["/api/v1/manage/fabrics/FAB/switchActions/deploy"]
    variables.update(
        {
            f"nd4x_{resource}_names": names,
            f"nd_{resource}_harness_switch_id": "SWITCH1",
            f"nd4x_{resource}_deploy_check": check_result,
            f"nd4x_{resource}_deploy_apply": apply_result,
        }
    )
    assert assert_conditions(guard, variables) is (fault is None)


@pytest.mark.parametrize("resource", RESOURCES)
def test_preflight_only_selection_does_not_enter_mutation_or_cleanup_block(resource):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del templar
    tasks = yaml.safe_load((target / "tasks/main.yaml").read_text())
    variables.update({"ansible_run_tags": ["nd4x_preflight"]})
    facts = tasks[0]["ansible.builtin.set_fact"]
    variables.update(Templar(loader=DataLoader(), variables=variables).template(facts))
    variables[f"nd4x_{resource}_supported"] = True
    outer = next(task for task in tasks if "always" in task)
    assert not assert_conditions(outer["when"], variables)


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("wrapped", (False, True))
def test_gathered_assertions_select_owned_resource_among_unrelated_definitions(resource, wrapped):
    target, variables, templar = fixture_context(resource, "msd", "4.3.1")
    name_key = resource + "_name"
    owned_name = templar.template(variables[f"nd4x_{resource}_names"])[0]
    gathered = {"gathered": [{name_key: "UNRELATED", "netflow_enable": True}, {name_key: owned_name}]}
    result = {"parent_fabric": gathered} if wrapped else gathered
    variables[f"nd4x_{resource}_gathered"] = {"first_run_result": result}
    tasks = yaml.safe_load((target / "tasks/nd4x_gathered.yaml").read_text())
    select = next(task for task in tasks if task.get("name") == "Select the owned fixture from the gathered inventory")
    variables.update(Templar(loader=DataLoader(), variables=variables).template(select["ansible.builtin.set_fact"]))
    guards = [task["ansible.builtin.assert"]["that"] for task in tasks if "ansible.builtin.assert" in task]
    assert all(assert_conditions(guard, variables) for guard in guards)
    variables[f"nd4x_{resource}_gathered_requested"][0]["netflow_enable"] = True
    assert not assert_conditions(guards[-1], variables)


@pytest.mark.parametrize("topology", TOPOLOGIES)
@pytest.mark.parametrize("pvlan_enabled", (False, True))
def test_secondary_cleanup_requires_supported_pvlan_opt_in(topology, pvlan_enabled):
    target, variables, templar = fixture_context("network", topology, "4.3.1")
    del templar
    variables["nd4x_network_pvlan_enabled"] = pvlan_enabled
    tasks = yaml.safe_load((target / "tasks/nd4x_reset.yaml").read_text())
    assert assert_conditions(tasks[0]["when"], variables) is (pvlan_enabled and topology != "mcfg")
    assert "when" not in tasks[1]


@pytest.mark.parametrize("topology", TOPOLOGIES)
def test_attachment_deployment_does_not_require_arp_suppression_tcam(topology):
    target, variables, templar = fixture_context("network", topology, "4.3.1")
    del variables
    tasks = yaml.safe_load((target / "tasks/nd4x_attachments.yaml").read_text())
    create = next(task for task in tasks if task.get("name") == "Create and attach a fresh resource in one module call")
    config = templar.template(create["cisco.nd.nd4x_module_test"]["config"])
    assert config[0]["arp_suppression"] is False
    assert templar.template("{{ nd4x_network_l3 }}")["arp_suppression"] is True


@pytest.mark.parametrize("release", RELEASES)
@pytest.mark.parametrize("wire_key,wire_integer", (("3des", 3), ("type6", 6), ("type7", 7)))
@pytest.mark.parametrize("correct_type", (False, True))
def test_bgp_wire_guard_uses_actual_ansible_conditions_without_coercion(release, wire_key, wire_integer, correct_type):
    target, variables, templar = fixture_context("vrf", "standalone", release)
    del templar
    named_release = release == "4.3.1"
    observed = wire_key if named_release == correct_type else wire_integer
    variables.update(
        {
            "nd4x_vrf_property_case": {"wire_key": wire_key, "wire_integer": wire_integer},
            "nd4x_vrf_property_result": {"nd_query_results": [{"result": {"current": {"fabricData": {"bgpPasswordKeyType": observed}}}}]},
        }
    )
    tasks = yaml.safe_load((target / "tasks/nd4x_property.yaml").read_text())
    guard = next(task for task in tasks if task.get("name") == "Verify release-specific BGP key readback without coercing its type")
    assert assert_conditions(guard["ansible.builtin.assert"]["that"], variables) is correct_type


def inventory_replay(resource, pages, page_size=1000):
    """Render the actual recursive inventory tasks using read-only page fixtures."""
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del templar
    prefix = f"nd4x_{resource}"
    variables.update(
        {
            f"nd_{resource}_harness_page_size": page_size,
            f"{prefix}_scope": {"api": "/api/v1/manage/fabrics/UNIT", "suffix": ""},
            f"{prefix}_offset": 0,
            f"{prefix}_page_count": 0,
            f"{prefix}_rows": [],
        }
    )
    tasks = yaml.safe_load((target / "tasks/nd4x_inventory_page.yaml").read_text())
    read_paths = []
    for current in pages:
        for task in tasks:
            templar = Templar(loader=DataLoader(), variables=variables)
            if "when" in task and not assert_conditions([task["when"]], variables):
                continue
            if "cisco.nd.nd_rest" in task:
                request = templar.template(task["cisco.nd.nd_rest"])
                read_paths.append(request["path"])
                variables[f"{prefix}_page"] = {"status": 200, "current": current}
            elif "ansible.builtin.set_fact" in task:
                variables.update(templar.template(task["ansible.builtin.set_fact"]))
            elif "ansible.builtin.assert" in task:
                assert assert_conditions(task["ansible.builtin.assert"]["that"], variables), task["name"]
        if not variables[f"{prefix}_more"]:
            return variables[f"{prefix}_rows"], read_paths
    raise AssertionError("Inventory was truncated before the next advertised page")


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("page_size", (1, 100, 1000))
def test_inventory_without_counts_uses_the_configured_page_size(resource, page_size):
    collection = "networks" if resource == "network" else "vrfs"
    name_key = "networkName" if resource == "network" else "vrfName"
    rows = [{name_key: f"RESOURCE_{number:04d}"} for number in range(page_size + 1)]
    pages = [{collection: rows[:page_size]}, {collection: rows[page_size:]}]
    if len(pages[-1][collection]) == page_size:
        pages.append({collection: []})
    actual, paths = inventory_replay(resource, pages, page_size)
    assert actual == rows
    assert [parse_qs(urlparse(path).query)["max"] for path in paths] == [[str(page_size)]] * len(pages)
    assert [parse_qs(urlparse(path).query)["offset"] for path in paths] == [[str(index * page_size)] for index in range(len(pages))]


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("page_size,valid", ((0, False), (-1, False), (10001, False), ("invalid", False), (1, True), (10000, True)))
def test_inventory_page_size_is_bounded_before_controller_access(resource, page_size, valid):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del templar
    tasks = yaml.safe_load((target / "tasks/nd4x_preflight.yaml").read_text())
    guards = [condition for condition in tasks[0]["ansible.builtin.assert"]["that"] if "harness_page_size" in condition]
    assert len(guards) == 2
    variables[f"nd_{resource}_harness_page_size"] = page_size
    assert assert_conditions(guards, variables) is valid


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("metadata_key", ("meta", "metadata"))
def test_complete_inventory_pagination_handles_both_metadata_contracts(resource, metadata_key):
    collection = "networks" if resource == "network" else "vrfs"
    name_key = "networkName" if resource == "network" else "vrfName"
    rows = [{name_key: f"RESOURCE_{number:03d}"} for number in range(205)]
    pages = [
        {collection: rows[:100], metadata_key: {"counts": {"total": 205, "remaining": 105}}},
        {collection: rows[100:200], metadata_key: {"counts": {"total": 205, "remaining": 5}}},
        {collection: rows[200:], metadata_key: {"counts": {"total": 205, "remaining": 0}}},
    ]
    actual, paths = inventory_replay(resource, pages)
    assert actual == rows
    assert [parse_qs(urlparse(path).query)["offset"] for path in paths] == [["0"], ["100"], ["200"]]


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("fault", ("repeated", "duplicate", "empty", "truncated", "contradictory"))
def test_inventory_safety_fails_closed_on_invalid_or_incomplete_pages(resource, fault):
    collection = "networks" if resource == "network" else "vrfs"
    name_key = "networkName" if resource == "network" else "vrfName"
    rows = [{name_key: "ONE"}]
    page = {collection: rows, "meta": {"counts": {"total": 2, "remaining": 1}}}
    if fault == "repeated":
        pages = [page, {collection: rows, "meta": {"counts": {"total": 2, "remaining": 0}}}]
    elif fault == "duplicate":
        pages = [{collection: rows * 2}]
    elif fault == "empty":
        pages = [{collection: [], "meta": {"counts": {"total": 1, "remaining": 1}}}]
    elif fault == "contradictory":
        pages = [{collection: rows, "meta": {"counts": {"total": 2, "remaining": 0}}}]
    else:
        pages = [page]
    with pytest.raises(AssertionError):
        inventory_replay(resource, pages)


@pytest.mark.parametrize("resource", RESOURCES)
@pytest.mark.parametrize("topology", TOPOLOGIES)
@pytest.mark.parametrize("page_size", (100, 1000))
def test_predictive_query_contract_covers_every_receiving_scope(resource, topology, page_size):
    target, variables, templar = fixture_context(resource, topology, "4.3.1")
    del templar
    prefix = f"nd4x_{resource}"
    variables[f"nd_{resource}_harness_page_size"] = page_size
    scopes = [{"name": "PARENT", "api": "/api/v1/manage/fabrics/PARENT", "suffix": ""}]
    if topology != "standalone":
        scopes.extend(
            [
                {"name": "CHILD1", "api": "/api/v1/manage/fabrics/CHILD1", "suffix": "?clusterName=C1" if topology == "mcfg" else ""},
                {"name": "CHILD2", "api": "/api/v1/manage/fabrics/CHILD2", "suffix": "?clusterName=C2" if topology == "mcfg" else ""},
            ]
        )
    tasks = yaml.safe_load((target / "tasks/nd4x_preflight.yaml").read_text())
    supported = next(task for task in tasks if "block" in task)["block"]
    snapshot_task = next(task for task in supported if task.get("name") == "Build complete predictive definition and attachment snapshots")
    variables[f"{prefix}_snapshots"] = []
    for scope in scopes:
        variables["item"] = scope
        variables.update(Templar(loader=DataLoader(), variables=variables).template(snapshot_task["ansible.builtin.set_fact"]))
    snapshots = variables[f"{prefix}_snapshots"]
    ActionModule.__new__(ActionModule)._validate_check_mode_queries(snapshots)
    assert len(snapshots) == len(scopes) * 2
    for scope in scopes:
        queries = [query for query in snapshots if query["path"].startswith(scope["api"] + "/")]
        assert len(queries) == 2
        assert all(query["pagination"]["page_size"] == page_size and not query.get("ignore_keys") for query in queries)
        attachment_query = next(query for query in queries if query.get("method") == "post")
        assert attachment_query["content"] == {}
        assert parse_qs(urlparse(attachment_query["path"]).query)["includeAll"] == ["true"]
        if scope["suffix"]:
            assert parse_qs(urlparse(attachment_query["path"]).query)["clusterName"] == [scope["name"].replace("CHILD", "C")]


@pytest.mark.parametrize("resource", RESOURCES)
def test_property_native_assertions_are_valid_harness_queries(resource):
    target, variables, templar = fixture_context(resource, "standalone", "4.3.1")
    del target
    plugin = ActionModule.__new__(ActionModule)
    for case in templar.template(variables[f"nd4x_{resource}_property_cases"]):
        expectations = [{"jsonpath": expression, "equals": value} for expression, value in case["native"].items()]
        expectations.extend(case.get("followup_expect", []))
        plugin._validate_nd_queries([{"path": "/api/v1/manage/fabrics/UNIT/resource", "expected_status": 200, "expect": expectations}])
        for expectation in expectations:
            parse(expectation["jsonpath"])
