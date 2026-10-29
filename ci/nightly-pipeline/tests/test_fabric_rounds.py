"""The nightly runs the whole suite once per VXLAN fabric (iBGP first, then eBGP).

`validate_nd_prerequisites.py render-round` re-targets the Consul-sourced lab files for the second
round. These tests prove the rendered set is internally consistent and behaves exactly like the
canonical set with the two fabric names exchanged, and that the Jenkinsfile and the switch
pre-flight playbook carry the round / re-home contract.
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import types

import pytest
import yaml

from test_five_issue_pipeline_fixes import groovy_runner as active_pipeline
from test_build124_switch_preflight import PRODUCER, groovy_runner as lifecycle_pipeline

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import validate_nd_prerequisites as canonical_validator  # noqa: E402
from validate_nd_prerequisites import (  # noqa: E402
    CANONICAL_FABRICS,
    HOME_ROSTER_COPY,
    ROUND_RENDER_FILES,
    ValidationError,
    _swap_fabric_names,
    expand_profile_executions,
    jenkins_targets,
    main,
    render_fabric_round,
    render_round_texts,
)

HOME_FABRIC = "VXLAN_EVPN_Fabric"
ROUND_FABRIC = "VXLAN_EVPN_Fabric_eBGP"
ROUND_TYPE = "vxlanEbgp"
# The disposable-cleanup guard in the validator describes the collection's own test files (same in every round).
CLEANUP_GUARD_FRAGMENT = r"""VXLAN_EVPN_Fabric['\"]\s*,\s*['\"]External_Connectivity_Fabric"""

# Installed (flat Consul layout) relative path -> its canonical source in this repository.
REPO_SOURCES = {
    "integration_config.yml": "tests/integration_config.yml",
    "nd_prerequisite_profiles.yaml": "tests/nd_prerequisite_profiles.yaml",
    "run_integration_module.yaml": "tests/run_integration_module.yaml",
    "reset_fabric.yaml": "consul/reset_fabric.yaml",
    "nd_prerequisite/nd_prerequisite_reconcile.yaml": "playbooks/nd_prerequisite/nd_prerequisite_reconcile.yaml",
    "fixtures/nd_prerequisite/valid_state.yaml": "tests/fixtures/nd_prerequisite/valid_state.yaml",
    "validate_nd_prerequisites.py": "tests/validate_nd_prerequisites.py",
}


def canonical_texts():
    assert set(REPO_SOURCES) == set(ROUND_RENDER_FILES)
    return {relative: (ROOT / source).read_text(encoding="utf-8") for relative, source in REPO_SOURCES.items()}


def install_canonical_tree(destination):
    for relative, text in canonical_texts().items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o644)
    return destination


def installed_files(destination):
    return sorted(path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file())


def load_validator(text):
    module = types.ModuleType("rendered_validator")
    exec(compile(text, "<rendered validator>", "exec", dont_inherit=True), module.__dict__)
    return module


def names_in(text, name):
    return len(re.findall(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", text))


@pytest.fixture(scope="module")
def rendered():
    return render_round_texts(canonical_texts(), ROUND_FABRIC, ROUND_TYPE)


# ----------------------------------------------------------------------------------------------
# The renderer
# ----------------------------------------------------------------------------------------------
def test_the_round_fabric_is_the_registrys_preserved_fabric():
    # The renderer takes both fabrics from the validator's own constants: round 2 runs on the preserved fabric.
    assert CANONICAL_FABRICS["advanced"]["name"] == HOME_FABRIC
    assert CANONICAL_FABRICS["advanced"]["lifecycle"] == "retained"
    assert CANONICAL_FABRICS["network_ebgp"]["name"] == ROUND_FABRIC
    assert CANONICAL_FABRICS["network_ebgp"]["lifecycle"] == "preserved"
    assert CANONICAL_FABRICS["network_ebgp"]["type"] == ROUND_TYPE
    assert canonical_validator.RETAINED == {HOME_FABRIC, "External_Connectivity_Fabric"}


def test_swap_exchanges_whole_fabric_names_in_one_pass():
    text = "a: VXLAN_EVPN_Fabric, b: VXLAN_EVPN_Fabric_eBGP, c: nd_test_fabric_switches.VXLAN_EVPN_Fabric | length"
    swapped, count = _swap_fabric_names(text, HOME_FABRIC, ROUND_FABRIC)
    assert swapped == (
        "a: VXLAN_EVPN_Fabric_eBGP, b: VXLAN_EVPN_Fabric, "
        "c: nd_test_fabric_switches.VXLAN_EVPN_Fabric_eBGP | length"
    )
    assert count == 3
    # Identifiers that merely contain a fabric name are left alone.
    untouched = _swap_fabric_names("VXLAN_EVPN_Fabric_other X_VXLAN_EVPN_Fabric", HOME_FABRIC, ROUND_FABRIC)
    assert untouched == ("VXLAN_EVPN_Fabric_other X_VXLAN_EVPN_Fabric", 0)


def test_every_runtime_file_exchanges_the_two_fabric_names(rendered):
    originals = canonical_texts()
    for relative in ROUND_RENDER_FILES:
        if relative == "validate_nd_prerequisites.py":
            continue  # targeted edits only, see the validator test below
        before, after = originals[relative], rendered[relative]
        assert names_in(before, HOME_FABRIC) > 0, relative
        # Every home occurrence became a round occurrence and vice versa (the registry and runner mention both).
        assert names_in(after, HOME_FABRIC) == names_in(before, ROUND_FABRIC), relative
        assert names_in(after, ROUND_FABRIC) == names_in(before, HOME_FABRIC), relative
        assert names_in(after, "External_Connectivity_Fabric") == names_in(before, "External_Connectivity_Fabric"), relative
        assert before != after, relative


def test_registry_and_validator_exchange_the_primary_and_preserved_roles(rendered):
    registry = yaml.safe_load(rendered["nd_prerequisite_profiles.yaml"])
    fabrics = registry["lab"]["fabrics"]
    assert fabrics["advanced"] == {"ref": "advanced", "name": ROUND_FABRIC, "type": ROUND_TYPE, "lifecycle": "retained"}
    assert fabrics["network_ebgp"] == {"ref": "network_ebgp", "name": HOME_FABRIC, "type": "vxlanIbgp", "lifecycle": "preserved"}
    assert registry["lab"]["retained_fabric_names"] == [ROUND_FABRIC, "External_Connectivity_Fabric"]
    assert registry["lab"]["preserved_fabric_names"] == [HOME_FABRIC]
    assert set(registry["runtime_defaults"]["nd_test_fabric_switches"]) == {ROUND_FABRIC, "External_Connectivity_Fabric"}
    # No profile still names the home fabric as its working fabric: only its preserved definition and name list remain.
    assert names_in(rendered["nd_prerequisite_profiles.yaml"], HOME_FABRIC) == 2

    validator = load_validator(rendered["validate_nd_prerequisites.py"])
    assert validator.RETAINED == {ROUND_FABRIC, "External_Connectivity_Fabric"}
    assert validator.PRESERVED == {HOME_FABRIC}
    assert validator.CANONICAL_FABRICS["advanced"] == fabrics["advanced"]
    assert validator.CANONICAL_FABRICS["network_ebgp"] == fabrics["network_ebgp"]
    assert set(validator.CANONICAL_RUNTIME_DEFAULTS["nd_test_fabric_switches"]) == {ROUND_FABRIC, "External_Connectivity_Fabric"}
    # The cleanup-guard regex is NOT swapped: a blanket swap would corrupt a description of files that never change.
    assert canonical_texts()["validate_nd_prerequisites.py"].count(CLEANUP_GUARD_FRAGMENT) == 1
    assert rendered["validate_nd_prerequisites.py"].count(CLEANUP_GUARD_FRAGMENT) == 1


def test_runner_reconcile_fixture_and_reset_follow_the_round_fabric(rendered):
    runner = rendered["run_integration_module.yaml"]
    assert "vrfType: vxlanEbgp" in runner
    assert "vrfType: vxlanIbgp" not in runner
    assert "vrfType: externalConnectivity" in runner
    assert "nd_test_fabric_switches.VXLAN_EVPN_Fabric_eBGP | length == 6" in runner
    assert "nd_test_fabric_switches.VXLAN_EVPN_Fabric |" not in runner
    # ToR runs its authored develop role; no reduced-suite aliases are injected.
    assert "nd_tor_switch_name: vxlan_leaf_3" not in runner and "nd_tor_leaf_name: vxlan_leaf_4" not in runner
    assert "test_tor_fabric_name" not in runner
    reconcile = rendered["nd_prerequisite/nd_prerequisite_reconcile.yaml"]
    assert "      advanced: VXLAN_EVPN_Fabric_eBGP\n" in reconcile
    assert "    _ndp_fabric_type_by_ref:\n      advanced: vxlanEbgp\n" in reconcile
    state = yaml.safe_load(rendered["fixtures/nd_prerequisite/valid_state.yaml"])
    assert state["fabrics"]["advanced"]["name"] == ROUND_FABRIC
    assert state["fabrics"]["advanced"]["type"] == ROUND_TYPE
    reset = yaml.safe_load(rendered["reset_fabric.yaml"])[0]
    assert reset["vars"]["nd_fabric_name"] == ROUND_FABRIC
    assert reset["vars"]["reset_fabric_switches"][0]["fabric"] == ROUND_FABRIC
    roster = yaml.safe_load(rendered["integration_config.yml"])["nd_test_fabric_switches"]
    assert [item["name"] for item in roster[ROUND_FABRIC]] == [
        "vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1", "vxlan_leaf_3", "vxlan_leaf_4",
    ]
    assert HOME_FABRIC not in roster


def test_round_type_matches_the_preserved_fabric_and_reaches_every_type_pin():
    texts = render_round_texts(canonical_texts(), ROUND_FABRIC, ROUND_TYPE)
    assert "vrfType: vxlanEbgp" in texts["run_integration_module.yaml"]
    assert "      advanced: vxlanEbgp\n" in texts["nd_prerequisite/nd_prerequisite_reconcile.yaml"]
    assert load_validator(texts["validate_nd_prerequisites.py"]).CANONICAL_FABRICS["advanced"]["type"] == ROUND_TYPE
    assert yaml.safe_load(texts["nd_prerequisite_profiles.yaml"])["lab"]["fabrics"]["advanced"]["type"] == ROUND_TYPE
    # A generic routed destination cannot replace the preserved VXLAN fabric.
    with pytest.raises(ValidationError, match="round type must be the preserved fabric type"):
        render_round_texts(canonical_texts(), ROUND_FABRIC, "routed")


@pytest.mark.parametrize("bad", ["vxlan-ebgp", "vxlanEbgp\n", "x y", "1abc", "a;b"])
def test_render_refuses_a_malformed_round_type(bad):
    with pytest.raises(ValidationError, match="invalid fabric type"):
        render_round_texts(canonical_texts(), ROUND_FABRIC, bad)


def test_render_refuses_any_fabric_but_the_preserved_one():
    for wrong in (HOME_FABRIC, "External_Connectivity_Fabric", "ANSIBLE_NIGHTLY_EBGP", "nope"):
        with pytest.raises(ValidationError, match="must be the preserved fabric"):
            render_round_texts(canonical_texts(), wrong, ROUND_TYPE)


def test_render_refuses_to_swap_back_when_the_files_are_already_rendered(rendered):
    validator = load_validator(rendered["validate_nd_prerequisites.py"])
    # The rendered validator names the round fabric as primary, so asking it to render again is refused.
    with pytest.raises(validator.ValidationError, match="must be the preserved fabric"):
        validator.render_round_texts(rendered, ROUND_FABRIC, ROUND_TYPE)


def test_a_drifted_file_shape_aborts_instead_of_half_rendering():
    texts = canonical_texts()
    texts["nd_prerequisite_profiles.yaml"] = texts["nd_prerequisite_profiles.yaml"].replace(
        "{ref: advanced, name: VXLAN_EVPN_Fabric, type: vxlanIbgp, lifecycle: retained}",
        "{ref: advanced, name: VXLAN_EVPN_Fabric, type: vxlanIbgp, lifecycle: retained, extra: 1}",
    )
    with pytest.raises(ValidationError, match="expected exactly one occurrence"):
        render_round_texts(texts, ROUND_FABRIC, ROUND_TYPE)
    texts = canonical_texts()
    texts["integration_config.yml"] = "nd_test_fabric_switches: {}\n"
    with pytest.raises(ValidationError, match="no fabric name to re-target"):
        render_round_texts(texts, ROUND_FABRIC, ROUND_TYPE)
    texts = canonical_texts()
    del texts["reset_fabric.yaml"]
    with pytest.raises(ValidationError, match="round files are missing"):
        render_round_texts(texts, ROUND_FABRIC, ROUND_TYPE)


# ----------------------------------------------------------------------------------------------
# The rendered set behaves like the canonical set
# ----------------------------------------------------------------------------------------------
@contextlib.contextmanager
def orchestrator_bound_to(validator_text):
    """Import the orchestrator against the given validator source, the way the pipeline runs them together."""
    validator = types.ModuleType("validate_nd_prerequisites")
    exec(compile(validator_text, "<validator>", "exec", dont_inherit=True), validator.__dict__)
    saved = sys.modules.get("validate_nd_prerequisites")
    sys.modules["validate_nd_prerequisites"] = validator
    try:
        spec = importlib.util.spec_from_file_location("nd_round_orchestrator", ROOT / "tests/nd_prerequisite_orchestrator.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield validator, module
    finally:
        if saved is None:
            sys.modules.pop("validate_nd_prerequisites", None)
        else:
            sys.modules["validate_nd_prerequisites"] = saved


def attempt(call):
    try:
        return call()
    except Exception as exc:  # noqa: BLE001 - the error text is part of the behaviour being compared
        return {"error": type(exc).__name__, "message": str(exc)}


def plan_outcome(orchestrator, registry, state, execution_id):
    def plan():
        resolved = orchestrator.resolve_execution(registry, execution_id, allow_auto_confirm=True)
        return {
            "operations": orchestrator.plan_topology_delta(registry, resolved, state),
            "runtime": orchestrator.runtime_vars_for_execution(resolved, "run-1", "baseline-1"),
        }

    return attempt(plan)


def swapped(value):
    text, _ = _swap_fabric_names(json.dumps(value, sort_keys=True), HOME_FABRIC, ROUND_FABRIC)
    return json.loads(text)


def test_the_rendered_round_plans_exactly_like_the_canonical_round(rendered):
    """Every profile execution plans identically (modulo the swapped names) on the rendered registry and state."""
    originals = canonical_texts()
    canonical_registry = yaml.safe_load(originals["nd_prerequisite_profiles.yaml"])
    canonical_state = yaml.safe_load(originals["fixtures/nd_prerequisite/valid_state.yaml"])
    rendered_registry = yaml.safe_load(rendered["nd_prerequisite_profiles.yaml"])
    rendered_state = yaml.safe_load(rendered["fixtures/nd_prerequisite/valid_state.yaml"])

    execution_ids = [
        execution["execution_id"]
        for profile_id in canonical_registry["profiles"]
        for execution in expand_profile_executions(canonical_registry, profile_id)
    ]
    assert len(execution_ids) > 30
    selected = [profile for profile in canonical_registry["profiles"] if profile.startswith("integration.")]

    with orchestrator_bound_to(originals["validate_nd_prerequisites.py"]) as (_, home_orchestrator):
        expected = {item: plan_outcome(home_orchestrator, canonical_registry, canonical_state, item) for item in execution_ids}
        expected_schedule = attempt(lambda: home_orchestrator.build_phase_schedule(canonical_registry, selected, allow_auto_confirm=True))
    with orchestrator_bound_to(rendered["validate_nd_prerequisites.py"]) as (round_validator, round_orchestrator):
        actual = {item: plan_outcome(round_orchestrator, rendered_registry, rendered_state, item) for item in execution_ids}
        actual_schedule = attempt(lambda: round_orchestrator.build_phase_schedule(rendered_registry, selected, allow_auto_confirm=True))
        # The rendered validator accepts the rendered registry, so the planner's own registry gate passes.
        assert round_validator.validate_registry(rendered_registry) == []

    assert any("operations" in item for item in actual.values())
    assert [item for item in execution_ids if swapped(expected[item]) != actual[item]] == []
    assert swapped(expected_schedule) == actual_schedule
    # The round really plans on the round fabric: no runtime variable still points at the home fabric.
    runtime_fabrics = {
        value
        for item in actual.values()
        for value in item.get("runtime", {}).values()
        if isinstance(value, str) and value in (HOME_FABRIC, ROUND_FABRIC)
    }
    assert runtime_fabrics == {ROUND_FABRIC}


def test_the_rendered_registry_covers_every_effective_jenkins_module(rendered):
    validator = load_validator(rendered["validate_nd_prerequisites.py"])
    registry = yaml.safe_load(rendered["nd_prerequisite_profiles.yaml"])
    targets = jenkins_targets((ROOT / "Jenkinsfile_nd_jenkins_script").read_text(encoding="utf-8"))
    modules = targets["EFFECTIVE_INTEGRATION_MODULES"] + targets["STANDALONE_INTEGRATION_MODULES"]
    assert validator.validate_effective_module_profile_coverage(modules, registry["profiles"]) == []


# ----------------------------------------------------------------------------------------------
# Writing the rendered files
# ----------------------------------------------------------------------------------------------
def test_render_fabric_round_writes_atomically_and_keeps_the_home_roster(tmp_path):
    install_canonical_tree(tmp_path)
    originals = canonical_texts()
    changed = render_fabric_round(tmp_path, ROUND_FABRIC, ROUND_TYPE)
    assert changed == sorted(ROUND_RENDER_FILES)
    # The untouched canonical roster is kept for the return to the home fabric.
    assert (tmp_path / HOME_ROSTER_COPY).read_text(encoding="utf-8") == originals["integration_config.yml"]
    assert ROUND_FABRIC in yaml.safe_load((tmp_path / "integration_config.yml").read_text())["nd_test_fabric_switches"]
    assert HOME_FABRIC in yaml.safe_load((tmp_path / HOME_ROSTER_COPY).read_text())["nd_test_fabric_switches"]
    assert (tmp_path / "validate_nd_prerequisites.py").stat().st_mode & 0o777 == 0o644
    # No staging leftovers beside the installed files.
    assert installed_files(tmp_path) == sorted([*ROUND_RENDER_FILES, HOME_ROSTER_COPY])


def test_a_failed_render_leaves_every_installed_file_untouched(tmp_path):
    install_canonical_tree(tmp_path)
    registry_path = tmp_path / "nd_prerequisite_profiles.yaml"
    # A registry that no longer matches its validator is caught by the rendered-set verification, not at run time.
    registry_path.write_text(registry_path.read_text(encoding="utf-8").replace("schema_version: 2", "schema_version: 3"), encoding="utf-8")
    before = {relative: (tmp_path / relative).read_text(encoding="utf-8") for relative in ROUND_RENDER_FILES}
    with pytest.raises(ValidationError, match="rendered registry fails the rendered validator"):
        render_fabric_round(tmp_path, ROUND_FABRIC, ROUND_TYPE)
    assert {relative: (tmp_path / relative).read_text(encoding="utf-8") for relative in ROUND_RENDER_FILES} == before
    assert installed_files(tmp_path) == sorted(ROUND_RENDER_FILES)

    (tmp_path / "reset_fabric.yaml").unlink()
    with pytest.raises(ValidationError, match="missing or unsafe"):
        render_fabric_round(tmp_path, ROUND_FABRIC, ROUND_TYPE)


def test_render_round_cli_reports_the_marker_and_failures(tmp_path, capsys):
    install_canonical_tree(tmp_path)
    assert main(["render-round", "--root", str(tmp_path), "--round-fabric", ROUND_FABRIC, "--round-type", ROUND_TYPE]) == 0
    out = capsys.readouterr().out
    assert "NDP_FABRIC_ROUND_RENDERED" in out
    assert f"{ROUND_FABRIC} is now the primary fabric (vxlanEbgp)" in out
    assert HOME_ROSTER_COPY in out
    assert main(["render-round", "--root", str(tmp_path / "missing"), "--round-fabric", ROUND_FABRIC]) == 1
    assert "NDP_FABRIC_ROUND_RENDER_FAILED" in capsys.readouterr().err
    assert main(["render-round", "--root", str(tmp_path), "--round-fabric", HOME_FABRIC]) == 1
    assert "NDP_FABRIC_ROUND_RENDER_FAILED" in capsys.readouterr().err


# ----------------------------------------------------------------------------------------------
# The Jenkinsfile runs one round per fabric and returns the lab home
# ----------------------------------------------------------------------------------------------
JENKINSFILE = ROOT / "Jenkinsfile_nd_jenkins_script"


def jenkins_text():
    return JENKINSFILE.read_text(encoding="utf-8")


def groovy_function(name):
    text = jenkins_text()
    start = text.index(f"def {name}(")
    return text[start:text.index("\n}\n", start) + 3]


def test_fabric_rounds_run_ibgp_first_then_the_preserved_ebgp_fabric():
    text = jenkins_text()
    block = re.search(r"@Field\ndef FABRIC_ROUNDS = \[\n(.*?)\n\]\n", text, re.S).group(1)
    rounds = re.findall(r"\[fabric: '([^']+)', type: '([^']+)', vpcType: '([^']+)', label: '([^']+)', idSuffix: '([^']*)'\]", block)
    assert rounds == [
        (HOME_FABRIC, "vxlanIbgp", "vxlanIbgp", "iBGP", ""),
        (ROUND_FABRIC, ROUND_TYPE, "vxlanEbgp", "eBGP", "_EBGP"),
    ]
    # Round 1 is the canonical fabric exactly as the registry pins it; round 2 is the registry's preserved fabric.
    assert rounds[0][:2] == (CANONICAL_FABRICS["advanced"]["name"], CANONICAL_FABRICS["advanced"]["type"])
    assert rounds[1][:2] == (CANONICAL_FABRICS["network_ebgp"]["name"], CANONICAL_FABRICS["network_ebgp"]["type"])
    assert "timeout(time: 20, unit: 'HOURS')" in text


def test_every_nd_version_is_expanded_into_one_run_per_round():
    text = jenkins_text()
    assert "def baseNdfcVersions = [" in text
    assert "def ndfcVersions = []" in text
    assert "ndfcVersions.add(buildRoundConfig(baseConfig, fabricRound))" in text
    assert "for (baseConfig in baseNdfcVersions) {" in text
    assert "def roundConfigs = FABRIC_ROUNDS.collect { buildRoundConfig(baseConfig, it) }" in text
    assert "for (ndfcConfig in roundConfigs) {" in text
    assert "ndfcVersions.collect { it.version }.unique().join(', ')" in text
    assert "env.ACTIVE_FABRIC_ROUNDS = FABRIC_ROUNDS.collect { it.label }.join(' + ')" in text
    builder = groovy_function("buildRoundConfig")
    assert 'roundConfig.versionId = "${baseConfig.versionId}${fabricRound.idSuffix}".toString()' in builder
    assert "roundConfig.fabric_name = fabricRound.fabric" in builder
    assert "(sw.fabric == baseConfig.fabric_name) ? fabricRound.fabric : sw.fabric" in builder
    assert "roundConfig.round_render = (fabricRound.fabric != homeRound.fabric)" in builder
    assert "roundConfig.rehome_fabrics = FABRIC_ROUNDS.collect { it.fabric }.unique()" in builder
    assert "must be the first round's fabric" in builder


def test_the_advanced_vpc_pair_follows_the_round_fabric():
    text = jenkins_text()
    assert "def pairFabric = run.id == 'advanced' ? ndfcConfig.fabric_name : run.fabric" in text
    assert "def pairType = run.id == 'advanced' ? ndfcConfig.vpc_pair_fabric_type : run.type" in text
    assert "def networkFabricName = ndfcConfig.fabric_name" in text
    assert "def networkFabricName = 'VXLAN_EVPN_Fabric_eBGP'" not in text
    assert "torFabricName" not in text


def test_vpc_pair_targets_are_rebuilt_fresh_inside_runFabricTest_every_round():
    run_fabric_test = groovy_function("runFabricTest")
    assert "def vpcPairRows = []" in run_fabric_test
    assert 'def standaloneTargets = vpcPairRows.collect { row -> "nd_vpc_pair.${row.id}".toString() }' in run_fabric_test
    assert "def orderedIntegrationTargets = []" in run_fabric_test
    assert "orderedIntegrationTargets.addAll(standaloneTargets)" in run_fabric_test
    assert "def plannedResultTargets = orderedIntegrationTargets.collect { [it, 'integration'] }" in run_fabric_test
    assert "registerStructuredExecutions(ndfcConfig, plannedResultTargets," in run_fabric_test
    text = jenkins_text()
    for name in ("vpcPairRows", "standaloneTargets", "orderedIntegrationTargets", "plannedResultTargets"):
        assert f"@Field\ndef {name}" not in text


def test_a_round_off_the_canonical_fabric_checks_its_type_then_renders_before_anything_runs():
    prepare = groovy_function("applyFabricRound")
    assert "if (!ndfcConfig.round_render) {\n        return\n    }" in prepare
    assert prepare.index("def reportedType = sh(returnStdout: true") < prepare.index("render-round")
    assert '"/api/v1/manage/fabrics/" + fabric' in prepare
    assert "reportedType.toLowerCase() != ndfcConfig.primary_fabric_type.toLowerCase()" in prepare
    assert "acceptedTypes" not in prepare
    assert "no switches were moved" in prepare
    assert '--round-fabric "${ROUND_FABRIC}"' in prepare and '--round-type "${ROUND_FABRIC_TYPE}"' in prepare
    assert "env.HOME_ROSTER_COPY_READY = 'true'" in prepare
    assert 'os.environ["NDFC_USER"]' in prepare and 'os.environ["NDFC_PASSWORD"]' in prepare
    run_tests = groovy_function("runNDFCVersionTests")
    assert run_tests.index("applyFabricRound(ndfcConfig)") > run_tests.index("Install runtime inputs")
    assert run_tests.index("applyFabricRound(ndfcConfig)") < run_tests.index("generateDynamicInventory(ndfcConfig)")


def test_the_lab_goes_home_after_the_last_reset_and_before_the_logs_are_bundled():
    text = jenkins_text()
    producer = text[text.index("for (baseConfig in baseNdfcVersions) {"):text.index("// Clean workspace - best effort")]
    assert "resetFabricBetweenVersions(ndfcConfig.round_tag ?: '')" in producer
    assert producer.index("resetFabricBetweenVersions(ndfcConfig.round_tag") < producer.index("restoreHomeFabric(roundConfigs, activeRound)")
    assert "withCleanupPreservingFailure({" in producer
    assert producer.index("restoreHomeFabric(roundConfigs, activeRound)") < producer.index("finishStructuredExecution(executionStatus)")
    assert producer.index("finishStructuredExecution(executionStatus)") < producer.index("bundleAllLogs()")
    home = groovy_function("restoreHomeFabric")
    assert "if (env.HOME_RESTORE_REQUIRED != 'true') { return }" in home
    assert "integration_config.home.yml" in home
    assert "runSwitchMembershipSync(homeConfig, 'home', homeRoster)" in home
    assert home.index("resetFabricBetweenVersions(") < home.index("runSwitchMembershipSync(")
    assert "rethrowIfInterrupt(e)" in home and "throw e" in home
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in home
    assert "usernamePassword(credentialsId: SWITCH_CREDENTIALS_ID" in home
    assert HOME_ROSTER_COPY == "integration_config.home.yml"


@pytest.mark.parametrize("failure", ["restore", "files", "home", "interrupt", "none"])
def test_round_failure_reporting_and_archiving_groovy_runtime(lifecycle_pipeline, failure):
    body = 'def scenario = ' + json.dumps(failure) + '\ndef failureMode = "reported-module-failure"\n'
    body += 'def failure = new IllegalStateException("offline infrastructure failure")\n'
    body += PRODUCER + r'''
script.metaClass.runNDFCVersionTests = { Object round ->
    calls.add('run:' + round.round_label)
    if (scenario == 'interrupt') { throw new InterruptedException('cancelled') }
    if (scenario == 'files') { throw failure }
    if (scenario == 'restore') {
        context.ND_SWITCH_RESTORE_FAILED = 'true'
        context.PIPELINE_FAILED = 'true'
    }
}
script.metaClass.restoreHomeFabric = { Object rounds, Object active ->
    calls.add('home')
    if (scenario == 'home') { throw failure }
}
def caught = null
try { script.run() } catch (Exception error) { caught = error }
assert calls.contains('home') && calls.count('bundle') == 1
assert calls.indexOf('home') < calls.indexOf('fold') && calls.indexOf('fold') < calls.indexOf('bundle')
assert (caught != null) == (scenario in ['files', 'home', 'interrupt'])
if (scenario == 'restore') {
    assert !calls.contains('run:eBGP')
    assert calls.contains('record:eBGP')
    assert context.PIPELINE_FAILED == 'true'
}
if (scenario in ['files', 'interrupt']) { assert !calls.contains('run:eBGP') }
assert calls.contains('finish:' + (scenario == 'interrupt' ? 'interrupted' : (scenario in ['files', 'home'] ? 'failed' : 'success')))
'''
    lifecycle_pipeline(body)


def test_home_recovery_remains_required_until_the_canonical_roster_is_confirmed():
    home = groovy_function("restoreHomeFabric")
    assert "if (env.HOME_RESTORE_REQUIRED != 'true') { return }" in home
    assert "def homeConfig = roundConfigs[0]" in home
    assert "env.HOME_ROSTER_COPY_READY == 'true' ?" in home
    assert '"${COLLECTIONS_DIRECTORY}/integration_config.home.yml" : "${COLLECTIONS_DIRECTORY}/integration_config.yml"' in home
    assert "runSwitchMembershipSync(homeConfig, 'home', homeRoster)" in home
    missing_files = home[home.index("if (env.REQUIRED_FILES_READY != 'true') {"):home.index("// Clear pairs/resources")]
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in missing_files
    assert "env.PIPELINE_FAILED = 'true'" in missing_files
    assert "NDP_SWITCH_HOME_RESTORE_FAILED: required runtime files are unavailable" in missing_files
    assert home.index("runSwitchMembershipSync(homeConfig, 'home', homeRoster)") < home.index("env.HOME_RESTORE_REQUIRED = 'false'")


@pytest.mark.parametrize("has_home_copy", [True, False])
def test_home_restore_reports_canonical_destination_groovy_runtime(lifecycle_pipeline, has_home_copy):
    body = 'context.HOME_ROSTER_COPY_READY = ' + json.dumps(str(has_home_copy).lower()) + '\n'
    body += r'''
context.HOME_RESTORE_REQUIRED = 'true'
context.REQUIRED_FILES_READY = 'true'
def captured = [:]
script.metaClass.usernamePassword = { Map options -> options }
script.metaClass.withCredentials = { List options, Closure work -> work.call() }
script.metaClass.resetFabricBetweenVersions = { Object label -> calls.add('reset') }
script.metaClass.generateDynamicInventory = { Object round -> calls.add('inventory:' + round.fabric_name) }
script.metaClass.runSwitchMembershipSync = { Object round, Object phase, Object roster ->
    captured = [config: round, phase: phase, roster: roster]
}
def first = [fabric_name: 'home', primary_fabric_type: 'vxlanIbgp', round_tag: '', version: '4.3', rehome_fabrics: ['home', 'round']]
def last = [fabric_name: 'round', primary_fabric_type: 'vxlanEbgp', round_tag: 'ebgp', version: '4.3', rehome_fabrics: ['home', 'round']]
script.restoreHomeFabric([first, last], last)
assert captured.phase == 'home'
assert captured.config.is(first)
assert captured.config.fabric_name == 'home' && captured.config.primary_fabric_type == 'vxlanIbgp'
assert captured.config.round_tag == '' && captured.config.version == '4.3'
assert captured.config.rehome_fabrics == ['home', 'round']
assert captured.roster == '/fixture/collection/' + (context.HOME_ROSTER_COPY_READY == 'true' ? 'integration_config.home.yml' : 'integration_config.yml')
assert calls == ['reset', 'inventory:home']
assert context.HOME_RESTORE_REQUIRED == 'false' && last.fabric_name == 'round'
'''
    lifecycle_pipeline(body)


def test_the_switch_sync_carries_the_round_roster_and_the_fabrics_to_move_between():
    sync = groovy_function("runSwitchMembershipSync")
    assert "def runSwitchMembershipSync(ndfcConfig, phase, rosterFile = '')" in sync
    assert "def isPost = (phase != 'pre')" in sync
    assert '-e "nd_switch_roster_file=${PREFLIGHT_ROSTER}"' in sync
    assert '-e "nd_switch_rehome_fabrics_csv=${PREFLIGHT_REHOME_FABRICS}"' in sync
    assert "(ndfcConfig.rehome_fabrics ?: []).join(',')" in sync
    assert "if (!isPost || phase == 'home') { throw e }" in sync
    assert "NDP_SWITCH_RESTORE_INCOMPLETE" in sync
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in sync
    assert "env.PIPELINE_FAILED = 'true'" in sync
    assert "continuing best-effort (post-suite)" not in sync
    text = jenkins_text()
    assert "runSwitchMembershipSync(ndfcConfig, 'pre')" in text and "runSwitchMembershipSync(ndfcConfig, 'post')" in text
    guard = text[text.index("ensure_switches_ready() {"):text.index("ensure_switches_ready() {") + 2500]
    assert "nd_switch_rehome_fabrics_csv" not in guard


def test_preflight_failure_keeps_home_recovery_required_and_blocks_the_next_round():
    lifecycle = groovy_function("runNDFCVersionTests")
    assert lifecycle.index("env.HOME_RESTORE_REQUIRED = 'true'") < lifecycle.index("runSwitchPreflight(ndfcConfig)")
    assert "def preflightCompleted = false" in lifecycle
    assert re.search(r"runSwitchPreflight\(ndfcConfig\)\s*preflightCompleted = true\s*runFabricTest\(ndfcConfig\)", lifecycle)
    assert "if (preflightCompleted) {\n                    runSwitchPostRestore(ndfcConfig)" in lifecycle
    assert "NDP_SWITCH_ACTIVE_ROUND_RESTORE_SKIPPED" in lifecycle
    assert "Outer home-fabric recovery remains required" in lifecycle
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in lifecycle
    text = jenkins_text()
    assert "if (env.ND_SWITCH_RESTORE_FAILED == 'true')" in text
    assert "previous restore did not confirm the full roster" in text


def test_switch_sync_passes_one_enclosing_budget_to_every_phase():
    sync = groovy_function("runSwitchMembershipSync")
    assert "def timeoutLimit = env.ND_SWITCH_SYNC_TIMEOUT ?: '3600'" in sync
    assert '"PREFLIGHT_TIMEOUT=${timeoutLimit}"' in sync
    assert 'timeout "${PREFLIGHT_TIMEOUT}" ansible-playbook' in sync
    assert '-e "nd_switch_guard_timeout_seconds=${PREFLIGHT_TIMEOUT}"' in sync
    assert "returnStatus: true" in sync


def test_switch_recovery_reaches_onboarding_with_guard_owned_preparation_defaults():
    sync = groovy_function("runSwitchMembershipSync")
    assert "def autoOnboard = (env.ND_PREREQUISITE_ONLY_EFFECTIVE != 'true')" in sync
    assert '-e "nd_switch_apply=${PREFLIGHT_APPLY}"' in sync
    assert '-e "nd_switch_require_full_roster=true"' in sync
    assert '-e "nd_switch_preserve_config=false"' in sync
    values = ensure_switches_play()["vars"]
    assert "ND_SWITCH_REDISCOVER_ENABLED" in values["nd_switch_rediscover_enabled"]
    assert "ND_SWITCH_ONBOARD_INITIAL_WAIT" in values["nd_switch_onboard_initial_wait"]
    assert "ND_SWITCH_ONBOARD_RETRIES" in values["nd_switch_onboard_retries"]
    assert "ND_SWITCH_ONBOARD_DELAY" in values["nd_switch_onboard_delay"]


def test_switch_recovery_budget_and_audit_mode_groovy_runtime(lifecycle_pipeline):
    lifecycle_pipeline(r'''
script.metaClass.sh = { Object options -> assert options.returnStatus == true; shells.add(options.script.toString()); return 0 }
['pre', 'post', 'home'].each { phase ->
    [[:], [ND_SWITCH_SYNC_TIMEOUT: '75']].each { overrides ->
        context.remove('ND_SWITCH_SYNC_TIMEOUT')
        context.putAll(overrides)
        script.runSwitchMembershipSync(config, phase, '/fixture/home.yml')
        def captured = capturedEnvironments[-1]
        assert captured.PREFLIGHT_TIMEOUT == (overrides.ND_SWITCH_SYNC_TIMEOUT ?: '3600')
        assert captured.PREFLIGHT_APPLY == 'true'
        assert captured.PREFLIGHT_ROSTER == '/fixture/home.yml'
        assert captured.PREFLIGHT_REHOME_FABRICS == 'VXLAN_EVPN_Fabric,VXLAN_EVPN_Fabric_eBGP'
    }
}
context.ND_PREREQUISITE_ONLY_EFFECTIVE = 'true'
script.runSwitchMembershipSync(config, 'pre')
assert capturedEnvironments[-1].PREFLIGHT_APPLY == 'false'
assert shells.size() == 7
''')


def test_switch_sync_propagates_pre_and_home_errors_and_flags_post_failure():
    sync = groovy_function("runSwitchMembershipSync")
    catch = sync.split("} catch (Exception e) {", 1)[1]
    assert catch.index("rethrowIfInterrupt(e)") < catch.index("if (isPost)")
    assert "if (!isPost || phase == 'home') { throw e }" in catch
    assert "if (!isPost || phase == 'home') { error(reason) }" in catch
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in catch
    assert "env.PIPELINE_FAILED = 'true'" in catch
    assert "NDP_SWITCH_RESTORE_INCOMPLETE" in catch
    assert "currentBuild.result = 'UNSTABLE'" not in catch


def test_incomplete_restore_skips_later_rounds_before_preparation():
    text = jenkins_text()
    loop = text.split("for (ndfcConfig in roundConfigs) {", 1)[1]
    guard = loop.split("activeRound = ndfcConfig", 1)[0]
    assert guard.lstrip().startswith("if (env.ND_SWITCH_RESTORE_FAILED == 'true') {")
    assert "recordUnstartedRound(ndfcConfig, 'previous switch restore incomplete')" in guard
    assert "NDP_SWITCH_ROUNDS_SKIPPED" in guard
    assert "continue" in guard
    assert "runNDFCVersionTests" not in guard
    assert "restoreHomeFabric(roundConfigs, activeRound)" in loop and "bundleAllLogs()" in loop


def test_port_channel_unbundle_is_scoped_to_the_runner_gate_with_an_audit_safe_default():
    # The current round lifecycle delegates topology preparation to the runner;
    # it has no separate best-effort port-channel stage before the suite.
    lifecycle = groovy_function("runNDFCVersionTests")
    assert "runPortChannelUnbundlePreflight" not in lifecycle
    assert "runFabricTest(ndfcConfig)" in lifecycle
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_pc_members_free.yaml").read_text(encoding="utf-8"))[0]
    assert play["vars"]["nd_pc_member_names"] == ["port-channel501", "port-channel502", "port-channel503"]
    assert play["vars"]["nd_pc_unbundle_apply"] is False
    delete_task = next(t for t in play["tasks"] if t.get("name", "").startswith("ENFORCE: delete"))
    assert delete_task["cisco.nd.nd_interface_port_channel_access"]["state"] == "deleted"
    rest_paths = [t["cisco.nd.nd_rest"]["path"] for t in play["tasks"] if "cisco.nd.nd_rest" in t]
    assert any("actions/configSave" in path for path in rest_paths)
    assert any("actions/deploy" in path for path in rest_paths)


def test_runner_releases_reserved_port_channel_members_before_the_prerequisite_gate():
    # Per-module C1 self-heal: before the read-only verify_free_interfaces gate (hosted by the
    # "prepare and verify declared prerequisites" block) runs for a port-channel module, release
    # any stale port-channel501/502/503 holding the shared Ethernet1/10-13 pool on vxlan_leaf_1,
    # then Recalculate & Deploy. Best-effort so a stuck port-channel can never block the module.
    play = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text(encoding="utf-8"))[0]
    pre = play["pre_tasks"]
    names = [t.get("name", "") for t in pre]
    heal = next(t for t in pre if t.get("name", "").endswith("release reserved port-channel members before the gate"))
    gate_index = names.index("[{{ test_module }}] prepare and verify declared prerequisites")
    assert names.index(heal["name"]) < gate_index  # the self-heal must run BEFORE the gate
    # Gated to exactly the three port-channel modules, and only while prerequisites run.
    assert "nd_prerequisite_enable | default(false) | bool" in heal["when"]
    assert any(
        all(mod in condition for mod in (
            "nd_interface_port_channel_access",
            "nd_interface_port_channel_trunk_host",
            "nd_interface_port_channel_routed",
        ))
        for condition in heal["when"]
    )
    # Scope: port-channel501/502/503 on ansible_switch1 (vxlan_leaf_1 -> frees Ethernet1/10-13).
    cfg = heal["vars"]["_ndp_pc_delete_config"]
    assert [row["interface_name"] for row in cfg] == ["port-channel501", "port-channel502", "port-channel503"]
    assert {row["switch_ip"] for row in cfg} == {"{{ ansible_switch1 }}"}
    inner = heal["block"]
    delete_task = next(t for t in inner if "cisco.nd.nd_interface_port_channel_access" in t)
    assert delete_task["cisco.nd.nd_interface_port_channel_access"]["state"] == "deleted"
    assert delete_task["failed_when"] is False  # best-effort: never blocks the module
    # Recalculate + Deploy, each only when the delete actually freed a stale port-channel.
    rest_tasks = [t for t in inner if "cisco.nd.nd_rest" in t]
    paths = [t["cisco.nd.nd_rest"]["path"] for t in rest_tasks]
    assert any("actions/configSave" in p for p in paths)
    assert any("actions/deploy" in p for p in paths)
    for task in rest_tasks:
        assert task["when"] == "_ndp_pc_unbundle_delete is changed"
        assert task["failed_when"] is False


def test_a_round_that_stops_early_is_listed_with_its_reason_and_rows_carry_the_round():
    missing = groovy_function("recordUnstartedRound")
    assert "result: 'NOT_RUN', coverage: 'UNKNOWN', counts: [:], case_totals: [:]" in missing
    assert "round_label: ndfcConfig.round_label" in missing
    assert "reason ?: 'round not reached'" in missing
    assert "MODULE_ACTIVITY_RESULTS.keySet().any" in missing
    summary = groovy_function("moduleCaseSummaryRows")
    assert 'label += " (${row.round_label} round)"' in summary
    fold = groovy_function("foldStructuredResults")
    assert '${row.module} (${row.scope}; ${row.round_label} round)|${row.artifact}' in fold


def test_capability_reporting_is_shared_and_keeps_failure_handling():
    spec = importlib.util.spec_from_file_location("round_invocation_summary", ROOT / "playbooks/nd_result_summary.py")
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    rejection = 'fatal: [leaf]: FAILED! => {"msg":"Virtual peer-link is not supported on N9K-C9300v", "private":"PRIVATE_BODY"}'
    failures = "TASK [create virtual pair] ***\n" + rejection + "\n" + rejection + "\n" + \
        "TASK [replace virtual pair] ***\nfatal: [leaf]: N9K-C9300v does not support vPC Fabric Peering\n"
    def collect(body, marker="current", failed=2, code=2, recap=True):
        text = "[RUN_MARKER: " + marker + "]\n" + body
        if recap:
            text += "PLAY RECAP\nleaf : ok=4 changed=0 unreachable=0 failed=" + str(failed) + " skipped=1\n"
        text += "[ANSIBLE_EXIT_STATUS: " + str(code) + "]\n[TIMESTAMP_END: 20]\n"
        return agent.parse_log(io.StringIO(text), "current")
    result = collect(failures)
    assert result["status"] == "FAIL" and result["counts"]["failed"] == 2
    assert result["capability_tasks"] == ["create virtual pair", "replace virtual pair"]
    assert "PRIVATE_BODY" not in json.dumps(result)
    assert collect(failures, marker="stale")["status"] == "ERR"
    assert collect(failures, recap=False)["status"] == "ERR"
    assert collect(failures, failed=0, code=2)["status"] == "FAIL"
    assert collect("TASK [expected rejection] ***\n" + rejection + "\n...ignoring\n", failed=0, code=0)["capability_tasks"] == []
    assert collect(failures.replace("N9K-C9300v", "N9K-C93180YC"))["capability_tasks"] == []
    assert collect("TASK [physical pair] ***\nfatal: [leaf]: N9K-C9300v peer-link missing; inSync timeout\n")["capability_tasks"] == []
    assert collect("TASK [platform] ***\nok: [leaf]: N9K-C9300v\nTASK [failure] ***\nfatal: [leaf]: virtual peer-link not supported\n")["capability_tasks"] == []


def test_capability_failure_survives_active_aggregation_and_bounded_webex_parts(active_pipeline):
    active_pipeline(r'''
def rejection = 'N9K-C9300v virtual peer-link is unsupported; use the physical peer-link'
def row = [version_id: 'ND43', module: 'nd_vpc_pair.advanced', run_id: 'current', nd: '4.3',
    fabric: 'fixture', scope: 'iBGP', round_label: 'iBGP', result: 'FAIL', coverage: 'COMPLETE',
    case_totals: [started: 2, passed: 0, failed: 2, skipped: 0, incomplete: 0],
    counts: [merged: [started: 2]], failure: rejection, reporting_status: 'SUCCESS',
    archive_status: 'success', artifact: 'fixture.txt', duration: '20s']
script.metaClass.sh = { Object options -> '' }
script.metaClass.readFile = { Map options -> script.writeReportingJson([rows: [row], failed: true, reporting_errors: []]) }
script.metaClass.archiveArtifacts = { Map options -> }
script.foldStructuredResults()
assert script.binding.env.PIPELINE_FAILED == 'true'
assert script.BUILD_FAILURE_REASON_BUF.contains(rejection)
def raw = script.moduleCaseSummaryRows()
assert raw.startsWith('FAIL|nd_vpc_pair.advanced|fixture|4.3|0|2|0|')
def table = script.formatResultsTable(raw, 'module test cases')
assert table.contains('FAIL') && table.contains('iBGP') && table.contains('eBGP') && table.contains('NOT_RUN')
assert script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList()).failed == '2'
def manyRows = (1..120).collect { index ->
    "FAIL|module_${index}|fixture|4.3|0|1|0|2s|case_${index}_end|iBGP"
}.join('\n')
def largeReport = script.formatResultsTable(manyRows, 'module test cases')
def parts = script.splitWebexMessage(largeReport, 'Build fixture continuation\n')
assert parts.size() > 1
assert parts.every { it.length() <= 7000 && it.count('```') % 2 == 0 }
(1..120).each { index -> assert parts.join('\n').count("case_${index}_end") == 1 }
''')


# ----------------------------------------------------------------------------------------------
# nd_ensure_switches.yaml moves the switches between the two fabrics
# ----------------------------------------------------------------------------------------------
def ensure_switches_play():
    return yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text(encoding="utf-8"))[0]


def walk_tasks(tasks):
    for task in tasks:
        yield task
        for branch in ("block", "rescue", "always"):
            yield from walk_tasks(task.get(branch, []))


def task_named(tasks, prefix):
    return next(task for task in walk_tasks(tasks) if task.get("name", "").startswith(prefix))


def test_switches_are_moved_only_in_enforce_mode_and_only_between_the_listed_fabrics():
    play = ensure_switches_play()
    names = [task["name"] for task in play["tasks"]]
    find = next(i for i, name in enumerate(names) if name.startswith("Find the missing roster switches that sit in another round fabric"))
    move = next(i for i, name in enumerate(names) if name.startswith("Move the roster switches out of the round fabric"))
    onboard = next(i for i, name in enumerate(names) if name.startswith("Onboard the missing switches"))
    assert find < move < onboard
    assert play["vars"]["nd_switch_rehome_fabrics_csv"] == ""
    assert "nd_switch_rehome_fabrics_csv.split(',')" in play["vars"]["nd_switch_rehome_fabrics"]
    # Nothing moves unless the caller names the fabrics, and a plan is printed even in audit mode.
    find_task = play["tasks"][find]
    assert "nd_switch_rehome_fabrics | length > 0" in find_task["when"]
    assert not any("nd_switch_apply" in str(condition) for condition in find_task["when"])
    move_task = play["tasks"][move]
    assert "nd_switch_apply | bool" in move_task["when"]
    assert "(nd_rehome_moves | default([])) | length > 0" in move_task["when"]


def test_the_destination_type_is_checked_before_a_switch_is_removed():
    play = ensure_switches_play()
    destination = task_named(play["tasks"], "Validate missing-switch destinations")
    move = task_named(play["tasks"], "Move the roster switches out of the round fabric")
    assert play["tasks"].index(destination) < play["tasks"].index(move)
    probe = task_named(destination["block"], "Read the type of each missing-switch destination")
    gate = task_named(destination["block"], "Refuse to onboard switches")
    assert destination["block"].index(probe) < destination["block"].index(gate)
    assert "NDP_SWITCH_REHOME_BLOCKED" in gate["ansible.builtin.assert"]["fail_msg"]
    assert "NOTHING was removed" in gate["ansible.builtin.assert"]["fail_msg"]
    assert "preserve_config=false" in gate["ansible.builtin.assert"]["fail_msg"]
    block = list(walk_tasks(move["block"]))
    unpair = task_named(block, "Unpair every vPC pair")
    removal = task_named(block, "Remove each switch from the fabric")
    accepted = task_named(block, "Require acceptance of every requested normal removal")
    assert block.index(unpair) < block.index(removal) < block.index(accepted)
    assert play["vars"]["nd_switch_rehome_supported_types"] == ["vxlanibgp", "vxlanebgp"]
    request = removal["cisco.nd.nd_rest"]
    assert request["method"] == "post"
    assert request["path"] == "/api/v1/manage/fabrics/{{ _rm.key }}/switchActions/remove"
    assert "selectattr('from_fabric', 'equalto', _rm.key)" in request["content"]["switchIds"]
    assert "map(attribute='serial')" in request["content"]["switchIds"]
    assert removal["failed_when"] is False and removal["no_log"] is True
    assert "_report.classification == 'accepted'" in accepted["ansible.builtin.assert"]["that"]
    assert not any(task.get("cisco.nd.nd_manage_switches", {}).get("state") == "merged" for task in block)


def test_the_move_waits_for_nd_to_finish_removing_the_switches():
    block = task_named(ensure_switches_play()["tasks"], "Move the roster switches out of the round fabric")["block"]
    tasks = list(walk_tasks(block))
    accepted = task_named(tasks, "Require acceptance of every requested normal removal")
    wait = task_named(tasks, "Wait until ND reports the moved switches gone")
    assert tasks.index(accepted) < tasks.index(wait)
    assert wait["cisco.nd.nd_manage_switches"]["state"] == "gathered"
    assert "intersect" in wait["until"] and "| length) == 0" in wait["until"]
    assert wait["retries"] == "{{ nd_switch_rehome_retries | int }}"
    assert "ignore_errors" not in wait
    assert "nd_rehome_left is succeeded" in wait["until"]
    assert "nd_rehome_left.gathered is defined" in wait["until"]
    assert "select('mapping')" in wait["until"]
    assert "failed_when" not in wait
    unpair = task_named(tasks, "Unpair every vPC pair")
    assert unpair["cisco.nd.nd_manage_vpc_pair"]["state"] == "deleted"
    assert "subelements('gathered.vpc_pairs', skip_missing=true)" in unpair["loop"]


def test_force_delete_is_rejected_before_any_controller_call():
    play = ensure_switches_play()
    assert play["vars"]["nd_switch_rehome_force_delete"] is False
    policy = task_named(play["tasks"], "Require a bounded non-force")
    assert "not (nd_switch_rehome_force_delete | default(false) | bool)" in policy["ansible.builtin.assert"]["that"]
    policy_index = play["tasks"].index(policy)
    assert not any(any(key.startswith("cisco.nd.") for key in task)
                   for task in walk_tasks(play["tasks"][:policy_index + 1]))
    assert "force=true" not in json.dumps(play)
    assert "NDP_SWITCH_LIFECYCLE_POLICY" in policy["ansible.builtin.assert"]["fail_msg"]


def test_webex_splits_the_complete_report_and_keeps_a_minimal_fallback():
    text = jenkins_text()
    post = text[text.index("post {\n        always {"):text.index("        cleanup {")]
    assert "final int WEBEX_SAFE_MESSAGE_LIMIT = 7000" in post
    assert "splitWebexMessage(message, continuationHeader, WEBEX_SAFE_MESSAGE_LIMIT)" in post
    assert "sendWebexNotificationMessages(notificationMessages)" in post
    assert "selectedBranch" in post and "selectedCommit" in post
    assert "sendWebexNotificationMessages([minimalBuildNotification(e.getClass().getName())])" in post
    sender = groovy_function("sendWebexNotificationMessages")
    assert "writeReportingJson(" in sender
    assert "contentType: 'APPLICATION_JSON_UTF8'" in sender
    assert "validResponseCodes: '100:599'" in sender
    assert "maskValue: true" in sender
    assert "if (resp.status == 200)" in sender
    assert 'error("Webex notification returned HTTP ${resp.status}")' in sender
    assert "httpRequest(" not in post and "withCredentials" not in post
    splitter = groovy_function("splitWebexMessage")
    assert "maxLength = 7000" in splitter
    assert "continuationHeader" in splitter
