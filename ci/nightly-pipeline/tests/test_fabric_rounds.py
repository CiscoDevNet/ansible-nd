"""The nightly runs the whole suite once per VXLAN fabric (iBGP first, then eBGP).

`validate_nd_prerequisites.py render-round` re-targets the Consul-sourced lab files for the second
round. These tests prove the rendered set is internally consistent and behaves exactly like the
canonical set with the two fabric names exchanged, and that the Jenkinsfile and the switch
pre-flight playbook carry the round / re-home contract.
"""
import contextlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import types

import pytest
import yaml

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
    # The reduced ToR test follows the round fabric through ansible_it_fabric and names no fabric literally.
    assert "nd_tor_switch_name: vxlan_leaf_3" in runner and "nd_tor_leaf_name: vxlan_leaf_4" in runner
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


def test_round_type_is_configurable_and_reaches_every_type_pin():
    texts = render_round_texts(canonical_texts(), ROUND_FABRIC, "routed")
    assert "vrfType: routed" in texts["run_integration_module.yaml"]
    assert "      advanced: routed\n" in texts["nd_prerequisite/nd_prerequisite_reconcile.yaml"]
    assert '"advanced": {"ref": "advanced", "name": "VXLAN_EVPN_Fabric_eBGP", "type": "routed"' in texts["validate_nd_prerequisites.py"]
    assert "{ref: advanced, name: VXLAN_EVPN_Fabric_eBGP, type: routed, lifecycle: retained}" in texts["nd_prerequisite_profiles.yaml"]


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
    assert "for (ndfcConfig in ndfcVersions) {" in text
    # A fabric round is not an ND version: the version shows once in the title, the rounds beside it.
    assert "ndfcVersions.collect { it.version }.unique().join(', ')" in text
    assert "env.ACTIVE_FABRIC_ROUNDS = (FABRIC_ROUNDS.size() > 1) ? FABRIC_ROUNDS.collect { it.label }.join(' + ') : ''" in text
    builder = groovy_function("buildRoundConfig")
    assert "roundConfig.versionId = \"${baseConfig.versionId}${fabricRound.idSuffix}\".toString()" in builder
    assert "roundConfig.fabric_name = fabricRound.fabric" in builder
    assert "(sw.fabric == baseConfig.fabric_name) ? fabricRound.fabric : sw.fabric" in builder
    assert "roundConfig.round_render = (fabricRound.fabric != homeRound.fabric)" in builder
    assert "roundConfig.rehome_fabrics = FABRIC_ROUNDS.collect { it.fabric }.unique()" in builder
    assert "must be the first round's fabric" in builder


def test_the_advanced_vpc_pair_follows_the_round_fabric():
    text = jenkins_text()
    assert "def pairFabric = (run.id == 'advanced') ? ndfcConfig.fabric_name : run.fabric" in text
    assert "def pairType = (run.id == 'advanced') ? (ndfcConfig.vpc_pair_fabric_type ?: run.type) : run.type" in text
    assert "def networkFabricName = ndfcConfig.fabric_name" in text
    assert "def networkFabricName = 'VXLAN_EVPN_Fabric_eBGP'" not in text
    assert "torFabricName" not in text


def test_vpc_pair_targets_are_rebuilt_fresh_inside_runFabricTest_every_round():
    # vpcPairRows/standaloneTargets/orderedIntegrationTargets/resultTargets must all be LOCAL to
    # runFabricTest(ndfcConfig), which runs once per ndfcVersions entry (once per fabric round) - so
    # nd_vpc_pair.advanced/.external are re-added, re-run and re-parsed on every round, not just the
    # first. A build where round 2 never starts (e.g. the eBGP round aborting earlier) only shows one
    # vpc_pair row per id because the ROUND never ran - that is not vpc_pair missing from the wiring.
    run_fabric_test = groovy_function("runFabricTest")
    assert "def vpcPairRows = []" in run_fabric_test
    assert 'def standaloneTargets = vpcPairRows.collect { row -> "nd_vpc_pair.${row.id}".toString() }' in run_fabric_test
    assert "def orderedIntegrationTargets = []" in run_fabric_test
    assert "orderedIntegrationTargets.addAll(standaloneTargets)" in run_fabric_test
    assert "def effectiveIntegrationModulesForResults = orderedIntegrationTargets" in run_fabric_test
    # None of the four are promoted to script-global state that could leak or go stale across rounds.
    text = jenkins_text()
    for name in ("vpcPairRows", "standaloneTargets", "orderedIntegrationTargets", "resultTargets"):
        assert f"@Field\ndef {name}" not in text


def test_a_round_off_the_canonical_fabric_checks_its_type_then_renders_before_anything_runs():
    prepare = groovy_function("applyFabricRound")
    assert "if (!ndfcConfig.round_render) {\n        return\n    }" in prepare
    # Read-only type check first, then the render; nothing is touched when the fabric is not the type the round needs.
    assert prepare.index("def reportedType = sh(returnStdout: true") < prepare.index("render-round")
    assert '"/api/v1/manage/fabrics/" + fabric' in prepare
    # ND labels a VXLAN EVPN eBGP/routed-underlay fabric 'routed', so the round accepts either label.
    assert "def acceptedTypes = (ndfcConfig.primary_fabric_type.toLowerCase() == 'vxlanebgp') ? ['vxlanebgp', 'routed'] : [ndfcConfig.primary_fabric_type.toLowerCase()]" in prepare
    assert "!acceptedTypes.contains(reportedType.toLowerCase())" in prepare
    assert "nothing was moved" in prepare
    assert "--round-fabric \"${ROUND_FABRIC}\"" in prepare and "--round-type \"${ROUND_FABRIC_TYPE}\"" in prepare
    assert "env.HOME_ROSTER_COPY_READY = 'true'" in prepare
    # The credentials are read from the bound environment, never printed or passed on a command line.
    assert 'os.environ["NDFC_USER"]' in prepare and 'os.environ["NDFC_PASSWORD"]' in prepare
    run_tests = groovy_function("runNDFCVersionTests")
    assert run_tests.index("applyFabricRound(ndfcConfig)") > run_tests.index("Install version-specific Dependencies")
    assert run_tests.index("applyFabricRound(ndfcConfig)") < run_tests.index("generateDynamicInventory(ndfcConfig)")


def test_the_lab_goes_home_after_the_last_reset_and_before_the_logs_are_bundled():
    text = jenkins_text()
    loop = text[text.index("for (ndfcConfig in ndfcVersions) {"):text.index("bundleAllLogs()\n")]
    assert "resetFabricBetweenVersions(ndfcConfig.round_tag ?: '')" in loop
    assert loop.index("resetFabricBetweenVersions(ndfcConfig.round_tag") < loop.index("restoreHomeFabric(ndfcVersions)")
    assert re.search(r"finally\s*\{\s*try\s*\{\s*if \(env.ND_PREREQUISITE_ONLY_EFFECTIVE != 'true'\) \{\s*restoreHomeFabric\(ndfcVersions\)", loop)
    home = groovy_function("restoreHomeFabric")
    assert "if (lastConfig.fabric_name == firstConfig.fabric_name && !needsRecovery) {" in home
    assert "integration_config.home.yml" in home
    assert "runSwitchMembershipSync(homeConfig, 'home'" in home
    assert "rethrowIfInterrupt(e)" in home
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in home
    assert "throw e" in home
    assert "usernamePassword(credentialsId: SWITCH_CREDENTIALS_ID" in home
    # The renderer keeps the canonical roster under exactly the name the restore reads.
    assert HOME_ROSTER_COPY == "integration_config.home.yml"


@pytest.mark.parametrize("failure", ["restore", "files", "home", "interrupt", "none"])
def test_round_failure_reporting_and_archiving_groovy_runtime(tmp_path, failure):
    java = os.environ.get("ND_REPORT_JAVA")
    groovy_jar = os.environ.get("ND_REPORT_GROOVY_JAR")
    if not java or not groovy_jar:
        pytest.skip("Set ND_REPORT_JAVA and ND_REPORT_GROOVY_JAR for offline Groovy checks")
    text = jenkins_text()
    lifecycle = text[text.index("                    try {\n                    for (ndfcConfig"):
                     text.index("                    // Clean workspace - best effort")]
    lifecycle = lifecycle.replace("org.jenkinsci.plugins.workflow.steps.FlowInterruptedException", "InterruptedException")
    harness = r'''
import groovy.transform.Field
@Field def env = [ND_SWITCH_RESTORE_FAILED: 'false', ND_PREREQUISITE_ONLY_EFFECTIVE: 'false']
@Field def currentBuild = [:]
@Field def events = []
@Field def TEST_RESULT_SUMMARY_BUF = ''
@Field def failure = 'SCENARIO'
def echo(message) {}
def setFailureFlag(name, value) {}
def isFailureFlagSet(name) { false }
def runNDFCVersionTests(config) {
    events.add('run:' + config.round_tag)
    if (failure == 'interrupt') { throw new InterruptedException('cancelled') }
    if (failure == 'files') { throw new RuntimeException('missing files') }
    env.REQUIRED_FILES_READY = 'true'
    if (failure == 'restore') {
        env.ND_SWITCH_RESTORE_FAILED = 'true'
        throw new RuntimeException('restore incomplete')
    }
}
def resetFabricBetweenVersions(tag) { events.add('reset:' + tag) }
def restoreHomeFabric(configs) {
    events.add('home')
    if (failure == 'home') { throw new RuntimeException('home failed') }
}
def bundleAllLogs() { events.add('archive') }
def ndfcVersions = [
    [version: '4.2', versionId: '42', round_tag: 'ibgp', fabric_name: 'home'],
    [version: '4.2', versionId: '42', round_tag: 'ebgp', fabric_name: 'round']
]
def thrown = false
try {
LIFECYCLE
} catch (Exception error) { thrown = true }
assert events[-2..-1] == ['home', 'archive'] : events
assert events.count('archive') == 1
assert thrown == (failure in ['files', 'home', 'interrupt'])
if (failure == 'restore') {
    assert events == ['run:ibgp', 'home', 'archive'] : events
    assert TEST_RESULT_SUMMARY_BUF.contains('ABORT|round stoppedibgp|')
    assert TEST_RESULT_SUMMARY_BUF.contains('ABORT|round skippedebgp|')
    assert env.PIPELINE_FAILED == 'true'
}
if (failure in ['files', 'interrupt']) { assert !events.contains('run:ebgp') }
'''.replace("SCENARIO", failure).replace("LIFECYCLE", lifecycle)
    script = tmp_path / "RoundLifecycle.groovy"
    script.write_text(harness)
    result = subprocess.run([java, "-cp", groovy_jar, "groovy.ui.GroovyMain", str(script)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_home_recovery_retries_a_failed_restore_before_the_second_round_render():
    home = groovy_function("restoreHomeFabric")
    assert "def needsRecovery = (env.ND_SWITCH_RESTORE_FAILED == 'true')" in home
    assert "def hasHomeCopy = (env.HOME_ROSTER_COPY_READY == 'true')" in home
    assert "if (!hasHomeCopy && !needsRecovery) {" in home
    assert 'def homeRoster = hasHomeCopy ? "${COLLECTIONS_DIRECTORY}/integration_config.home.yml" : "${COLLECTIONS_DIRECTORY}/integration_config.yml"' in home
    assert "runSwitchMembershipSync(homeConfig, 'home', homeRoster)" in home
    missing_files = home[home.index("if (env.REQUIRED_FILES_READY != 'true') {"):home.index("def homeRoster")]
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in missing_files
    assert "env.PIPELINE_FAILED = 'true'" in missing_files
    assert "NDP_SWITCH_RESTORE_FAILED: required files are unavailable" in missing_files


@pytest.mark.parametrize("has_home_copy", [True, False])
def test_home_restore_reports_canonical_destination_groovy_runtime(tmp_path, has_home_copy):
    java = os.environ.get("ND_REPORT_JAVA")
    groovy_jar = os.environ.get("ND_REPORT_GROOVY_JAR")
    if not java or not groovy_jar:
        pytest.skip("Set ND_REPORT_JAVA and ND_REPORT_GROOVY_JAR for offline Groovy checks")
    harness = r'''
import groovy.transform.Field
@Field def env = [ND_SWITCH_RESTORE_FAILED: 'true', HOME_ROSTER_COPY_READY: 'HAS_COPY', REQUIRED_FILES_READY: 'true']
@Field def COLLECTIONS_DIRECTORY = '/unused'
@Field def SWITCH_CREDENTIALS_ID = 'unused'
@Field def captured = [:]
def usernamePassword(config) { config }
def withCredentials(credentials, Closure body) { body() }
def runSwitchMembershipSync(config, phase, roster) { captured = [config: config, phase: phase, roster: roster] }
def echo(message) {}
def error(message) { throw new RuntimeException(message) }
def rethrowIfInterrupt(error) { throw error }
HOME_FUNCTION
def first = [fabric_name: 'home', primary_fabric_type: 'vxlanIbgp', round_tag: '', version: '4.2']
def last = [fabric_name: 'round', primary_fabric_type: 'vxlanEbgp', round_tag: 'ebgp', version: '4.3', rehome_fabrics: ['home', 'round']]
restoreHomeFabric([first, last])
assert captured.phase == 'home'
assert captured.config.fabric_name == 'home'
assert captured.config.primary_fabric_type == 'vxlanIbgp'
assert captured.config.round_tag == ''
assert captured.config.version == '4.3'
assert captured.config.rehome_fabrics == ['home', 'round']
assert captured.roster == '/unused/' + (env.HOME_ROSTER_COPY_READY == 'true' ? 'integration_config.home.yml' : 'integration_config.yml')
assert last.fabric_name == 'round'
'''.replace("HAS_COPY", str(has_home_copy).lower()).replace("HOME_FUNCTION", groovy_function("restoreHomeFabric"))
    script = tmp_path / "HomeRestore.groovy"
    script.write_text(harness)
    result = subprocess.run([java, "-cp", groovy_jar, "groovy.ui.GroovyMain", str(script)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_switch_sync_carries_the_round_roster_and_the_fabrics_to_move_between():
    sync = groovy_function("runSwitchMembershipSync")
    assert "def runSwitchMembershipSync(ndfcConfig, phase, rosterFile = '')" in sync
    assert "def isPost = (phase != 'pre')" in sync
    assert '-e "nd_switch_roster_file=${PREFLIGHT_ROSTER}"' in sync
    assert '-e "nd_switch_rehome_fabrics_csv=${PREFLIGHT_REHOME_FABRICS}"' in sync
    assert "(ndfcConfig.rehome_fabrics ?: []).join(',')" in sync
    assert "if (!isPost) {" in sync and "throw e" in sync
    assert "NDP_SWITCH_RESTORE_FAILED" in sync
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in sync
    assert "continuing best-effort (post-suite)" not in sync
    text = jenkins_text()
    assert "runSwitchMembershipSync(ndfcConfig, 'pre')" in text and "runSwitchMembershipSync(ndfcConfig, 'post')" in text
    # The per-module guard never moves a switch between fabrics: only the pre-flight and the restores do.
    guard = text[text.index("ensure_switches_ready() {"):text.index("ensure_switches_ready() {") + 2500]
    assert "nd_switch_rehome_fabrics_csv" not in guard


def test_preflight_failure_still_runs_restore_and_restore_failure_blocks_the_next_round():
    lifecycle = groovy_function("runNDFCVersionTests")
    assert re.search(r"try\s*\{\s*runSwitchPreflight\(ndfcConfig\)\s*runInterfacePreflight\(ndfcConfig\)\s*runPortChannelUnbundlePreflight\(ndfcConfig\)\s*runFabricTest\(ndfcConfig\)\s*\}\s*finally", lifecycle)
    assert "runSwitchPostRestore(ndfcConfig)" in lifecycle
    text = jenkins_text()
    assert "if (env.ND_SWITCH_RESTORE_FAILED == 'true')" in text
    assert "Switch restore failed; refusing to start another fabric round" in text


def test_switch_sync_has_independent_phase_timeouts_and_env_overrides():
    sync = groovy_function("runSwitchMembershipSync")
    selection = sync.split("def syncTimeout =", 1)[1].split("stage(stageName)", 1)[0]
    assert " ".join(selection.split()) == (
        "(phase == 'home') ? (env.ND_SWITCH_HOME_SYNC_TIMEOUT ?: '1500') : "
        "((phase == 'post') ? (env.ND_SWITCH_POST_SYNC_TIMEOUT ?: '2100') : "
        "(env.ND_SWITCH_SYNC_TIMEOUT ?: '3600'))"
    )
    assert '"PREFLIGHT_TIMEOUT=${syncTimeout}"' in sync
    assert 'timeout "${PREFLIGHT_TIMEOUT}" ansible-playbook' in sync


def test_switch_recovery_reaches_onboarding_without_optional_preparation():
    sync = groovy_function("runSwitchMembershipSync")
    assert "def isPost = (phase != 'pre')" in sync
    assert "PREFLIGHT_REDISCOVER_ENABLED=${env.ND_SWITCH_REDISCOVER_ENABLED ?: (isPost ? 'false' : 'true')}" in sync
    assert "PREFLIGHT_ONBOARD_INITIAL_WAIT=${env.ND_SWITCH_ONBOARD_INITIAL_WAIT ?: (isPost ? '0' : '480')}" in sync
    assert '-e "nd_switch_rediscover_enabled=${PREFLIGHT_REDISCOVER_ENABLED}"' in sync
    assert '-e "nd_switch_onboard_initial_wait=${PREFLIGHT_ONBOARD_INITIAL_WAIT}"' in sync
    assert '-e "nd_switch_require_full_roster=true"' in sync
    assert '-e "nd_switch_onboard_retries=${ND_SWITCH_ONBOARD_RETRIES:-10}"' in sync
    assert '-e "nd_switch_onboard_delay=${ND_SWITCH_ONBOARD_DELAY:-120}"' in sync


def test_switch_recovery_preparation_groovy_runtime(tmp_path):
    java = os.environ.get("ND_REPORT_JAVA")
    groovy_jar = os.environ.get("ND_REPORT_GROOVY_JAR")
    if not java or not groovy_jar:
        pytest.skip("Set ND_REPORT_JAVA and ND_REPORT_GROOVY_JAR for offline Groovy checks")
    harness = r'''
import groovy.transform.Field
@Field def env = [:]
@Field def COLLECTIONS_DIRECTORY = '/unused'
@Field def captured = [:]
@Field def shellCalls = 0
def stage(name, Closure body) { body() }
def echo(message) {}
def withEnv(entries, Closure body) {
    captured = entries.collectEntries { entry ->
        def parts = entry.toString().split('=', 2)
        [(parts[0]): parts[1]]
    }
    body()
}
def sh(script) { shellCalls += 1 }
'''
    checks = r'''
def config = [version: '4.3', rehome_fabrics: ['home', 'ebgp']]
['pre', 'post', 'home'].each { phase ->
    [[:], [ND_SWITCH_REDISCOVER_ENABLED: 'true', ND_SWITCH_ONBOARD_INITIAL_WAIT: '75'],
        [ND_SWITCH_REDISCOVER_ENABLED: 'false', ND_SWITCH_ONBOARD_INITIAL_WAIT: '0']].each { overrides ->
        env.clear()
        env.putAll([ND_SWITCH_PREFLIGHT_READY: 'true'] + overrides)
        runSwitchMembershipSync(config, phase, '/unused/home.yml')
        assert captured.PREFLIGHT_REDISCOVER_ENABLED ==
            (overrides.ND_SWITCH_REDISCOVER_ENABLED ?: (phase == 'pre' ? 'true' : 'false'))
        assert captured.PREFLIGHT_ONBOARD_INITIAL_WAIT ==
            (overrides.ND_SWITCH_ONBOARD_INITIAL_WAIT ?: (phase == 'pre' ? '480' : '0'))
        assert captured.PREFLIGHT_TIMEOUT == [pre: '3600', post: '2100', home: '1500'][phase]
        assert captured.PREFLIGHT_APPLY == 'true'
        assert captured.PREFLIGHT_ROSTER == '/unused/home.yml'
        assert captured.PREFLIGHT_REHOME_FABRICS == 'home,ebgp'
    }
}
env.clear()
env.putAll([ND_SWITCH_PREFLIGHT_READY: 'true', ND_PREREQUISITE_ONLY_EFFECTIVE: 'true'])
runSwitchMembershipSync(config, 'pre')
assert captured.PREFLIGHT_APPLY == 'false'
assert shellCalls == 10
'''
    program = tmp_path / "switch_recovery.groovy"
    program.write_text(harness + groovy_function("runSwitchMembershipSync") + checks, encoding="utf-8")
    result = subprocess.run(
        [java, "-cp", groovy_jar, "groovy.ui.GroovyMain", str(program)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_switch_sync_phase_caps_preserve_fatal_pre_and_soft_post_home():
    sync = groovy_function("runSwitchMembershipSync")
    catch = sync.split("} catch (Exception e) {", 1)[1]
    pre, remainder = catch.split("if (phase == 'home') {", 1)
    home, post = remainder.split("\n            }", 1)
    assert "if (!isPost) {" in pre and "throw e" in pre
    assert "currentBuild.result = 'UNSTABLE'" in home and "return" in home
    assert "env.ND_SWITCH_RESTORE_FAILED = 'true'" in post
    assert "currentBuild.result = 'UNSTABLE'" in post and "return" in post
    assert "NDP_SWITCH_RESTORE_INCOMPLETE" in post
    assert "env.PIPELINE_FAILED = 'true'" not in post and "error(" not in post
    assert catch.index("rethrowIfInterrupt(e)") < catch.index("if (!isPost)")


def test_incomplete_restore_skips_later_rounds_before_preparation():
    text = jenkins_text()
    loop = text.split("for (ndfcConfig in ndfcVersions) {", 1)[1]
    guard = loop.split("// Define failure flag", 1)[0]
    assert guard.lstrip().startswith("if (env.ND_SWITCH_RESTORE_FAILED == 'true') {")
    assert "currentBuild.result = 'UNSTABLE'" in guard
    assert "NDP_SWITCH_ROUNDS_SKIPPED" in guard
    assert "ABORT|round skipped" in guard
    assert "continue" in guard
    assert "env.PIPELINE_FAILED" not in guard
    assert "restoreHomeFabric(ndfcVersions)" in loop and "bundleAllLogs()" in loop


def test_port_channel_unbundle_preflight_runs_before_the_gate_and_clears_the_stale_pcs():
    # The remediating unbundle pre-flight is wired best-effort (own ready flag), runs
    # after the interface pre-flight and BEFORE runFabricTest (which hosts the read-only
    # verify_free_interfaces gate), and deletes the stale test port-channel50x then
    # Recalculate & Deploy so the shared Ethernet1/10-13 members are free.
    text = jenkins_text()
    assert "def CONSUL_PC_UNBUNDLE_FILES = ['nd_ensure_pc_members_free.yaml']" in text
    assert "CONSUL_PC_UNBUNDLE_FILES.each { pb -> downloadFromConsul(pb) }" in text
    assert "env.ND_PC_UNBUNDLE_READY = 'true'" in text
    assert "def pcUnbundleInstallFiles = (env.ND_PC_UNBUNDLE_READY == 'true') ? CONSUL_PC_UNBUNDLE_FILES : []" in text
    move_block = text[text.index("def moveFiles ="):text.index("def moveFiles =") + 400]
    assert "pcUnbundleInstallFiles" in move_block

    preflight = groovy_function("runPortChannelUnbundlePreflight")
    assert "if (env.ND_PC_UNBUNDLE_READY != 'true')" in preflight
    # ENFORCE in a normal run, audit-only during a prerequisite-only run.
    assert "def applyUnbundle = (env.ND_PREREQUISITE_ONLY_EFFECTIVE != 'true')" in preflight
    assert '-e "nd_pc_unbundle_apply=${PC_APPLY}"' in preflight
    assert '-e "nd_pc_fabric_name=${PC_FABRIC}"' in preflight
    assert "PC_FABRIC=${ndfcConfig.fabric_name}" in preflight
    assert "non-fatal; suite continues" in preflight

    # The playbook deletes port-channel501/502/503 and then Recalculate & Deploy.
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_pc_members_free.yaml").read_text(encoding="utf-8"))[0]
    assert play["vars"]["nd_pc_member_names"] == ["port-channel501", "port-channel502", "port-channel503"]
    assert play["vars"]["nd_pc_unbundle_apply"] is False  # audit-safe default
    delete_task = next(t for t in play["tasks"] if t.get("name", "").startswith("ENFORCE: delete"))
    assert delete_task["cisco.nd.nd_interface_port_channel_access"]["state"] == "deleted"
    rest_paths = [t["cisco.nd.nd_rest"]["path"] for t in play["tasks"] if "cisco.nd.nd_rest" in t]
    assert any("actions/configSave" in p for p in rest_paths)
    assert any("actions/deploy" in p for p in rest_paths)


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
    text = jenkins_text()
    assert "TEST_RESULT_SUMMARY_BUF += \"\\nABORT|round stopped${ndfcConfig.round_tag ?: ''}|" in text
    table = groovy_function("formatResultsTable")
    assert "f[0].trim() == 'ABORT'" in table and "ROUND NOT COMPLETED:" in table
    assert "def pbLabel = ((testType == 'smoke') ? \"${pb} (smoke)\" : pb) + (ndfcConfig.round_tag ?: '')" in text
    assert "def artifactLabel = ((testType == 'smoke') ? \"${token} (smoke)\" : token) + (ndfcConfig.round_tag ?: '')" in text
    assert "def roundsSuffix = activeRounds ? \" (${activeRounds})\" : ''" in text


def test_capability_reporting_is_shared_and_keeps_failure_handling():
    capability_parser = groovy_function("virtualPeerLinkCapabilityFailures")
    assert ".clear(" not in capability_parser
    assert "failureLines = []" in capability_parser
    parser = groovy_function("parseTestResults")
    assert parser.index("missing the current-run marker") < parser.index("virtualPeerLinkCapabilityFailures(testOutput)")
    assert "|${durationStr}|${capabilityNote}" in parser
    assert 'error("Test stage failed: unsupported virtual peer-link capability (no PLAY RECAP)")' in parser
    assert 'error("Test stage failed: ${failedCount} tasks failed")' in parser
    assert 'error("Test stage failed: Ansible exited with status ${ansibleExitStatus}")' in parser
    table = groovy_function("formatResultsTable")
    assert "affected task case(s)" in table
    assert "Failure totals are unchanged; other failures may coexist." in table
    assert "formatResultsTable(TEST_RESULT_SUMMARY_BUF)" in groovy_function("bundleAllLogs")
    assert "formatResultsTable(roundGroup.rows)" in jenkins_text()
    assert "webexMessages.collectMany { splitWebexReport(it, WEBEX_SAFE_MESSAGE_LIMIT) }" in jenkins_text()


def test_capability_reporting_groovy_runtime(tmp_path):
    java = os.environ.get("ND_REPORT_JAVA")
    groovy_jar = os.environ.get("ND_REPORT_GROOVY_JAR")
    if not java or not groovy_jar:
        pytest.skip("Set ND_REPORT_JAVA and ND_REPORT_GROOVY_JAR for offline Groovy checks")
    source = "\n".join(groovy_function(name) for name in (
        "virtualPeerLinkCapabilityFailures", "formatResultsTable", "parseTestResults", "splitWebexReport",
    ))
    harness = r'''
import groovy.transform.Field
@Field def env = [COLLECTIONS_DIRECTORY: '/unused', TOTAL_FAILED_COUNT: '0', TOTAL_PASSED_COUNT: '0']
@Field def TEST_RESULT_SUMMARY_BUF = ''
@Field def BUILD_FAILURE_REASON_BUF = ''
@Field def output = ''
@Field def messages = []
@Field def failureFlag = false
def echo(message) { messages.add(message.toString()) }
def sh(options) { output }
def withEnv(values, body) { body() }
def setFailureFlag(name, value) { failureFlag = value }
def error(message) { throw new RuntimeException(message.toString()) }
'''
    checks = r'''
def rejection = 'fatal: [leaf1]: FAILED! => {"msg":"Virtual peer-link is not supported on N9K-C9300v"}'
def rejected = "TASK [create virtual pair] ***\n${rejection}\n${rejection}\n" +
    'TASK [replace virtual pair] ***\nfatal: [leaf2]: FAILED! => {"msg":"N9K-C9300v does not support vPC Fabric Peering"}\n'
assert virtualPeerLinkCapabilityFailures(rejected) == ['create virtual pair', 'replace virtual pair']
assert virtualPeerLinkCapabilityFailures('TASK [physical pair]\nfatal: [leaf]: FAILED! => {"msg":"N9K-C9300v peer-link missing; vpc 101 invalid; inSync timeout"}') == []
assert virtualPeerLinkCapabilityFailures(rejected.replace('N9K-C9300v', 'N9K-C93180YC')) == []
assert virtualPeerLinkCapabilityFailures(rejected.replace('fatal:', 'ok:')) == []
assert virtualPeerLinkCapabilityFailures('TASK [expected rejection]\n' + rejection + '\n...ignoring\nTASK [physical failure]\nfatal: [leaf]: cable missing') == []
assert virtualPeerLinkCapabilityFailures('TASK [platform]\nok: [leaf] => N9K-C9300v\nTASK [failure]\nfatal: [leaf]: virtual peer-link not supported') == []
assert virtualPeerLinkCapabilityFailures('TASK [name|unsafe`label]\n' + rejection) == ['name unsafe label']
def config = [fabric_name: 'fabricA', version: '4.3', versionId: '43', round_tag: ' (iBGP)']
output = '[RUN_MARKER: current]\n' + rejected + '\nPLAY RECAP\nleaf : ok=4 failed=3 skipped=1\n[ANSIBLE_EXIT_STATUS: 2]'
try { parseTestResults(config, 'failed', 'nd_vpc_pair', 'integration', 'current'); assert false }
catch (RuntimeException failure) { assert failure.message.contains('Ansible exited with status 2') }
assert failureFlag
assert env.TOTAL_FAILED_COUNT == '3'
assert TEST_RESULT_SUMMARY_BUF.contains('FAIL|nd_vpc_pair (iBGP)|fabricA|4.3|4|3|1|N/A|NDP_UNSUPPORTED_CAPABILITY count=2')
assert messages.any { it.contains('N9K-C9300v virtual peer-link / vPC Fabric Peering is unsupported') }
def report = formatResultsTable(TEST_RESULT_SUMMARY_BUF)
assert report.contains('2 affected task case(s) across 1 module/round result(s).')
assert report.contains('tests=create virtual pair; replace virtual pair')
assert report.contains('Failure totals are unchanged')
TEST_RESULT_SUMMARY_BUF = ''
output = '[RUN_MARKER: current]\n' + rejected
try { parseTestResults(config, 'failed', 'nd_vpc_pair', 'integration', 'current'); assert false }
catch (RuntimeException failure) { assert failure.message.contains('no PLAY RECAP') }
assert TEST_RESULT_SUMMARY_BUF.readLines().findAll { it }.size() == 1
assert TEST_RESULT_SUMMARY_BUF.contains('ERR|nd_vpc_pair (iBGP)')
assert formatResultsTable(TEST_RESULT_SUMMARY_BUF).contains('count=2')
TEST_RESULT_SUMMARY_BUF = ''
try { parseTestResults(config, 'failed', 'nd_vpc_pair', 'integration', 'other-run'); assert false }
catch (RuntimeException failure) { assert failure.message.contains('current-run marker') }
assert TEST_RESULT_SUMMARY_BUF == ''
messages.clear()
output = '[RUN_MARKER: current]\n' + rejected + '\nPLAY RECAP\nleaf : ok=4 failed=0 skipped=1\n[ANSIBLE_EXIT_STATUS: 0]'
parseTestResults(config, 'failed', 'nd_vpc_pair', 'integration', 'current')
assert !TEST_RESULT_SUMMARY_BUF.contains('NDP_UNSUPPORTED_CAPABILITY')
assert !messages.any { it.contains('NDP_UNSUPPORTED_CAPABILITY') }
assert !formatResultsTable(TEST_RESULT_SUMMARY_BUF).contains('UNSUPPORTED CAPABILITY')
def manyRows = (1..120).collect { index ->
    "FAIL|module_${index}|fabricA|4.3|4|1|0|2s|NDP_UNSUPPORTED_CAPABILITY count=1 tests=case_${index}_end"
}.join('\n')
def largeReport = formatResultsTable(manyRows)
assert largeReport.contains('120 affected task case(s) across 120 module/round result(s).')
def parts = splitWebexReport(largeReport)
assert parts.size() > 1
assert parts.every { it.length() <= 7000 && it.count('```') % 2 == 0 }
(1..120).each { index -> assert parts.join('\n').count("tests=case_${index}_end") == 1 }
assert splitWebexReport('short report') == ['short report']
assert splitWebexReport('x' * 15000).join('') == 'x' * 15000
println 'Capability parser, console, report, failure preservation and stale-output checks passed'
'''
    program = tmp_path / "capability_reporting.groovy"
    program.write_text(harness + source + checks, encoding="utf-8")
    result = subprocess.run(
        [java, "-cp", groovy_jar, "groovy.ui.GroovyMain", str(program)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ----------------------------------------------------------------------------------------------
# nd_ensure_switches.yaml moves the switches between the two fabrics
# ----------------------------------------------------------------------------------------------
def ensure_switches_play():
    return yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text(encoding="utf-8"))[0]


def task_named(tasks, prefix):
    return next(task for task in tasks if task.get("name", "").startswith(prefix))


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
    block = task_named(ensure_switches_play()["tasks"], "Move the roster switches out of the round fabric")["block"]
    names = [task["name"] for task in block]
    gate = next(i for i, name in enumerate(names) if name.startswith("Refuse to move switches into a fabric type"))
    probe = next(i for i, name in enumerate(names) if name.startswith("Read the type of each fabric"))
    unpair = next(i for i, name in enumerate(names) if name.startswith("Unpair every vPC pair"))
    remove = next(i for i, name in enumerate(names) if name.startswith("Remove each switch from the fabric"))
    assert probe < gate < unpair < remove
    assert "NDP_SWITCH_REHOME_BLOCKED" in block[gate]["ansible.builtin.assert"]["fail_msg"]
    assert "NOTHING was removed" in block[gate]["ansible.builtin.assert"]["fail_msg"]
    # The destination must be a type nd_manage_switches can onboard into (an ND 'routed' fabric is not).
    play = ensure_switches_play()
    supported = play["vars"]["nd_switch_rehome_supported_types"]
    assert supported == ["vxlanibgp", "vxlanebgp", "vxlancampus", "external", "externalconnectivity"]
    assert "routed" not in supported
    # The removal is the module's deleted state on the leaving fabric. Its failure stops the move, as
    # before, unless the opt-in force-delete fallback is enabled (default off), which then gets a chance first.
    removal = block[remove]
    assert removal["cisco.nd.nd_manage_switches"]["state"] == "deleted"
    assert "failed_when" not in removal
    assert removal["ignore_errors"] == "{{ nd_switch_rehome_force_delete | bool }}"
    assert removal["cisco.nd.nd_manage_switches"]["config"] == "{{ _rm.value }}"
    # The onboard block still adds with exactly one nd_manage_switches call (pinned elsewhere); the move block never adds.
    assert not any(task.get("cisco.nd.nd_manage_switches", {}).get("state") == "merged" for task in block)


def test_the_move_waits_for_nd_to_finish_removing_the_switches():
    block = task_named(ensure_switches_play()["tasks"], "Move the roster switches out of the round fabric")["block"]
    wait = task_named(block, "Wait until ND reports the moved switches gone")
    assert wait["cisco.nd.nd_manage_switches"]["state"] == "gathered"
    assert "intersect" in wait["until"] and "| length) == 0" in wait["until"]
    assert wait["retries"] == "{{ nd_switch_rehome_retries | int }}"
    # The wait is BEST-EFFORT: it gives ND time to report the switches gone but never aborts the
    # round, so switches ND already removed (or is slow/lagging to report) are still onboarded to eBGP.
    assert wait["ignore_errors"] is True
    assert "failed_when" not in wait
    unpair = task_named(block, "Unpair every vPC pair")
    assert unpair["cisco.nd.nd_manage_vpc_pair"]["state"] == "deleted"
    assert "subelements('gathered.vpc_pairs', skip_missing=true)" in unpair["loop"]


def test_force_delete_fallback_is_opt_in_and_does_nothing_while_off():
    play = ensure_switches_play()
    assert play["vars"]["nd_switch_rehome_force_delete"] is False
    block = task_named(play["tasks"], "Move the roster switches out of the round fabric")["block"]
    names = [task["name"] for task in block]
    remove = next(i for i, name in enumerate(names) if name.startswith("Remove each switch from the fabric"))
    force = next(i for i, name in enumerate(names) if name.startswith("Force-remove the switches the normal call could not"))
    wait = next(i for i, name in enumerate(names) if name.startswith("Wait until ND reports the moved switches gone"))
    assert remove < force < wait
    # One flag gates every force-delete task, so with it off none of them is evaluated and the move behaves as before.
    fallback = block[force]
    assert fallback["when"] == "nd_switch_rehome_force_delete | bool"
    assert fallback["block"][0]["name"].startswith("Re-check which switches are still present")
    forced = task_named(fallback["block"], "Force-remove only the switches that are still present")
    assert forced["when"] == "(nd_rehome_force_needed | default([])) | length > 0"
    post = task_named(forced["block"], "POST switchActions/remove with force=true")["cisco.nd.nd_rest"]
    assert post["method"] == "post"
    assert post["path"] == "/api/v1/manage/fabrics/{{ _ff.key }}/switchActions/remove?force=true"
    assert post["content"] == {"switchIds": "{{ _ff.value }}"}
    # Only the force call tolerates failure; the wait task that verifies the move stays unconditional.
    assert "when" not in block[wait]


def test_webex_results_are_split_one_round_per_message_only_when_they_do_not_fit():
    text = jenkins_text()
    post = text[text.index("post {\n        always {"):text.index("        cleanup {")]
    # One message by default; a second compaction step splits per fabric round instead of dropping rows.
    assert "def webexMessages = [message]" in post
    assert "if (message.length() > WEBEX_SAFE_MESSAGE_LIMIT) {" in post
    assert "def roundGroups = groupResultRowsByFabric(TEST_RESULT_SUMMARY_BUF)" in post
    assert "if (roundGroups.size() > 1) {" in post
    assert "formatResultsTable(roundGroup.rows)" in post
    assert "if (index == 0) {" in post and "if (index == roundGroups.size() - 1) {" in post
    assert post.count("postWebexMarkdown(webexMessage)") == 1
    # The send itself moved into one helper that keeps the ASCII-only JSON escaping and never throws on a non-200 reply.
    sender = groovy_function("postWebexMarkdown")
    assert "String.format('\\\\u%04x', (int) ch)" in sender
    assert "contentType: 'APPLICATION_JSON_UTF8'" in sender
    assert "validResponseCodes: '100:599'" in sender
    assert "maskValue: true" in sender
    assert "httpRequest(" not in post and "withCredentials" not in post
    grouper = groovy_function("groupResultRowsByFabric")
    assert "fields[2].trim()" in grouper
    assert "current.fabric != fabric" in grouper
