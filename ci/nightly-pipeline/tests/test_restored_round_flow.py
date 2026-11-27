"""Run real producer/version/batch methods with only external operations substituted."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest
from test_build124_switch_preflight import PRELUDE, PRODUCER

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script", "Jenkinsfile_nd_jenkins_script_temp_switches",
            "Jenkinsfile_nd_jenkins_script_comm_list")
PRODUCER_WITH_REAL_VERSION = re.sub(
    r"script\.metaClass\.runNDFCVersionTests = \{.*?\n\}\n", "", PRODUCER, count=1, flags=re.S)


@pytest.fixture(scope="module", params=VARIANTS)
def groovy(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA", "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java"))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    assert java.is_file() and jar.is_file(), "Real Groovy runtime is required"
    folder = tmp_path_factory.mktemp("restored-round-flow")
    counter = 0

    def run(body):
        nonlocal counter
        counter += 1
        path = folder / f"flow-{counter}.groovy"
        path.write_text(PRELUDE + "\n" + PRODUCER_WITH_REAL_VERSION + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(path), str(ROOT / request.param)],
                                text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout

    return run


@pytest.mark.parametrize("scenario", ["healthy", "ibgp-test-failed", "both-tests-failed", "batch-setup-failed",
                                     "preflight-failed", "migration-unconfirmed", "standalone-move-recovers", "missing-receipt",
                                     "malformed-receipt", "restore-failed", "apply-failed", "reset-failed",
                                     "post-restore-exception", "flow-aborted", "java-interrupted"])
def test_real_full_flow_continues_failures_and_only_interrupts_stop_later_rounds(groovy, scenario):
    groovy("def scenario = " + json.dumps(scenario) + "\n" + r'''
script.binding.currentBuild.currentResult = 'SUCCESS'
context.ND_RUNTIME_INPUTS_READY = 'true'
context.ND_REPORTING_RELATIVE_ROOT = 'fixture-reports'
context.ND_REPORTING_ROOT = '/fixture/reports'
context.ANSIBLE_HOST = '192.0.2.10'
// Build 203: Jenkins copied the unset NDFC_HOST_CURRENT as the string 'null'.
context.NDFC_HOST_CURRENT = 'null'
script.binding.setVariable('BASE_DIRECTORY', '/fixture/base')
script.binding.setVariable('COLLECTIONS_DIRECTORY', '/fixture/collection')
script.binding.setVariable('params', [DEBUG:false, DEBUG_MODULES:''])
script.metaClass.pwd = { -> '/fixture/workspace' }
script.metaClass.stage = { Object name, Closure work ->
    if (!(name in ['Set environment', 'Clone Repository'])) { work.call() }
}
// withEnv restores only its own bindings; unrelated build-failure flags persist.
script.metaClass.withEnv = { List entries, Closure work ->
    def prior = [:]
    def absent = []
    entries.each { entry ->
        int split = entry.indexOf('='); def key = entry.substring(0, split)
        if (context.containsKey(key)) { prior[key] = context[key] } else { absent.add(key) }
        context[key] = entry.substring(split + 1)
    }
    try { work.call() }
    finally { absent.each { context.remove(it) }; prior.each { key,value -> context[key]=value } }
}
script.metaClass.usernamePassword = { Map options -> options }
script.metaClass.withCredentials = { List options, Closure work -> work.call() }
def reportReadyField = script.getClass().getDeclaredField('ND_CASE_REPORT_READY')
reportReadyField.setAccessible(true)
script.metaClass.foldStructuredResults = { ->
    calls.add('fold')
    reportReadyField.set(script, true)
}
script.metaClass.applyFabricRound = { Object round ->
    calls.add('apply:' + round.round_label)
    if (scenario == 'apply-failed') { throw new IllegalStateException('apply failed') }
}
script.metaClass.resetFabricBetweenVersions = { Object label ->
    calls.add('reset')
    if (scenario == 'reset-failed') { throw new IllegalStateException('reset failed') }
}
script.metaClass.generateDynamicInventory = { Object round ->
    context.CURRENT_NDFC_INVENTORY = '/fixture/inventory.yaml'
}
script.metaClass.runSwitchPreflight = { Object round ->
    calls.add('pre:' + round.round_label)
    if (scenario in ['preflight-failed', 'migration-unconfirmed', 'standalone-move-recovers']) { throw new IllegalStateException('preflight failed') }
}
script.metaClass.runSwitchPostRestore = { Object round ->
    calls.add('post:' + round.round_label)
    if (scenario == 'post-restore-exception') { throw new IllegalStateException('post restore failed') }
    context.ND_SWITCH_RESTORE_FAILED = (scenario == 'restore-failed' ? 'true' : 'false')
    if (scenario == 'restore-failed') { context.PIPELINE_FAILED='true' }
}
script.metaClass.registerStructuredExecutions = { Object round, Object targets, Object run, Object fabric, Object pairs ->
    calls.add('register:' + round.round_label)
    return '/fixture/reports/executions/' + round.versionId + '/' + run
}
script.metaClass.installEmbeddedReportingHelper = { Object name, Object target -> calls.add('install:' + name); true }
def migrationAudits = 0
def swallowed = []
script.metaClass.catchError = { Map options, Closure work ->
    try { work.call() } catch (Exception e) {
        script.rethrowIfInterrupt(e)
        swallowed.add(e.message)
    }
}
script.metaClass.sh = { Object options ->
    def text = (options instanceof Map ? options.script : options).toString()
    if (text.contains('nd_switch_fabric_move.py" move')) {
        calls.add('standalone-move:' + context.MOVE_SRC + '->' + context.MOVE_DST + '@' + context.MOVE_ND_HOST)
        return scenario == 'migration-unconfirmed' ? 1 : 0
    }
    if (text.contains('nd_switch_fail_on_missing=true')) {
        calls.add('migration-check:' + context.MIGRATION_ROSTER)
        migrationAudits++
        return scenario == 'migration-unconfirmed' || (scenario == 'standalone-move-recovers' && migrationAudits == 1) ? 2 : 0
    }
    if (text.contains('NDP_MODULE_BATCH_CLOSED:')) {
        def round = context.VERSION_ID.endsWith('_EBGP') ? 'eBGP' : 'iBGP'
        calls.add('batch:' + round)
        if (scenario == 'batch-setup-failed') { throw new IllegalStateException('source validation failed') }
        if (scenario == 'flow-aborted') { throw loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException').newInstance('aborted') }
        if (scenario == 'java-interrupted') { throw new InterruptedException('interrupted') }
        return 0
    }
    if (text.contains('cat -- "$ND_MODULE_BATCH_STATUS"')) {
        calls.add('receipt')
        if (scenario == 'missing-receipt') { throw new IllegalStateException('missing receipt') }
        if (scenario == 'malformed-receipt') { return 'invalid' }
        return scenario == 'both-tests-failed' || (scenario == 'ibgp-test-failed' && !context.VERSION_ID.endsWith('_EBGP')) ? '1\n' : '0\n'
    }
    return options instanceof Map && options.returnStdout ? 'fixture listing' : 0
}
def caught = null
try { script.run() } catch (Exception e) { caught = e }
assert calls.contains('pre:iBGP')
assert calls.any { it.startsWith('home:') }
assert script.binding.currentBuild.result != 'FAILURE'
assert swallowed.empty
// The real runNDFCVersionTests must never export the literal "null" host.
assert context.NDFC_HOST == '192.0.2.10' : context.NDFC_HOST
if (!(scenario in ['flow-aborted', 'java-interrupted'])) {
    assert caught == null
    assert calls.contains('batch:iBGP') && calls.contains('post:iBGP')
    assert calls.contains('reset') && calls.contains('finish:success')
    // The eBGP round needs confirmed migration: a successful pre-flight, or a
    // read-only audit after a failed one. Unconfirmed rounds skip modules and
    // post-restore, record NOT_RUN rows and still return home.
    def migrationChecks = calls.findAll { it.startsWith('migration-check:') }
    // A failed audit runs the standalone mover once; only its success re-audits.
    def audit = 'migration-check:/fixture/collection/integration_config.yml'
    assert migrationChecks == (scenario == 'standalone-move-recovers' ? [audit, audit] :
        (scenario in ['preflight-failed', 'migration-unconfirmed'] ? [audit] : [])) : calls
    assert calls.findAll { it.startsWith('standalone-move:') } == (scenario in ['migration-unconfirmed', 'standalone-move-recovers'] ?
        ['standalone-move:VXLAN_EVPN_Fabric->VXLAN_EVPN_Fabric_eBGP@192.0.2.10'] : []) : calls
    if (scenario in ['apply-failed', 'migration-unconfirmed']) {
        assert !calls.contains('batch:eBGP') && !calls.contains('post:eBGP') : calls
        assert calls.indexOf('record:eBGP') < calls.findIndexOf { it.startsWith('home:') }
        assert logs.any { it.startsWith('NDP_FABRIC_ROUND_MIGRATION_BLOCKED: eBGP modules not started') } : logs
        assert logs.any { it.startsWith('NDP_FABRIC_ROUND_FAILED_CONTINUING: eBGP') } : logs
        assert context.PIPELINE_FAILED == 'true'
    } else {
        assert calls.contains('batch:eBGP') && calls.contains('post:eBGP')
        assert !logs.any { it.startsWith('NDP_FABRIC_ROUND_MIGRATION_BLOCKED') } : logs
    }
    if (scenario == 'healthy') { assert context.PIPELINE_FAILED != 'true' : [calls: calls, logs: logs] }
    def warning = [
        'ibgp-test-failed': 'NDP_MODULE_BATCH_ISSUES:',
        'both-tests-failed': 'NDP_MODULE_BATCH_ISSUES:',
        'batch-setup-failed': 'NDP_FABRIC_ROUND_FAILED_CONTINUING:',
        'missing-receipt': 'NDP_FABRIC_ROUND_FAILED_CONTINUING:',
        'malformed-receipt': 'NDP_MODULE_BATCH_STATUS_INVALID:',
        'preflight-failed': 'NDP_FABRIC_ROUND_MIGRATION_CHECK fabric=VXLAN_EVPN_Fabric_eBGP exit_code=0 migrated=true',
        'migration-unconfirmed': 'NDP_FABRIC_ROUND_STANDALONE_MOVE_RESULT fabric=VXLAN_EVPN_Fabric_eBGP exit_code=1',
        'standalone-move-recovers': 'NDP_FABRIC_ROUND_STANDALONE_MOVE_RESULT fabric=VXLAN_EVPN_Fabric_eBGP exit_code=0',
        'restore-failed': 'NDP_SWITCH_RESTORE_INCOMPLETE_CONTINUING:',
        'apply-failed': 'NDP_FABRIC_ROUND_APPLY_FAILED_CONTINUING:',
        'reset-failed': 'NDP_FABRIC_RESET_FAILED_CONTINUING:',
        'post-restore-exception': 'NDP_SWITCH_POST_RESTORE_FAILED_CONTINUING:',
    ][scenario]
    if (warning) { assert logs.any { it.startsWith(warning) } : logs }
} else {
    assert caught != null
    assert !calls.contains('batch:eBGP')
    assert calls.contains('finish:interrupted')
}
''')


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("failure", [0, 1])
def test_real_completed_batch_shell_writes_status_without_raising_test_failure(tmp_path, variant, failure):
    source = (ROOT / variant).read_text()
    tail = source.split('# Module case progress/skips are rendered once', 1)[1].split("\n", 1)[1].split("'''", 1)[0]
    receipt = tmp_path / "module_batch.status"
    result = subprocess.run(["bash", "-c", "set -e\n" + tail],
                            env=dict(os.environ, RUN_FAILURE=str(failure), ND_MODULE_BATCH_STATUS=str(receipt),
                                     FABRIC_NAME="fixture", VERSION_ID="fixture"),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert receipt.read_text() == str(failure) + "\n"


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("scenario", ["target-and-source-failures", "guard-failed", "guard-timeout", "healthy"])
def test_module_loops_continue_after_test_and_prerequisite_failures(tmp_path, monkeypatch, variant, scenario):
    monkeypatch.syspath_prepend(str(ROOT / "playbooks"))
    import nd_result_summary

    source = (ROOT / variant).read_text()
    helpers = "run_reported_playbook() {" + source.split("run_reported_playbook() {", 1)[1].split(
        'PROFILE_VALIDATOR="${COLLECTIONS_DIRECTORY}', 1)[0]
    guard = "ensure_switches_ready() {" + source.split("ensure_switches_ready() {", 1)[1].split(
        "# nd_vpc_pair runs once", 1)[0]
    loops = "run_standalone_integration() {" + source.split("run_standalone_integration() {", 1)[1].split(
        "'''", 1)[0]
    collection = tmp_path / "collection"
    collection.mkdir()
    (collection / "run_integration_module.yaml").write_text("fixture")
    (collection / "nd_ensure_switches.yaml").write_text("fixture")
    (collection / "good.yaml").write_text("fixture")
    target = collection / "tests/integration/targets/nd_vpc_pair/tasks/main.yaml"
    target.parent.mkdir(parents=True)
    target.write_text("fixture")
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    script = tmp_path / "continue.sh"
    script.write_text("set -e\nRUN_FAILURE=0\nFIRST_TARGET_GUARD=true\n" +
                     helpers.replace("\\\\", "\\") + guard + r'''
begin_reported_module() { echo "begin $1" >> "$EVENTS"; }
close_reported_module() { echo "close $1 $ANSIBLE_STATUS" >> "$EVENTS"; }
git() { printf '%s\n' "$ND_GIT_REPOSITORY"; }
python() {
    if [ "$1" = "$COLLECTIONS_DIRECTORY/nd_verify_develop_sources.py" ]; then
        local target="${pb:-$m}"
        echo "source $target" >> "$EVENTS"
        case "$target" in *blocked*) return 1;; esac
        return 0
    fi
    "$PYTHON_EXE" "$@"
}
timeout() {
    case "$*" in
        *nd_ensure_switches.yaml*)
            echo "guard ${pb:-$m}" >> "$EVENTS"
            echo "fixture switch-guard status=$GUARD_EXIT_STATUS"
            return "$GUARD_EXIT_STATUS";;
        *peerlink-probe.yaml*) echo NDP_VPC_PEERLINK_PRESENT;;
        *) return 99;;
    esac
}
ansible-playbook() {
    local target= arg
    for arg in "$@"; do
        case "$arg" in
            probe_fabric=*) echo NDP_VPC_PEERLINK_PRESENT; return 0;;
            test_module=*) target="${arg#test_module=}";;
            */tests/integration/targets/*/tasks/main.yaml) target=nd_vpc_pair.good;;
            */good.yaml) target=good.yaml;;
        esac
    done
    [ -n "$target" ] || return 99
    echo "run $target" >> "$EVENTS"
    echo 'PLAY RECAP'
    if [ "$target" = nd_bad ]; then
        echo 'fixture : ok=0 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0'
        return 2
    fi
    echo 'fixture : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0'
}
''' + loops.replace(r"\$", "$"))
    events = tmp_path / "events"
    receipt = tmp_path / "module_batch.status"
    guard_status = {"guard-failed": "2", "guard-timeout": "124"}.get(scenario, "0")
    target_failures = scenario == "target-and-source-failures"
    modules = ("nd_bad nd_blocked nd_after nd_vpc_pair.blocked nd_vpc_pair.missing "
               "nd_vpc_pair.good nd_interface_port_channel_routed" if target_failures else
               "nd_first nd_after nd_vpc_pair.good nd_interface_port_channel_routed nd_local_user")
    environment = dict(os.environ,
        PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        PYTHON_EXE=sys.executable, GUARD_EXIT_STATUS=guard_status,
        ND_GIT_REPOSITORY="fixture-origin", ND_GIT_BRANCH="selected-branch", ND_GIT_COMMIT="fixture-commit",
        ND_SWITCH_PREFLIGHT_READY="true", ND_SWITCH_PREFLIGHT_CONFIRMED="true",
        SWITCH_GUARD_APPLY="true", SWITCH_GUARD_TIMEOUT="10",
        SWITCH_GUARD_PLAYBOOK=str(collection / "nd_ensure_switches.yaml"),
        SWITCH_GUARD_ROSTER=str(collection / "integration_config.yml"),
        COLLECTIONS_DIRECTORY=str(collection), ND_REPORTING_TOOLS=str(ROOT / "playbooks"),
        ND_REPORT_LOG_DIR=str(log_dir), EVENTS=str(events), ND_MODULE_BATCH_STATUS=str(receipt),
        FABRIC_NAME="fixture", VERSION_ID="ND43", TEST_RUN_MARKER="continuation-fixture",
        INVENTORY_FILE="inventory.yaml", INVENTORY_VARS_FILE=str(collection / "inventory-vars.json"),
        ND_REPORT_DEBUG_ENABLED="false", ND_REPORT_DEBUG_MODULES="",
        ND_PREREQUISITE_ENABLE_EFFECTIVE="true", ND_PREREQUISITE_APPLY_EFFECTIVE="true",
        ND_PREREQUISITE_ONLY_EFFECTIVE="false", SECONDARY_FABRIC_NAME="external",
        ORDERED_INTEGRATION_LIST=modules,
        PLAYBOOK_LIST="blocked.yaml missing.yaml good.yaml" if target_failures else "good.yaml",
        VPC_PAIR_RUNS="blocked|fixture|vxlanIbgp|A|B good|fixture|vxlanIbgp|C|D",
        VPC_PEERLINK_TIMEOUT="10")
    result = subprocess.run(["bash", str(script)], cwd=tmp_path, env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert receipt.read_text() == ("0\n" if scenario == "healthy" else "1\n")
    recorded = events.read_text().splitlines()
    # A failed source check only warns; the module still runs. Only absent targets are not run.
    expected = (["nd_bad", "nd_blocked", "nd_after", "nd_vpc_pair.blocked", "nd_vpc_pair.good",
                 "nd_interface_port_channel_routed", "good.yaml"]
                if target_failures else modules.split() + ["good.yaml"])
    fixture_runs = {"nd_vpc_pair.blocked": "nd_vpc_pair.good"}
    assert [line for line in recorded if line.startswith("run ")] == [
        "run " + fixture_runs.get(module, module) for module in expected]
    if target_failures:
        assert "NDP_SELECTED_SOURCE_VERIFY_FAILED_CONTINUING: integration module nd_blocked" in result.stderr
        assert "NDP_SELECTED_SOURCE_VERIFY_FAILED_CONTINUING: standalone module nd_vpc_pair.blocked" in result.stderr
    blocked = (("nd_vpc_pair.missing", "blocked.yaml", "missing.yaml") if target_failures else ())
    for module in blocked:
        assert recorded.count("begin " + module) == 1
        assert recorded.count("close " + module + " 125") == 1
        log = log_dir / f"test_output_fixture_ND43_{module}.txt"
        assert "NDP_MODULE_BLOCKED" in log.read_text()
        metadata = json.loads(Path(str(log) + ".execution.json").read_text())
        assert metadata["module"] == module and metadata["exit_code"] == 125
    guarded = {line.removeprefix("guard ") for line in recorded if line.startswith("guard ")}
    for module in expected:
        assert "source " + module in recorded
        exit_code = 2 if module == "nd_bad" else 0
        assert recorded.count(f"close {module} {exit_code}") == 1
        log = log_dir / f"test_output_fixture_ND43_{module}.txt"
        text = log.read_text()
        assert "NDP_MODULE_BLOCKED" not in text
        assert "[ND_MODULE_PLAYBOOK_START]" in text
        assert "Execution completed." in text
        metadata = json.loads(Path(str(log) + ".execution.json").read_text())
        assert metadata["exit_code"] == exit_code
        summary = nd_result_summary.summarize(log, module, "continuation-fixture", require_execution=True)
        assert summary["status"] == ("FAIL" if exit_code else "OK")
        assert summary["counts"]["failed"] == (1 if exit_code else 0)
        if guard_status != "0" and module in guarded:
            assert "NDP_SWITCH_GUARD_FAILED: " in text
            assert f"exit={guard_status}" in text
        else:
            assert "NDP_SWITCH_GUARD_FAILED" not in text
    if not target_failures:
        assert guarded == {"nd_after", "nd_vpc_pair.good", "nd_interface_port_channel_routed", "good.yaml"}
