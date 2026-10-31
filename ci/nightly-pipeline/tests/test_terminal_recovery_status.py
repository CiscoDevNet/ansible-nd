"""Terminal execution status and verified home recovery remain independent."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_five_issue_pipeline_fixes import groovy_runner

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "playbooks/nd_reporting_pipeline.py"


def queue(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    root = workspace / "reports"

    def cli(command, *arguments):
        result = subprocess.run([sys.executable, str(HELPER), command, "--root", str(root), *map(str, arguments)],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        return json.loads(result.stdout)

    cli("init", "--workspace", workspace, "--build", "129", "--run-id", "fixture129")
    return workspace, root, cli


@pytest.mark.parametrize("execution,recovery,expected", [
    ("failed", "confirmed", "confirmed"),
    ("failed", "failed", "failed"),
    ("interrupted", "unverified", "unverified"),
    ("success", "not_required", "not_required"),
    ("success", "failed", "failed"),
    ("success", None, "unverified"),
])
def test_terminal_json_keeps_legacy_status_and_first_verified_receipt(tmp_path, execution, recovery, expected):
    _, root, cli = queue(tmp_path)
    arguments = [] if recovery is None else ["--home-recovery-status", recovery]
    receipt = cli("finish", "--status", execution, *arguments)
    assert receipt["status"] == receipt["execution_status"] == execution
    assert receipt["status_scope"] == "execution_branch"
    assert receipt["home_recovery_status"] == expected
    assert "restoration_scope" not in receipt
    assert receipt == cli("finish", "--status", "success", "--home-recovery-status", "not_required")
    assert json.loads((root / "producer.json").read_text()) == receipt


@pytest.mark.parametrize("recovery,failed", [("failed", True), (None, False)])
def test_aggregate_fails_known_home_failure_without_reclassifying_unknown(tmp_path, recovery, failed):
    _, _, cli = queue(tmp_path)
    arguments = [] if recovery is None else ["--home-recovery-status", recovery]
    cli("finish", "--status", "success", *arguments)
    report = cli("aggregate")
    assert report["failed"] is failed
    assert report["producer_status"] == report["execution_status"] == "success"
    assert report["status_scope"] == "execution_branch"
    assert report["home_recovery_status"] == (recovery or "unverified")


def test_legacy_success_is_not_inferred_as_confirmed_home_or_rewritten(tmp_path):
    _, root, cli = queue(tmp_path)
    legacy = {"schema_version": 1, "run_id": "fixture129", "status": "success", "finished_at": 100,
              "restoration_scope": "execution branch has finished its recovery attempts"}
    (root / "producer.json").write_text(json.dumps(legacy))
    assert cli("finish", "--status", "failed", "--home-recovery-status", "confirmed") == legacy
    report = cli("aggregate")
    assert report["home_recovery_status"] == "unverified" and report["failed"] is False
    assert report["execution_status"] == "success"


@pytest.mark.parametrize("scenario,expected", [
    ("success", "confirmed"), ("ordinary-failure", "failed"), ("flow-interrupt", "unverified"),
    ("java-interrupt", "unverified"), ("missing-inputs", "failed"), ("no-home", "not_required"),
    ("noop-confirmed", "confirmed"), ("noop-failed", "failed"),
])
def test_home_status_follows_actual_guard_result_and_preserves_interruptions(groovy_runner, scenario, expected):
    groovy_runner("def scenario=" + json.dumps(scenario) + "\n" + r'''
boolean noHome=scenario.startsWith('noop') || scenario=='no-home'
script.binding.env.HOME_RESTORE_REQUIRED=noHome?'false':'true'
script.binding.env.ND_HOME_RECOVERY_STATUS=scenario=='no-home'?'not_required':scenario=='noop-failed'?'failed':'confirmed'
script.binding.env.REQUIRED_FILES_READY=scenario=='missing-inputs'?'false':'true'
script.binding.setVariable('COLLECTIONS_DIRECTORY','/fixture/collection')
def calls=[]
script.metaClass.resetFabricBetweenVersions={Object tag->calls.add('reset')}
script.metaClass.generateDynamicInventory={Object config->calls.add('inventory')}
script.metaClass.usernamePassword={Map options->options}
script.metaClass.withCredentials={List bindings,Closure work->work.call()}
def failure=scenario=='flow-interrupt'?
    loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException').newInstance('injected home abort'):
    scenario=='java-interrupt'?new InterruptedException('injected home abort'):new IllegalStateException('injected home failure')
script.metaClass.runSwitchMembershipSync={Object config,Object phase,Object roster->
    calls.add('guard')
    assert phase=='home' && script.binding.env.ND_HOME_RECOVERY_STATUS=='unverified'
    if(scenario in ['ordinary-failure','flow-interrupt','java-interrupt']){throw failure}
}
def home=[version:'4.3',versionId:'ND43',fabric_name:'home-fabric']
def caught=null
try{script.restoreHomeFabric([home],home)}catch(Exception actual){caught=actual}
''' + "assert script.binding.env.ND_HOME_RECOVERY_STATUS==" + json.dumps(expected) + "\n" + r'''
if(noHome){assert calls.isEmpty() && caught==null}
else if(scenario=='success'){
    assert caught==null && calls==['reset','inventory','guard']
    assert script.binding.env.HOME_RESTORE_REQUIRED=='false'
}else{
    assert caught != null
    if(scenario!='missing-inputs'){assert caught.is(failure)}
    assert script.binding.env.HOME_RESTORE_REQUIRED=='true'
}
''')


def test_actual_finish_shell_passes_bounded_confirmed_home_with_failed_execution(tmp_path, groovy_runner):
    workspace, root, _ = queue(tmp_path)
    fake_home = workspace / "home"
    python = fake_home / "ansible/venv/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(sys.executable)
    groovy_runner("def queue=" + json.dumps(str(root)) + "\n" +
                  "def home=" + json.dumps(str(fake_home)) + "\n" +
                  "def tools=" + json.dumps(str(ROOT / "playbooks")) + "\n" + r'''
script.binding.env.putAll([ND_HOME_RECOVERY_STATUS:'confirmed',ND_REPORTING_ROOT:queue,ND_REPORTING_TOOLS:tools,HOME:home])
script.metaClass.withEnv={List entries,Closure work->
    def prior=[:];entries.each{value->def pair=value.split('=',2);prior[pair[0]]=script.binding.env[pair[0]];script.binding.env[pair[0]]=pair[1]}
    try{return work.call()}finally{prior.each{key,value->if(value==null)script.binding.env.remove(key);else script.binding.env[key]=value}}
}
script.metaClass.sh={String body->
    def builder=new ProcessBuilder('bash','-c',body)
    script.binding.env.each{key,value->if(value!=null)builder.environment()[key.toString()]=value.toString()}
    builder.redirectErrorStream(true)
    def process=builder.start();def output=process.inputStream.getText('UTF-8');assert process.waitFor()==0:output
    return output
}
script.finishStructuredExecution('failed')
def receipt=script.parseReportingJson(new File(queue,'producer.json').getText('UTF-8'))
assert receipt.status=='failed' && receipt.execution_status=='failed' && receipt.home_recovery_status=='confirmed'
assert receipt.status_scope=='execution_branch' && !receipt.containsKey('restoration_scope')
''')


@pytest.mark.parametrize("reason,expected", [("Switch pre-flight failed", "preflight blocked"),
                                            ("previous round stopped", "earlier execution stopped")])
def test_not_run_description_uses_the_actual_blocking_reason(groovy_runner, reason, expected):
    groovy_runner("def reason=" + json.dumps(reason) + "\n" + r'''
script.MODULE_ACTIVITY_RESULTS.put('unstarted',[module:'example',result:'NOT_RUN',coverage:'UNKNOWN',
    scope:'eBGP',fabric:'fabric',nd:'4.3',failure:reason])
def note=script.moduleCaseSummaryRows()
''' + "assert note.contains('Not executed—" + expected + "')\n" +
                  ("assert !note.contains('preflight blocked')\n" if "preflight" not in expected else "") + r'''
assert !note.contains('UNKNOWN')
''')
