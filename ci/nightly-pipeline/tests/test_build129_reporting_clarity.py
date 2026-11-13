"""Separate execution failures, skipped execution and successful recovery offline."""
import hashlib
import json
from pathlib import Path
import sys

import pytest
import yaml

from test_five_issue_pipeline_fixes import groovy_runner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "playbooks"))
import nd_test_activity as activity

REASON = "Unsupported module parameter: timeout"


def test_not_run_has_no_unknown_case_warning_and_failed_setup_retains_cause(groovy_runner):
    groovy_runner(r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    'ibgp': [module:'nd_manage_community_list',nd:'4.3',round_label:'iBGP',scope:'iBGP',fabric:'fabric',
        result:'FAIL',coverage:'UNKNOWN',base:'Failed',cleanup:'Not observed',counts:[:],case_totals:[:],
        failure:'module base: SETUP: Remove test community lists; Unsupported module parameter: timeout'],
    'ebgp': [module:'nd_manage_community_list',nd:'4.3',round_label:'eBGP',scope:'eBGP',fabric:'fabric_ebgp',
        result:'NOT_RUN',coverage:'UNKNOWN',counts:[:],case_totals:[:],failure:'preflight blocked']
])
def rows = script.moduleCaseSummaryRows().readLines().collect { it.split('\\|', -1) }
def ibgp = rows.find { it[0] == 'FAIL' }
def ebgp = rows.find { it[0] == 'NOT_RUN' }
assert ibgp[4..6] == ['?', '?', '?']
assert ibgp[8].contains('Setup/Base failed; case outcomes are separate')
assert ibgp[8].contains('Unsupported module parameter: timeout')
assert ebgp[4..6] == ['-', '-', '-']
assert ebgp[8].contains('Not executed—preflight blocked')
assert ebgp[8].contains('Case coverage: N/A')
assert !ebgp[8].contains('UNKNOWN')
''')


def test_cleanup_and_authored_case_failures_are_distinct(groovy_runner):
    groovy_runner(r'''
script.MODULE_ACTIVITY_RESULTS.putAll([
    'cleanup': [module:'example',nd:'4.3',scope:'iBGP',fabric:'fabric',result:'FAIL',coverage:'COMPLETE',
        base:'Ran',cleanup:'Failed',case_totals:[passed:2,failed:0,skipped:0]],
    'case': [module:'example',nd:'4.3',scope:'eBGP',fabric:'fabric',result:'FAIL',coverage:'COMPLETE',
        base:'Ran',cleanup:'Ran',case_totals:[passed:1,failed:1,skipped:0]]
])
def rows=script.moduleCaseSummaryRows().readLines().collect { it.split('\\|', -1) }
assert rows[0][8].contains('Cleanup failed; earlier case results are retained')
assert !rows[0][8].contains('authored test case(s) failed')
assert rows[1][8].contains('1 authored test case(s) failed')
assert !rows[1][8].contains('Cleanup failed')
''')


@pytest.mark.parametrize('code,classification,explanation', [
    (2, 'ANSIBLE_FAILED', 'Ansible prerequisite task failed; this was not a timeout.'),
    (124, 'TIMEOUT', 'Guard exceeded its configured 3600s limit.'),
])
def test_membership_failure_classification_keeps_its_actual_meaning(groovy_runner, code, classification, explanation):
    groovy_runner("def code = " + str(code) + "\n" + r'''
script.binding.env.ND_SWITCH_PREFLIGHT_READY='true'
script.binding.env.CURRENT_NDFC_INVENTORY='/fixture/inventory.yaml'
script.binding.env.ND_PREREQUISITE_ONLY_EFFECTIVE='false'
script.binding.setVariable('COLLECTIONS_DIRECTORY','/fixture/collection')
script.metaClass.stage={Object name,Closure work->work.call()}
script.metaClass.withEnv={Object entries,Closure work->work.call()}
script.metaClass.sh={Object options->code}
def caught=null
try{script.runSwitchMembershipSync([version:'4.3',fabric_name:'fabric',rehome_fabrics:[]],'pre','/fixture/roster.yaml')}
catch(IllegalStateException failure){caught=failure}
assert caught != null
''' + "assert caught.message.contains(" + json.dumps(explanation) + ")\n" +
                  "assert caught.message.contains('exit_code=" + str(code) + ", classification=" + classification + ", timeout_limit_seconds=3600')\n" + r'''
assert logs.any{it.contains('NDP_SWITCH_PREDELETE_RESPONSE') && it.contains('NDP_SWITCH_PREDELETE_DEPLOY_BLOCKED')}
''')


def test_terminal_status_is_labelled_as_overall_execution_not_recovery(groovy_runner):
    groovy_runner(r'''
script.binding.env.ND_HOME_RECOVERY_STATUS='confirmed'
script.metaClass.withEnv={Object entries,Closure work->work.call()}
def commands=[]
script.metaClass.sh={Object options->commands.add(options.toString());return ''}
script.finishStructuredExecution('failed')
assert commands.size()==1 && commands[0].contains('--status "$ND_REPORT_PRODUCER_STATUS"')
assert commands[0].contains('--home-recovery-status "$ND_REPORT_HOME_RECOVERY_STATUS"')
assert logs.any{it.contains('status_scope=execution_branch execution_status=failed home_recovery_status=confirmed')}
''')


@pytest.mark.parametrize('structured', [False, True])
def test_setup_timeout_reason_survives_reduction_without_a_failed_testcase(tmp_path, structured):
    module='nd_example'
    collection=tmp_path/'collection'
    source=collection/'tests/integration/targets'/module/'tasks/main.yaml'
    source.parent.mkdir(parents=True)
    source.write_text(yaml.safe_dump([
        {'name':'SETUP: Remove test objects','cisco.nd.nd_example':{'state':'deleted'}},
        {'name':'MERGED TC1 - configure','cisco.nd.nd_example':{'state':'merged'}},
        {'name':'MERGED TC1 - verify','ansible.builtin.assert':{'that':[True]}},
    ],sort_keys=False))
    catalog=activity.load_catalog(collection,module)
    base=next(record for records in catalog['tasks'].values() for record in records if record['base'])
    message='Unsupported parameters for (cisco.nd.nd_example) module: timeout. password=PRIVATE_CANARY'
    log=tmp_path/'output.txt'
    log.write_text('\n'.join([
        '[MODULE: nd_example] Starting execution...','[RUN_MARKER: current]',
        'TASK [nd_example : SETUP: Remove test objects] ***',f'task path: {source}:{base["line"]}',
        'fatal: [fixture]: FAILED! => '+json.dumps({'msg':message}),
        'PLAY RECAP','fixture : ok=0 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0',
        '[ANSIBLE_EXIT_STATUS: 2]',
    ])+'\n')
    Path(str(log)+'.execution.json').write_text(json.dumps({'module':module,'run_id':'current','exit_code':2}))
    if structured:
        common={'schema_version':1,'module':module,'run_id':'current','invocation_id':'fixture','phase':'execution',
                'task_uuid':'base','task_instance':1,'name':base['name'],'path':str(source),'line':base['line'],
                'action':'cisco.nd.nd_example','role':module,'no_log':False}
        records=[dict(common,kind='task',seq=1),dict(common,kind='outcome',seq=2,outcome='failed',host='fixture',
                 terminal=True,item=False,ignored=False,reason_codes=[REASON])]
        journal=''.join(json.dumps(record)+'\n' for record in records).encode()
        Path(str(log)+'.events.jsonl').write_bytes(journal)
        Path(str(log)+'.event-summary.json').write_text(json.dumps({'schema_version':1,'module':module,'run_id':'current',
            'invocation_id':'fixture','completed':True,'capture_error':False,'errors':[],'event_count':2,'event_bytes':len(journal),
            'event_sha256':hashlib.sha256(journal).hexdigest(),'host_count':1,
            'counts':{'ok':0,'changed':0,'unreachable':0,'failed':1,'skipped':0,'rescued':0,'ignored':0}}))
        result=activity.summarize_events(log,module,'current','129','iBGP',collection)
    else:
        result=activity.summarize(log,module,'current','129','iBGP',collection)
    assert result['result']=='FAIL' and result['base']=='Failed'
    assert result['testcase_totals']['failed']==0 and result['testcase_totals']['started']==0
    assert REASON in '; '.join(result['failure'])
    assert 'PRIVATE_CANARY' not in json.dumps(result)
