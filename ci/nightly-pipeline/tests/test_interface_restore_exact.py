"""Exercise production before-image restoration against a local fake ND module."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / 'playbooks/nd_prerequisite'

REST = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={'method':{'type':'str'},'path':{'type':'str'},'content':{'type':'raw'}})
p = Path(os.environ['RESTORE_LEDGER'])
s = json.loads(p.read_text()); method=m.params['method']; path=m.params['path']; body=m.params['content']
if method != 'get':
    if s.get('require_journal') and not Path(os.environ['RESTORE_JOURNAL']).exists():
        m.fail_json(msg='mutation before durable before-image')
    s['writes'].append([method,path,body]); p.write_text(json.dumps(s))
    if s['problem'] == 'refused_put' and method == 'put':
        m.fail_json(msg='injected refusal')
    if method == 'put':
        if s['problem'] == 'delayed_acceptance':
            s['pending']=body['configData']
        else:
            s['current']['configData']=body['configData']
            if s['problem'] in ('nd_trunk_defaults', 'nd_unexpected_default', 'nd_changed_existing', 'nd_unknown_field', 'nd_wrong_type'):
                policy=s['current']['configData']['networkOS']['policy']
                policy.update({'bpduFilter':'default','cdp':True,'duplexMode':'auto',
                    'errorDetectionAcl':True,'fec':'auto','linkType':'auto','monitor':False,
                    'negotiateAuto':True,'orphanPort':False,'pfc':False,'ptp':'false',
                    'qos':False,'stormControl':False,'stormControlAction':'default','vlanMapping':False})
                if s['problem'] == 'nd_unexpected_default':
                    policy['cdp']=False
                if s['problem'] == 'nd_changed_existing':
                    policy['description']='changed by controller'
                if s['problem'] == 'nd_unknown_field':
                    policy['unexpectedOption']=True
                if s['problem'] == 'nd_wrong_type':
                    policy['cdp']=1
    if method == 'post':
        if 'pending' in s:
            m.fail_json(msg='deploy before intent acceptance')
        s['current']['operData']={'mode':s['current']['configData']['mode'],
            'adminStatus':'up' if s['current']['configData']['networkOS']['policy']['adminState'] else 'down'}
        if s['problem'] == 'missing_oper':
            s['current']['operData']={}
        deployed=[row['interfaceName'] for row in (body or {}).get('interfaces',[]) if isinstance(row,dict)]
        for row in s.get('rows',[]):
            if row['interfaceName'] in deployed and row['interfaceType'] == 'ethernet':
                row['operData']['portChannelId']=-1
        if any(name.startswith('Port-channel') for name in deployed):
            s['sync']='inSync'
    p.write_text(json.dumps(s)); m.exit_json(status=200,current={})
if path.endswith('/interfaces'):
    result={'interfaces':s.get('rows',[])}
elif path.endswith('/switches'):
    result={'switches':[{'switchId':'SERIAL','additionalData':{'configSyncStatus':s.get('sync','inSync')}}]}
elif '/interface?' in path:
    result=[]
else:
    result=s['current']
    if 'pending' in s:
        result=json.loads(json.dumps(result))
        s['current']['configData']=s.pop('pending')
        s['stale_read_returned']=True
        p.write_text(json.dumps(s))
m.exit_json(status=200,current=result)
'''

PORT_CHANNEL = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m=AnsibleModule(argument_spec={'fabric_name':{'type':'str'},'config':{'type':'list'},
    'config_actions':{'type':'dict'},'state':{'type':'str'},'output_level':{'type':'str'}})
p=Path(os.environ['RESTORE_LEDGER']); s=json.loads(p.read_text())
item=m.params['config'][0]; ports=item['config_data']['network_os']['policy']['ports']
s['writes'].append(['port_channel',m.params['fabric_name'],item['interface_name'],ports])
s['current']['configData']['networkOS']['policy']['ports']=ports
p.write_text(json.dumps(s)); m.exit_json(changed=True,before=[],after=[])
'''


def execute(tmp_path, *, problem='', before_up=False, prepare=False, mode='trunk'):
    before = {'mode':mode,'networkOS':{'networkOSType':'nx-os','policy':{
        'adminState':before_up,'policyType':'routedHost' if mode=='routed' else 'trunkHost',
        'mtu':9216 if mode=='routed' else 'jumbo','speed':'auto','description':'preserve exactly'}}}
    current = copy.deepcopy(before)
    if not prepare and not problem.startswith('restore_staged_') and problem != 'restore_converged':
        current={'mode':'routed','networkOS':{'networkOSType':'nx-os','policy':{'adminState':True,'policyType':'routedHost','mtu':9216}}}
    detail={'switchId':'SERIAL','interfaceName':'Ethernet1/35','interfaceType':'ethernet',
        'configData':current,'operData':{'mode':current['mode'],'adminStatus':'up' if current['networkOS']['policy']['adminState'] else 'down'}}
    if prepare == 'free_ports':
        detail['operData']['portChannelId']=-1
        if problem == 'bundled_member':
            detail['operData']['portChannelId']=520
        elif problem == 'missing_member_oper':
            detail['operData'].pop('portChannelId')
    if problem == 'staged_pending_deploy':
        detail['operData']['adminStatus']='down'
    if problem == 'restore_staged_admin':
        detail['operData']['adminStatus']='down' if before_up else 'up'
    if problem == 'restore_staged_mode':
        detail['operData']['mode']='routed'
    if problem == 'restore_staged_unknown':
        detail['operData']={}
    if problem == 'foreign':
        detail['switchId']='FOREIGN'
    ledger=tmp_path/'ledger.json'; journal=tmp_path/'journal.yaml'
    state={'current':detail,'problem':problem,'writes':[],'require_journal':bool(prepare and not before_up)}
    if problem == 'staged_unbundle':
        # A failed authored delete: member intent free, still bundled on the switch,
        # parent left as an undeployed interface_delete, switch outOfSync.
        state.update(sync='outOfSync',rows=[
            {'interfaceName':'Ethernet1/35','interfaceType':'ethernet','configData':copy.deepcopy(current),
             'operData':{'portChannelId':520}},
            {'interfaceName':'Port-channel520','interfaceType':'portChannel',
             'configData':{'networkOS':{'policy':{'policyType':'userDefined','templateName':'interface_delete'}}}}])
    ledger.write_text(json.dumps(state))
    (tmp_path/'converge_port_channel_member_drift.yaml').write_text((TASKS/'converge_port_channel_member_drift.yaml').read_text())
    modules=tmp_path/'collections/ansible_collections/cisco/nd/plugins/modules'; modules.mkdir(parents=True)
    for name in ['nd_rest','nd_interface_subinterface_managed','nd_interface_subinterface_unmanaged','nd_manage_links']:
        (modules/(name+'.py')).write_text(REST)
    for name in ['nd_interface_port_channel_access','nd_interface_port_channel_trunk_host','nd_interface_port_channel_routed']:
        (modules/(name+'.py')).write_text(PORT_CHANNEL)
    restore=yaml.safe_load((TASKS/'restore_interface_operation.yaml').read_text())
    # Keep production conditionals/verification; shorten only polling delays.
    def speed(tasks):
        for t in tasks:
            if 'retries' in t:
                t.update(retries=1,delay=0)
            speed(t.get('block',[]))
    speed(restore)
    operation={'action':'restore_ethernet','interface':'Ethernet1/35','serial':'SERIAL',
        'fabric_name':'TEST','switch_ip':'192.0.2.1','pre_change_intent_exists':True,
        'pre_change_config_data':before}
    if problem == 'missing_snapshot':
        operation.pop('pre_change_config_data')
    variables={'ansible_python_interpreter':sys.executable,'_ndp_restore_operation':operation,'test_module':'fixture'}
    tasks=[]
    if prepare:
        variables.update(_ndp_registry={'lab':{'switches':{'leaf':{'serial':'SERIAL','seed_ip':'192.0.2.1'}},
                            'interface_allowlist':{'leaf':['Ethernet1/35']}}},
            _auif={'fabric':'TEST','serial':'SERIAL','ifname':'Ethernet1/35','label':'leaf/Ethernet1/35'},
            _ndp_restore_file=str(journal),_ndp_run_id='run',_ndp_execution_id='fixture')
        if prepare == 'free_ports':
            variables['_ndp_registry']['lab']['switches']['leaf']['baseline_fabric_ref']='advanced'
            variables['_ndp_registry']['lab']['fabrics']={'advanced':{'name':'TEST'}}
            variables['_ndp_operation']={'switch_ref':'leaf','serial':'SERIAL','interfaces':['Ethernet1/35'],
                'constraints':['exists','not_fabric_link','not_port_channel_member']}
            free_ports=yaml.safe_load((TASKS/'apply_verify_free_interfaces.yaml').read_text())
            speed(free_ports)
            tasks.extend(free_ports)
            # A target's deletion/normalization leaves an unused test port up.
            normalized=copy.deepcopy(before)
            normalized['networkOS']['policy']['adminState']=True
            tasks.append({'cisco.nd.nd_rest':{'method':'put','path':'/api/v1/manage/fabrics/TEST/switches/SERIAL/interfaces/Ethernet1%2F35',
                'content':{'configData':normalized}}})
            tasks.append({'ansible.builtin.fail':{'msg':'injected authored target failure'},'ignore_errors':True})
        else:
            admin_up=yaml.safe_load((TASKS/'admin_up_interface.yaml').read_text())
            speed(admin_up)
            tasks.extend(admin_up)
        if prepare != 'only':
            tasks.append({'ansible.builtin.set_fact':{'_ndp_restore_operation':'{{ _ndp_prerequisite_restore_operations | first }}'}})
    if prepare != 'only':
        tasks.extend(restore)
    play=tmp_path/'play.yaml'; play.write_text(yaml.safe_dump([{'hosts':'localhost','connection':'local','gather_facts':False,'vars':variables,'tasks':tasks}],sort_keys=False))
    config=tmp_path/'ansible.cfg'; config.write_text('[defaults]\n')
    env=dict(os.environ,ANSIBLE_CONFIG=str(config),ANSIBLE_COLLECTIONS_PATH=str(tmp_path/'collections'),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='False',ANSIBLE_STDOUT_CALLBACK='default',ANSIBLE_NOCOLOR='1',
        ANSIBLE_LOCAL_TEMP=str(tmp_path/'local'),ANSIBLE_REMOTE_TEMP=str(tmp_path/'remote'),
        RESTORE_LEDGER=str(ledger),RESTORE_JOURNAL=str(journal),OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES')
    done=subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')),'-i','localhost,',str(play)],
        env=env,text=True,capture_output=True,timeout=60)
    return done,json.loads(ledger.read_text()),before,journal


@pytest.mark.parametrize('before_up,mode',[(False,'trunk'),(True,'trunk'),(False,'routed')])
def test_restore_preserves_admin_state_policy_and_all_other_fields(tmp_path,before_up,mode):
    done,state,before,_=execute(tmp_path,before_up=before_up,mode=mode)
    assert done.returncode==0,done.stdout+done.stderr
    assert state['current']['configData']==before
    assert state['current']['operData']['adminStatus']==('up' if before_up else 'down')
    assert [row[0] for row in state['writes']]==['put','post']


@pytest.mark.parametrize('problem,before_up,success,writes', [
    ('restore_staged_admin', True, True, ['post']),
    ('restore_staged_admin', False, True, ['post']),
    ('restore_staged_mode', True, True, ['post']),
    ('restore_staged_unknown', True, False, []),
    ('restore_converged', True, True, []),
])
def test_restore_reconciles_staged_intent_without_rewriting_it(tmp_path,problem,before_up,success,writes):
    done,state,before,_=execute(tmp_path,problem=problem,before_up=before_up)
    assert (done.returncode==0)==success,done.stdout+done.stderr
    assert [row[0] for row in state['writes']]==writes
    assert state['current']['configData']==before
    if success:
        assert state['current']['operData']=={'mode':'trunk','adminStatus':'up' if before_up else 'down'}
    else:
        assert 'NDP_RESTORE_OBSERVED_STATE_UNVERIFIED' in done.stdout


@pytest.mark.parametrize('admin,mode,expected_reconcile,expected_deploy', [
    ('up', 'trunk', False, False),
    ('down', 'trunk', True, True),
    ('up', 'routed', True, True),
    (None, None, True, False),
])
def test_restore_staged_state_decisions(admin,mode,expected_reconcile,expected_deploy):
    from jinja2 import Environment, StrictUndefined

    environment=Environment(undefined=StrictUndefined)
    restore=yaml.safe_load((TASKS/'restore_interface_operation.yaml').read_text())
    block=next(task for task in restore if any(
        child.get('cisco.nd.nd_rest',{}).get('method')=='put' for child in task.get('block',[])))
    config={'mode':'trunk','networkOS':{'policy':{'adminState':True}}}
    values={'_ndp_restore_operation':{'action':'restore_ethernet','pre_change_config_data':config},
            '_ndp_restore_ethernet_cur':{'current':{'configData':config,'operData':{
                'adminStatus':admin,'mode':mode}}}}
    evaluate=lambda expression: environment.compile_expression(expression)(**values)
    reconcile=all(evaluate(condition) for condition in block['when'])
    assert reconcile==expected_reconcile
    if not reconcile:
        return
    observed_guard=block['block'][0]['ansible.builtin.assert']['that']
    assert (reconcile and all(evaluate(condition) for condition in observed_guard))==expected_deploy
    put=next(task for task in block['block'] if task.get('cisco.nd.nd_rest',{}).get('method')=='put')
    assert not evaluate(put['when'])


@pytest.mark.parametrize('problem',['missing_snapshot','foreign','refused_put','missing_oper'])
def test_incomplete_restore_never_claims_success_or_deploys_a_rejected_put(tmp_path,problem):
    done,state,_,_=execute(tmp_path,problem=problem)
    assert done.returncode!=0
    if problem in ['foreign','missing_snapshot']:
        assert state['writes']==[]
    if problem=='refused_put':
        assert [r[0] for r in state['writes']]==['put']


def test_selected_admin_up_is_journaled_and_restored_to_admin_down(tmp_path):
    done,state,before,journal=execute(tmp_path,prepare=True)
    assert done.returncode==0,done.stdout+done.stderr
    captured=yaml.safe_load(journal.read_text())['operations'][0]
    assert captured['pre_change_config_data']==before
    assert state['current']['configData']==before
    assert [r[0] for r in state['writes']]==['put','post','put','post']
    assert (journal.stat().st_mode & 0o777)==0o600


def test_admin_up_waits_for_exact_intent_acceptance_before_deploy(tmp_path):
    done,state,_,_=execute(tmp_path,prepare='only',problem='delayed_acceptance')
    assert done.returncode==0,done.stdout+done.stderr
    assert state['stale_read_returned'] is True
    assert [row[0] for row in state['writes']]==['put','post']
    assert state['current']['operData']['adminStatus']=='up'


def test_admin_up_rejected_put_reports_safe_reason_without_deploy(tmp_path):
    done,state,_,_=execute(tmp_path,prepare='only',problem='refused_put')
    assert done.returncode!=0
    assert [row[0] for row in state['writes']]==['put']
    assert 'NDP_ADMIN_UP_UNVERIFIED' in done.stdout
    assert 'intent_matches=False' in done.stdout
    assert 'put_http_status=0' in done.stdout
    assert 'admin_up=False' in done.stdout
    assert 'mode_matches=True' in done.stdout
    assert 'policy_type_matches=True' in done.stdout
    assert 'other_intent_matches=True' in done.stdout
    assert 'preserve exactly' not in done.stdout+done.stderr


def test_admin_up_accepts_only_observed_nd_trunk_defaults(tmp_path):
    done,state,_,_=execute(tmp_path,prepare='only',problem='nd_trunk_defaults')
    assert done.returncode==0,done.stdout+done.stderr
    assert [row[0] for row in state['writes']]==['put','post']
    assert state['current']['operData']['adminStatus']=='up'


def test_admin_up_deploys_existing_staged_intent_without_rewriting_it(tmp_path):
    done,state,before,_=execute(tmp_path,prepare='only',before_up=True,problem='staged_pending_deploy')
    assert done.returncode==0,done.stdout+done.stderr
    assert [row[0] for row in state['writes']]==['post']
    assert state['current']['configData']==before
    assert state['current']['operData']['adminStatus']=='up'


@pytest.mark.parametrize('problem',['nd_unexpected_default','nd_changed_existing','nd_unknown_field','nd_wrong_type'])
def test_admin_up_rejects_nondefault_or_changed_policy_fields(tmp_path,problem):
    done,state,_,_=execute(tmp_path,prepare='only',problem=problem)
    assert done.returncode!=0
    assert [row[0] for row in state['writes']]==['put']
    assert 'NDP_ADMIN_UP_UNVERIFIED' in done.stdout
    assert 'preserve exactly' not in done.stdout+done.stderr


def test_free_port_target_normalization_cannot_leave_a_reserved_unused_port_up(tmp_path):
    done,state,before,journal=execute(tmp_path,prepare='free_ports')
    assert done.returncode==0,done.stdout+done.stderr
    assert yaml.safe_load(journal.read_text())['operations'][0]['pre_change_config_data']==before
    assert state['current']['configData']==before
    assert state['current']['operData']['adminStatus']=='down'
    assert [r[0] for r in state['writes']]==['put','put','post']
    assert all('Ethernet1%2F35' in r[1] or r[1].endswith('/interfaceActions/deploy') for r in state['writes'])


def test_restore_deploys_a_staged_parent_delete_before_restoring_its_member(tmp_path):
    done,state,before,_=execute(tmp_path,problem='staged_unbundle')
    assert done.returncode==0,done.stdout+done.stderr
    assert state['writes'][0][1].endswith('/interfaceActions/deploy')
    assert sorted(row['interfaceName'] for row in state['writes'][0][2]['interfaces'])==['Ethernet1/35','Port-channel520']
    assert [row[0] for row in state['writes']]==['post','put','post']
    assert state['current']['configData']==before
    assert 'NDP_RESERVED_MEMBERS_UNBUNDLED' in done.stdout


@pytest.mark.parametrize('problem', ['bundled_member', 'missing_member_oper'])
def test_free_ports_require_device_membership_before_target_or_journal(tmp_path,problem):
    done,state,_,journal=execute(tmp_path,prepare='free_ports',problem=problem)
    assert done.returncode != 0,done.stdout+done.stderr
    assert state['writes']==[]
    assert not journal.exists()
    assert 'injected authored target failure' not in done.stdout


def _stale_rows():
    def member(name,pc):
        return {'interfaceName':name,'interfaceType':'ethernet',
                'configData':{'mode':'trunk','networkOS':{'policy':{'policyType':'trunkHost'}}},'operData':{'portChannelId':pc}}
    return [member('Ethernet1/18',520),member('Ethernet1/19',520),member('Ethernet1/20',-1),
            {'interfaceName':'Port-channel520','interfaceType':'portChannel',
             'configData':{'networkOS':{'policy':{'policyType':'userDefined','templateName':'interface_delete'}}}}]


CONVERGE_REST = r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
m=AnsibleModule(argument_spec={'method':{'type':'str'},'path':{'type':'str'},'content':{'type':'raw'}})
p=Path(os.environ['RESTORE_LEDGER']); s=json.loads(p.read_text()); path=m.params['path']
if m.params['method'] != 'get':
    s['writes'].append([m.params['method'],path,m.params['content']])
    names=[row['interfaceName'] for row in m.params['content']['interfaces']]
    if s['problem'] != 'stuck':
        for row in s['rows']:
            if row['interfaceName'] in names and row['interfaceType'] == 'ethernet':
                row['operData']['portChannelId']=-1
        if s['problem'] != 'unrelated_drift':
            s['sync']='inSync'
    p.write_text(json.dumps(s)); m.exit_json(status=207,current=None)
if path.endswith('/interfaces'):
    m.exit_json(status=200,current={'interfaces':s['rows']})
m.exit_json(status=200,current={'switches':[{'switchId':'SERIAL','additionalData':{'configSyncStatus':s['sync']}}]})
'''


@pytest.mark.parametrize('problem,members,strict,success,deployed,marker', [
    ('', ['Ethernet1/18','Ethernet1/19','Ethernet1/20'], True, True,
     ['Ethernet1/18','Ethernet1/19','Port-channel520'], 'NDP_RESERVED_MEMBERS_UNBUNDLED'),
    ('unrelated_drift', ['Ethernet1/18','Ethernet1/19','Ethernet1/20'], True, True,
     ['Ethernet1/18','Ethernet1/19','Port-channel520'], 'NDP_RESERVED_MEMBERS_UNBUNDLED'),
    ('stuck', ['Ethernet1/18','Ethernet1/19','Ethernet1/20'], True, False,
     ['Ethernet1/18','Ethernet1/19','Port-channel520'], 'NDP_RESERVED_MEMBERS_STILL_BUNDLED'),
    ('stuck', ['Ethernet1/18','Ethernet1/19','Ethernet1/20'], False, True,
     ['Ethernet1/18','Ethernet1/19','Port-channel520'], 'NDP_RESERVED_MEMBERS_STILL_BUNDLED'),
    ('', ['Ethernet1/18','Ethernet1/20'], True, False, None, 'NDP_RESERVED_MEMBERS_REFUSED'),
    ('live_parent', ['Ethernet1/18','Ethernet1/19','Ethernet1/20'], True, False, None, 'NDP_RESERVED_MEMBERS_REFUSED'),
    ('free', ['Ethernet1/18','Ethernet1/19','Ethernet1/20'], True, True, None, 'NDP_RESERVED_MEMBERS_FREE'),
])
def test_staged_unbundle_is_deployed_only_for_wholly_owned_members(tmp_path,problem,members,strict,success,deployed,marker):
    rows=_stale_rows()
    if problem == 'live_parent':
        rows[-1]['configData']['networkOS']['policy']={'policyType':'l3Po','ports':['Ethernet1/18','Ethernet1/19']}
    if problem == 'free':
        rows=[row for row in rows if row['interfaceType']=='ethernet']
        for row in rows:
            row['operData']['portChannelId']=-1
    ledger=tmp_path/'ledger.json'
    ledger.write_text(json.dumps({'rows':rows,'sync':'outOfSync','problem':problem,'writes':[]}))
    modules=tmp_path/'collections/ansible_collections/cisco/nd/plugins/modules'; modules.mkdir(parents=True)
    (modules/'nd_rest.py').write_text(CONVERGE_REST)
    play=tmp_path/'converge.yaml'; play.write_text(yaml.safe_dump([{'hosts':'localhost','connection':'local',
        'gather_facts':False,'vars':{'ansible_python_interpreter':sys.executable,'_ndp_cv':{'fabric':'TEST',
        'serial':'SERIAL','label':'leaf','members':members,'port_channels':[],'strict':strict,
        'retries':1,'sync_retries':1,'delay':0}},
        'tasks':[{'ansible.builtin.include_tasks':str(TASKS/'converge_port_channel_member_drift.yaml')}]}],sort_keys=False))
    config=tmp_path/'ansible.cfg'; config.write_text('[defaults]\n')
    env=dict(os.environ,ANSIBLE_CONFIG=str(config),ANSIBLE_COLLECTIONS_PATH=str(tmp_path/'collections'),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='False',ANSIBLE_STDOUT_CALLBACK='default',ANSIBLE_NOCOLOR='1',
        ANSIBLE_LOCAL_TEMP=str(tmp_path/'local'),ANSIBLE_REMOTE_TEMP=str(tmp_path/'remote'),
        RESTORE_LEDGER=str(ledger),OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES')
    done=subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')),'-i','localhost,',str(play)],
        env=env,text=True,capture_output=True,timeout=60)
    state=json.loads(ledger.read_text())
    assert (done.returncode==0) is success,done.stdout+done.stderr
    assert marker in done.stdout
    if deployed is None:
        assert state['writes']==[]
    else:
        assert len(state['writes'])==1 and state['writes'][0][1]=='/api/v1/manage/fabrics/TEST/interfaceActions/deploy'
        assert sorted(row['interfaceName'] for row in state['writes'][0][2]['interfaces'])==deployed
        assert all(row['switchId']=='SERIAL' for row in state['writes'][0][2]['interfaces'])


@pytest.mark.parametrize('problem,success', [('', True), ('pc_changed', False)])
def test_standalone_port_channel_restore_is_exact_and_refuses_drift(tmp_path,problem,success):
    modules=tmp_path/'collections/ansible_collections/cisco/nd/plugins/modules'
    modules.mkdir(parents=True)
    (modules/'nd_rest.py').write_text(REST)
    for name in ['nd_interface_subinterface_managed','nd_interface_subinterface_unmanaged','nd_manage_links',
                 'nd_interface_port_channel_access','nd_interface_port_channel_trunk_host','nd_interface_port_channel_routed']:
        (modules/(name+'.py')).write_text(PORT_CHANNEL)
    current={'switchId':'SERIAL','interfaceName':'Port-channel11','interfaceType':'portChannel',
        'configData':{'mode':'access','networkOS':{'networkOSType':'nx-os','policy':{
            'policyType':'accessPoHost','ports':['Ethernet1/30']}}},'operData':{'mode':'access','adminStatus':'up'}}
    if problem == 'pc_changed':
        current['configData']['networkOS']['policy']['ports']=['Ethernet1/30','Ethernet1/40']
    ledger=tmp_path/'ledger.json'; ledger.write_text(json.dumps({'current':current,'problem':'','writes':[]}))
    operation={'action':'restore_port_channel_members','interface':'Port-channel11','serial':'SERIAL',
        'switch_ip':'192.0.2.1','fabric_name':'TEST','module':'access','policy_type':'accessPoHost',
        'members_before':['Ethernet1/10','Ethernet1/30'],'members_after':['Ethernet1/30']}
    restore=yaml.safe_load((TASKS/'restore_interface_operation.yaml').read_text())
    restore_tasks=[task for task in restore if task.get('name','').startswith('Restore reserved members to the standalone')]
    assert len(restore_tasks)==3
    restore_args=[task[next(key for key in task if key.startswith('cisco.nd.nd_interface_port_channel_'))]
                  for task in restore_tasks]
    assert all(task['state']=='merged' for task in restore_args)
    assert all(task['config'][0]['config_data']['network_os']['policy']['ports']=='{{ _ndp_restore_operation.members_before }}'
               for task in restore_args)
    play=tmp_path/'restore-pc.yaml'; play.write_text(yaml.safe_dump([{'hosts':'localhost','connection':'local',
        'gather_facts':False,'vars':{'ansible_python_interpreter':sys.executable,
        '_ndp_restore_operation':operation},'tasks':restore}],sort_keys=False))
    config=tmp_path/'ansible.cfg'; config.write_text('[defaults]\n')
    env=dict(os.environ,ANSIBLE_CONFIG=str(config),ANSIBLE_COLLECTIONS_PATH=str(tmp_path/'collections'),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='False',ANSIBLE_STDOUT_CALLBACK='default',ANSIBLE_NOCOLOR='1',
        ANSIBLE_LOCAL_TEMP=str(tmp_path/'local'),ANSIBLE_REMOTE_TEMP=str(tmp_path/'remote'),
        RESTORE_LEDGER=str(ledger),RESTORE_JOURNAL=str(tmp_path/'journal.yaml'),OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES')
    done=subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')),'-i','localhost,',str(play)],
        env=env,text=True,capture_output=True,timeout=60)
    state=json.loads(ledger.read_text())
    assert (done.returncode == 0) is success,done.stdout+done.stderr
    if success:
        assert state['current']['configData']['networkOS']['policy']['ports']==['Ethernet1/10','Ethernet1/30']
        assert [row[0] for row in state['writes']]==['port_channel']
    else:
        assert state['writes']==[]
