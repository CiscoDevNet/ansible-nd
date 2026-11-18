"""Exercise real Ansible credential templating with a controller-free action adapter."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
INTERPRETERS = list(dict.fromkeys(filter(None, [sys.executable, os.environ.get("ND_ANSIBLE_COMPAT_PYTHON")])))


@pytest.mark.parametrize("interpreter", INTERPRETERS)
def test_lookup_credentials_reach_batch_discovery_without_literal_templates(tmp_path, interpreter):
    plugins = tmp_path / "action_plugins"
    plugins.mkdir()
    # The production action handles templating, batching and results. Only the
    # network boundary is substituted; no controller or switch is contacted.
    source = ROOT / "playbooks/action_plugins/nd_switch_discovery.py"
    (plugins / "nd_switch_discovery.py").write_text('''
import importlib.util
import os
spec = importlib.util.spec_from_file_location("production_discovery", ''' + repr(str(source)) + ''')
production = importlib.util.module_from_spec(spec)
spec.loader.exec_module(production)
class ActionModule(production.ActionModule):
    def _execute_module(self, **kwargs):
        assert self._task.no_log is True
        assert kwargs['module_name'] == 'cisco.nd.nd_rest'
        content = kwargs['module_args']['content']
        assert content['username'] == os.environ['ANSIBLE_NXOS_SWITCH_USERNAME']
        assert content['password'] == os.environ['ANSIBLE_NXOS_SWITCH_PASSWORD']
        assert content['snmpV3AuthProtocol'] == 'md5'
        assert len(content['seedIpCollection']) == 4
        return {'status': 200, 'current': {'switches': [
            {'ip': ip, 'serialNumber': 'SERIAL' + str(index), 'status': 'manageable'}
            for index, ip in enumerate(content['seedIpCollection'])]}}
''')
    expected = [{"seed_ip": f"192.0.2.{10 + index}", "serial": f"SERIAL{index}", "fabric": "fixture"}
                for index in range(4)]
    playbook = tmp_path / "binding.yaml"
    playbook.write_text(json.dumps([{
        "hosts": "all", "connection": "local", "gather_facts": False,
        "vars": {
            "nd_switch_username": "{{ lookup('env', 'ANSIBLE_NXOS_SWITCH_USERNAME') | default(switch_username | default(''), true) }}",
            "nd_switch_password": "{{ lookup('env', 'ANSIBLE_NXOS_SWITCH_PASSWORD') | default(switch_password | default(''), true) }}",
        },
        "tasks": [
            {"name": "Discover four fixtures", "nd_switch_discovery": {"seeds": expected, "protocols": ["md5", "sha"]},
             "register": "discovery"},
            {"name": "Confirm all expected identities", "ansible.builtin.assert": {"that": [
                "discovery.discovery_status == 'READY'", "discovery.discovery_batches == 1",
                "discovery.protocol_by_seed | length == 4"]}},
        ],
    }]))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    username, password = "fixture-admin", "fixture-quote'\"!$\\-password"
    env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_ACTION_PLUGINS=str(plugins),
               ANSIBLE_NXOS_SWITCH_USERNAME=username, ANSIBLE_NXOS_SWITCH_PASSWORD=password,
               ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"), ANSIBLE_LOCAL_TMP=str(tmp_path / "local"),
               ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"), ANSIBLE_STDOUT_CALLBACK="default",
               OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES", ANSIBLE_NOCOLOR="1")
    completed = subprocess.run([str(Path(interpreter).with_name("ansible-playbook")), "-i", "localhost,", str(playbook)],
                               cwd=tmp_path, env=env, text=True, capture_output=True, timeout=45)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "failed=0" in output
    assert username not in output and password not in output
