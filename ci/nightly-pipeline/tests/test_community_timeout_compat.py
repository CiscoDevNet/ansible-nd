"""Execute the pipeline action hook with fake FQCN modules, without ND access."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "playbooks/compat_action_plugins/normal.py"
MODULE = """from ansible.module_utils.basic import AnsibleModule
def main():
    module = AnsibleModule(argument_spec=dict(fabric_name=dict(type='str'),
        config=dict(type='raw'), state=dict(type='str')))
    module.exit_json(changed=False, observed=module.params)
if __name__ == '__main__':
    main()
"""


@pytest.mark.parametrize("scenario,expected_pass", [
    ("caller_default_cannot_override_authored_default", False),
    ("community", True), ("extended", True), ("hidden", True),
    ("explicit_timeout", False), ("explicit_args_timeout", False),
    ("other_module", False), ("other_default", False),
    ("not_enabled", False), ("wrong_transport_timeout", False),
    ("unknown_argument", False), ("already_valid_call", True),
])
def test_only_known_inherited_default_is_adapted_without_source_edits(tmp_path, scenario, expected_pass):
    target = ("nd_manage_extended_community_list" if scenario == "extended" else
              "nd_manage_policy" if scenario == "other_module" else "nd_manage_community_list")
    action = "cisco.nd." + target
    collection = tmp_path / "collections/ansible_collections/cisco/nd"
    module = collection / ("plugins/modules/" + target + ".py")
    module.parent.mkdir(parents=True)
    module.write_text(MODULE)
    tasks = tmp_path / "roles/authored/tasks/main.yaml"
    tasks.parent.mkdir(parents=True)
    config = [{"name": "fixture-object"}]
    if scenario == "hidden":
        config[0]["private_value"] = "PRIVATE_COMPAT_CANARY"
    arguments = {"fabric_name": "fixture-fabric", "state": "merged", "config": config}
    setup = {"name": "SETUP: authored module invocation", action: dict(arguments), "register": "observed"}
    if scenario == "explicit_timeout":
        setup[action]["timeout"] = 300
    if scenario == "explicit_args_timeout":
        setup["args"] = {"timeout": 300}
    if scenario == "unknown_argument":
        setup[action]["unsupported_other_option"] = "fixture"
    assertion = {"name": "MERGED: authored functional assertions", "ansible.builtin.assert": {
        "that": ["observed.observed.fabric_name == 'fixture-fabric'", "observed.observed.state == 'merged'",
                 "observed.observed.config == expected_config", "ansible_command_timeout | int == 300"],
        "quiet": True}}
    cleanup = {"name": "CLEANUP: authored module invocation", action: dict(arguments, state="deleted")}
    if scenario == "hidden":
        setup["no_log"] = cleanup["no_log"] = True
    block = {"name": "Authored role", "block": [setup, assertion], "always": [cleanup]}
    if scenario != "already_valid_call":
        block["module_defaults"] = {action: {"timeout": 600 if scenario == "other_default" else 300}}
    tasks.write_text(yaml.safe_dump([block], sort_keys=False))
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
        "module_defaults": {action: {"timeout": "{{ omit }}"}},
        "tasks": [{"name": "Run original authored role", "ansible.builtin.include_role": {"name": "authored"},
            "vars": {"expected_config": config, "ansible_command_timeout": 600 if scenario == "wrong_transport_timeout" else 300,
                     "nd_pipeline_community_timeout_compat": scenario != "not_enabled"}}]}], sort_keys=False))
    config_file = tmp_path / "ansible.cfg"
    config_file.write_text("[defaults]\nstdout_callback=default\nretry_files_enabled=False\n")
    actions = tmp_path / "pipeline-actions"
    actions.mkdir()
    (actions / "normal.py").write_bytes(PLUGIN.read_bytes())
    protected = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (module, tasks)}
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config_file), ANSIBLE_COLLECTIONS_PATH=str(tmp_path / "collections"),
                       ANSIBLE_ROLES_PATH=str(tmp_path / "roles"), ANSIBLE_LOCAL_TEMP=str(tmp_path / "temp"),
                       PYTHONPYCACHEPREFIX=str(tmp_path / "pycache"), ANSIBLE_NOCOLOR="1")
    if scenario != "caller_default_cannot_override_authored_default":
        environment["ANSIBLE_ACTION_PLUGINS"] = str(actions)
    else:
        environment.pop("ANSIBLE_ACTION_PLUGINS", None)
    result = subprocess.run([sys.executable, "-m", "ansible.cli.playbook", "-i", "localhost,", str(play),
                             "-e", "ansible_python_interpreter=" + sys.executable, "-v"],
                            cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=60)
    output = result.stdout + result.stderr
    assert (result.returncode == 0) is expected_pass, output
    assert {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in protected} == protected
    if expected_pass:
        assert "All assertions passed" in output
        assert "CLEANUP: authored module invocation" in output
    else:
        assert "Unsupported parameters" in output
        assert ("unsupported_other_option" if scenario == "unknown_argument" else "timeout") in output
    if scenario in {"community", "extended", "hidden", "unknown_argument"}:
        assert "NDP_COMMUNITY_TIMEOUT_COMPAT" in output
    if scenario in {"other_module", "other_default", "not_enabled", "wrong_transport_timeout", "already_valid_call"}:
        assert "NDP_COMMUNITY_TIMEOUT_COMPAT" not in output
    if scenario == "hidden":
        assert "PRIVATE_COMPAT_CANARY" not in output
