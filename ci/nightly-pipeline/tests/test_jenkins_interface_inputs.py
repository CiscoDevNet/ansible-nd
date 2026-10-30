"""Execute the Jenkins selection shell and Ansible variable precedence offline."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("module,ip,parent,expected", [
    ("nd_interface_subinterface_managed", "", "", None),
    ("nd_interface_subinterface_managed", "", "Ethernet1/35", "192.0.2.195"),
    ("nd_interface_loopback", "192.0.2.196", "Ethernet1/35", "192.0.2.196"),
    ("nd_interface_svi", "192.0.2.85", "", "192.0.2.85"),
    ("nd_interface_vpc_access", "192.0.2.196", "Ethernet1/35", None),
    ("nd_manage_community_list", "192.0.2.196", "Ethernet1/35", None),
])
def test_actual_selection_shell_feeds_final_matching_extra_vars(tmp_path, variant, module, ip, parent, expected):
    source = (ROOT / variant).read_text()
    assert "string(name: 'ND_INTERFACE_TEST_SWITCH_IP', defaultValue: ''" in source
    assert "string(name: 'ND_SUBIF_ETHERNET_PARENT', defaultValue: ''" in source
    block = source.split("INTERFACE_SELECTION_VARS=()", 1)[1].split('ensure_switches_ready "integration module $m"', 1)[0]
    block = "INTERFACE_SELECTION_VARS=()" + block
    # The real production CLI is used. Only the surrounding module execution is
    # replaced by recording argv; neither ND nor authored tests are contacted.
    receipt = tmp_path / "args.json"
    script = tmp_path / "selection.sh"
    script.write_text("set -e\n" + block + '''
python - "$ARGV_FILE" "${INTERFACE_SELECTION_VARS[@]}" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))
PY
''')
    env = dict(os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
               m=module, ND_INTERFACE_TEST_SWITCH_IP=ip, ND_SUBIF_ETHERNET_PARENT=parent,
               COLLECTIONS_DIRECTORY=str(ROOT / "tests"), PROFILE_REGISTRY=str(ROOT / "tests/nd_prerequisite_profiles.yaml"),
               ND_REPORT_LOG_DIR=str(tmp_path / "round logs with spaces"), ARGV_FILE=str(receipt))
    Path(env["ND_REPORT_LOG_DIR"]).mkdir()
    result = subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    arguments = json.loads(receipt.read_text())
    if expected is None:
        assert arguments == []
        assert not list(tmp_path.rglob("vars_*.json"))
        return
    assert arguments[0] == "-e" and arguments[1].startswith("@") and len(arguments) == 2
    variables = json.loads(Path(arguments[1][1:]).read_text())
    selected = json.loads(Path(variables["nd_prerequisite_registry"]).read_text())
    runtime = selected["profiles"]["integration." + module]["runtime_vars"]
    assert variables["nd_test_switch_ip"] == runtime["nd_test_switch_ip"] == expected
    assert variables["nd_prerequisite_repair_baseline"] is False
    assert selected["profiles"]["integration." + module]["interface_selection_changed"] is True
    if "subinterface" in module:
        assert variables["nd_test_ethernet_parent"] == runtime["nd_test_ethernet_parent"] == parent
    # Verify the actual -e ordering lets the selected file override the legacy
    # per-module defaults. It must remain the final vars argument in Jenkins.
    invocation = next(line for line in source.splitlines() if '${INTERFACE_SELECTION_VARS[@]}' in line)
    assert invocation.index('${INTERFACE_TEST_VARS}') < invocation.index('${INTERFACE_SELECTION_VARS[@]}')
    interpreter = os.environ.get("ND_ANSIBLE_COMPAT_PYTHON", sys.executable)
    check = r'''
import json, sys
from ansible import context
from ansible.module_utils.common.collections import ImmutableDict
from ansible.parsing.dataloader import DataLoader
from ansible.utils.vars import load_extra_vars
context.CLIARGS = ImmutableDict(extra_vars=['nd_test_switch_ip=LEGACY nd_prerequisite_repair_baseline=true', '@' + sys.argv[1]])
values = load_extra_vars(DataLoader())
assert values['nd_test_switch_ip'] == sys.argv[2]
assert values['nd_prerequisite_repair_baseline'] is False
'''
    checked = subprocess.run([interpreter, "-c", check, arguments[1][1:], expected],
                             env=dict(env, ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"),
                                      ANSIBLE_LOCAL_TMP=str(tmp_path / "ansible-local")),
                             text=True, capture_output=True, timeout=20)
    assert checked.returncode == 0, checked.stdout + checked.stderr


@pytest.mark.parametrize("variant", VARIANTS)
def test_interface_selection_failure_cannot_reach_the_switch_guard(tmp_path, variant):
    source = (ROOT / variant).read_text()
    block = "INTERFACE_SELECTION_VARS=()" + source.split("INTERFACE_SELECTION_VARS=()", 1)[1].split(
        'ensure_switches_ready "integration module $m"', 1)[0]
    marker = tmp_path / "guard-reached"
    script = tmp_path / "selection.sh"
    script.write_text("set -e\n" + block + '\nprintf guard > "$MARKER"\n')
    result = subprocess.run(["bash", str(script)], env=dict(os.environ,
        PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        m="nd_interface_subinterface_managed", ND_INTERFACE_TEST_SWITCH_IP="", ND_SUBIF_ETHERNET_PARENT="Ethernet1/3",
        COLLECTIONS_DIRECTORY=str(ROOT / "tests"), PROFILE_REGISTRY=str(ROOT / "tests/nd_prerequisite_profiles.yaml"),
        ND_REPORT_LOG_DIR=str(tmp_path / "logs"), MARKER=str(marker)), text=True, capture_output=True, timeout=20)
    assert result.returncode != 0
    assert not marker.exists()


@pytest.mark.parametrize("custom,baseline,occupied", [(True, False, False), (False, True, False),
                                                       (False, False, False), (True, False, True)])
def test_selected_profile_retains_exclusive_lock_without_baseline_deletion(tmp_path, custom, baseline, occupied):
    wrapper = yaml.safe_load((ROOT / "playbooks/nd_prerequisite/nd_prerequisite_wrapper.yaml").read_text())
    lock_task = next(task for task in wrapper if task.get("name") == "Hold the exclusive baseline repair lock through the integration target")
    lock = tmp_path / "nd-prerequisite-baseline.lock"
    if occupied:
        lock.mkdir()
        (lock / "owner.json").write_text('{"run_id":"other-run"}')
    play = tmp_path / "lock.yaml"
    play.write_text(json.dumps([{
        "hosts": "all", "connection": "local", "gather_facts": False,
        "vars": {"ansible_python_interpreter": sys.executable, "nd_prerequisite_mode": "live", "nd_prerequisite_apply": True,
                 "nd_prerequisite_repair_baseline": baseline, "nd_prerequisite_repair_lock_dir": str(lock),
                 "test_module": "nd_interface_loopback", "_ndp_run_id": "fixture-run",
                 "_ndp_execution_id": "integration.nd_interface_loopback",
                 "_ndp_profile": {"switches": {"members": [{"ref": "fixture"}]}, "interface_selection_changed": custom}},
        "tasks": [lock_task], "handlers": [{"name": "Restore prerequisite interface changes", "ansible.builtin.debug": {"msg": "fixture handler"}}],
    }]))
    result = subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(play)],
                            cwd=tmp_path, env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "local"),
                                                  ANSIBLE_LOCAL_TMP=str(tmp_path / "local"),
                                                  ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"),
                                                  OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES"),
                            text=True, capture_output=True, timeout=30)
    if occupied:
        assert result.returncode != 0
        assert json.loads((lock / "owner.json").read_text())["run_id"] == "other-run"
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert lock.exists() == (custom or baseline)
        if lock.exists():
            assert json.loads((lock / "owner.json").read_text())["run_id"] == "fixture-run"
