"""Exercise Jenkins profile defaults and direct-call lock compatibility offline."""
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
def test_jenkins_uses_declared_interface_profiles_without_runtime_selectors(variant):
    source = (ROOT / variant).read_text()
    for removed in ("ND_INTERFACE_TEST_SWITCH_IP", "ND_SUBIF_ETHERNET_PARENT",
                    "INTERFACE_SELECTION_VARS", "select-interface"):
        assert removed not in source
    assert '-e "nd_prerequisite_repair_baseline=true"' in source


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("fabric", ("VXLAN_EVPN_Fabric", "VXLAN_EVPN_Fabric_eBGP"))
@pytest.mark.parametrize("module", ("nd_interface_subinterface_managed", "nd_interface_subinterface_unmanaged",
                                    "nd_interface_loopback", "nd_interface_port_channel_access",
                                    "nd_manage_community_list"))
def test_actual_module_invocation_keeps_profile_defaults_despite_stale_selector_environment(
        tmp_path, variant, fabric, module):
    source = (ROOT / variant).read_text()
    defaults = 'INTERFACE_TEST_VARS=""' + source.split('INTERFACE_TEST_VARS=""', 1)[1].split(
        "# Switch prep gets a longer cap", 1)[0]
    marker = ('run_reported_playbook "$m" "${ND_REPORT_LOG_DIR}/'
              'test_output_${FABRIC_NAME}_${VERSION_ID}_${m}.txt" prerequisites ')
    invocation = marker + source.split(marker, 1)[1].split('ANSIBLE_STATUS=${PIPESTATUS[0]}', 1)[0]
    receipt = tmp_path / "arguments.json"
    script = tmp_path / "default-module.sh"
    script.write_text("set -e\n" + r'''
run_reported_playbook() {
    python - "$ARGV_FILE" "$@" <<'PYREC'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))
PYREC
}
''' + defaults + "\n" + invocation)
    environment = dict(os.environ,
        PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"], m=module,
        FABRIC_NAME=fabric, SECONDARY_FABRIC_NAME="External_Connectivity_Fabric", VERSION_ID="fixture",
        COLLECTIONS_DIRECTORY=str(ROOT / "tests"), ND_REPORT_LOG_DIR=str(tmp_path), ARGV_FILE=str(receipt),
        INVENTORY_FILE="fixture-inventory.yaml", INVENTORY_VARS_FILE="fixture-vars.json", TEST_RUN_MARKER="fixture",
        ND_PREREQUISITE_ENABLE_EFFECTIVE="true", ND_PREREQUISITE_APPLY_EFFECTIVE="true",
        ND_PREREQUISITE_ONLY_EFFECTIVE="false", MOD_TIMEOUT_CMD="", NETWORK_EXTRA_VARS="", MODULE_TOPOLOGY_VARS="",
        # Old agent environments cannot silently retarget the ordinary Jenkins path.
        ND_INTERFACE_TEST_SWITCH_IP="198.51.100.254", ND_SUBIF_ETHERNET_PARENT="Ethernet1/999")
    completed = subprocess.run(["bash", str(script)], env=environment, capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    arguments = json.loads(receipt.read_text())
    extra = {}
    for index, argument in enumerate(arguments[:-1]):
        if argument == "-e" and not arguments[index + 1].startswith("@"):
            key, value = arguments[index + 1].split("=", 1)
            extra[key] = value
    assert extra["test_module"] == module
    assert extra["fabric_name"] == fabric
    assert extra["nd_prerequisite_repair_baseline"] == "true"
    assert "nd_prerequisite_registry" not in extra
    assert "nd_interface_selection_changed" not in extra
    assert "198.51.100.254" not in arguments and "Ethernet1/999" not in arguments
    registry = yaml.safe_load((ROOT / "tests/nd_prerequisite_profiles.yaml").read_text())
    if module.startswith("nd_interface_"):
        profile = registry["profiles"]["integration." + module]
        runtime = dict(profile["runtime_vars"], nd_test_fabric_name=fabric)
        assert not profile.get("interface_selection_changed", False)
        for key in ("nd_test_fabric_name", "nd_test_switch_ip", "nd_test_port_channel_parent",
                    "nd_test_pc_member_a", "nd_test_pc_member_b", "nd_test_pc_member_c", "nd_test_pc_member_d"):
            if key in runtime:
                assert extra[key] == runtime[key]
        # Ethernet parent comes from the unchanged declared profile, with no final override file.
        assert "nd_test_ethernet_parent" not in extra
        if "subinterface" in module:
            assert runtime["nd_test_ethernet_parent"] == "Ethernet1/1"
    else:
        assert "nd_test_switch_ip" not in extra
        assert "nd_test_port_channel_parent" not in extra


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
