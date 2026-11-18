"""Exercise the production final readiness facts/assertion offline; no ND calls."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = ROOT.parents[1]


def confirmation_tasks():
    play = yaml.safe_load((ROOT / "playbooks/nd_ensure_switches.yaml").read_text())[0]
    confirm = next(task for task in play["tasks"] if task.get("name", "").startswith("Confirm the full canonical roster"))
    return [copy.deepcopy(task) for task in confirm["block"] if task.get("name", "").startswith((
        "Corroborate canonical system modes", "Require every canonical switch to be in sync"))]


def test_original_develop_normalized_after_shape_supplies_the_fallback(tmp_path):
    """Use the original pinned model/output classes, without changing collection files."""
    package = tmp_path / "ansible_collections/cisco"
    package.mkdir(parents=True)
    (package / "nd").symlink_to(CHECKOUT)
    code = '''
import json
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import SwitchDataModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
switch = SwitchDataModel.model_validate({'switchId':'FIXTURE0001','fabricManagementIp':'192.0.2.10','additionalData':{'systemMode':'normal'}})
output = NDOutput(output_level='normal')
output.assign(after=NDConfigCollection(SwitchDataModel, [switch]))
print(json.dumps(output.format(gathered=[{'seed_ip':'192.0.2.10','role':'leaf'}])))
'''
    result = subprocess.run([sys.executable, "-B", "-c", code], env=dict(os.environ, PYTHONPATH=str(tmp_path)),
                            capture_output=True, text=True, check=True)
    output = json.loads(result.stdout)
    assert "system_mode" not in output["gathered"][0]
    assert output["after"][0]["switch_id"] == "FIXTURE0001"
    assert output["after"][0]["additional_data"]["system_mode"] == "normal"
    assert "additional_data.system_mode" in confirmation_tasks()[0]["vars"]["_gathered_mode"]


@pytest.mark.parametrize("raw_mode,fresh_mode,status,fresh_serial,expected", [
    ("normal", "normal", 200, "FIXTURE0001", "OK"),
    (None, "normal", 200, "FIXTURE0001", "OK"),
    (None, "Normal", 500, "FIXTURE0001", "OK"),
    ("normal", None, 200, "FIXTURE0001", "OK"),
    (None, None, 200, "FIXTURE0001", "UNVERIFIED"),
    ("unrecognized", "bad mode", 200, "FIXTURE0001", "UNVERIFIED"),
    ("normal", "unrecognized", 200, "FIXTURE0001", "UNVERIFIED"),
    ("unrecognized", "normal", 200, "FIXTURE0001", "OK"),
    ("normal", None, 500, "FIXTURE0001", "UNVERIFIED"),
    (None, "normal", 200, "DIFFERENT_SERIAL", "UNVERIFIED"),
    ("Migration", "normal", 200, "FIXTURE0001", "TIMEOUT"),
    ("normal", "maintenance", 200, "FIXTURE0001", "TIMEOUT"),
    (None, "waiting", 200, "FIXTURE0001", "TIMEOUT"),
    ("notApplicable", "normal", 200, "FIXTURE0001", "TIMEOUT"),
])
def test_readiness_requires_positive_mode_evidence_without_overriding_a_negative(
        tmp_path, raw_mode, fresh_mode, status, fresh_serial, expected):
    switch = {"seed_ip": "192.0.2.10", "serial": "FIXTURE0001"}
    fabric = {"key": "fixture-fabric", "value": [switch]}
    raw = {"switchId": switch["serial"], "additionalData": {}}
    fresh = {"switch_id": fresh_serial, "fabric_management_ip": switch["seed_ip"], "additional_data": {}}
    if raw_mode is not None:
        raw["additionalData"]["systemMode"] = raw_mode
    if fresh_mode is not None:
        fresh["additional_data"]["system_mode"] = fresh_mode
    values = {"nd_switch_wait_insync": True,
              "nd_insync_probe": {"results": [{"_fab": fabric, "status": status, "current": {"switches": [raw]}}]},
              "nd_gathered_confirm": {"results": [{"_fab": fabric, "after": [fresh],
                                                      "gathered": [{"seed_ip": switch["seed_ip"], "role": "leaf"}]}]}}
    play = tmp_path / "play.yaml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                    "vars": values, "tasks": confirmation_tasks()}], sort_keys=False))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled=False\n")
    environment = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_STDOUT_CALLBACK="default",
                       ANSIBLE_CALLBACK_PLUGINS=str(tmp_path / "callbacks"),
                       ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"), ANSIBLE_LOCAL_TMP=str(tmp_path / "local-tmp"),
                       ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote-tmp"), OBJC_DISABLE_INITIALIZE_FORK_SAFETY="YES")
    result = subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")), "-i", "localhost,", str(play)],
                            env=environment, text=True, capture_output=True, timeout=30)
    assert (result.returncode == 0) is (expected == "OK"), result.stdout + result.stderr
    assert "NDP_SWITCH_INSYNC_" + expected in result.stdout, result.stdout + result.stderr
    if expected == "UNVERIFIED":
        assert "NDP_SWITCH_INSYNC_TIMEOUT" not in result.stdout
