"""Run the actual Jenkins Bash wrapper with local command/collection fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ('Jenkinsfile_nd_jenkins_script',)
COMMUNITY = ("nd_manage_community_list", "nd_manage_extended_community_list")


@pytest.fixture(params=VARIANTS)
def runner(request, tmp_path):
    source = (ROOT / request.param).read_text()
    start = source.index("                                run_reported_playbook() {")
    end = source.index("\n                                }", start) + len("\n                                }")
    # Match Groovy's literal backslash unescaping before executing the real Bash.
    wrapper = source[start:end].replace("\\\\", "\\")
    collection = tmp_path / "collection"
    for name in ("plugins/modules/nd_example.py", "tests/integration/targets/nd_example/tasks/main.yaml"):
        path = collection / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# original authored source\n")
    original = {str(path.relative_to(collection)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in collection.rglob("*") if path.is_file()}
    frozen = tmp_path / "runtime-inputs"
    plugin = frozen / "compat_action_plugins/normal.py"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("# frozen pipeline plugin, kept outside collection\n")
    output = tmp_path / "output"
    output.mkdir()
    binary = tmp_path / "bin"
    binary.mkdir()
    command = binary / "ansible-playbook"
    command.write_text("#!" + sys.executable + "\n" + '''
import json, os, sys
with open(os.environ['CAPTURE'], 'a') as stream:
    stream.write(json.dumps({'args':sys.argv[1:], 'module':os.environ['ND_RESULT_MODULE'],
        'action_plugins':os.environ.get('ANSIBLE_ACTION_PLUGINS'),
        'phase':os.environ['ND_RESULT_PHASE'], 'log':os.environ['ND_RESULT_LOG'],
        'stdout_callback':os.environ['ANSIBLE_STDOUT_CALLBACK']}) + '\\n')
sys.exit(2 if os.environ['ND_RESULT_MODULE'] == os.environ.get('FAIL_MODULE') else 0)
''')
    command.chmod(0o755)
    capture = tmp_path / "calls.jsonl"
    script = tmp_path / "run.sh"
    script.write_text("set -e\n" + wrapper + '''
PREREQUISITE_START=$(date +%s)
for module in "$@"; do
    if run_reported_playbook "$module" "$OUTPUT/$module.txt" prerequisites \
            ansible-playbook -i fixture-inventory.yaml run_integration_module.yaml -e "test_module=$module"; then
        status=0
    else
        status=$?
    fi
    printf '%s %s\\n' "$module" "$status"
done
''')

    def run(targets, failure="", plugin_state="valid"):
        if plugin_state == "missing":
            plugin.unlink()
        elif plugin_state == "empty":
            plugin.write_bytes(b"")
        elif plugin_state == "symlink":
            actual = tmp_path / "other-plugin.py"
            actual.write_text("# not the frozen regular file\n")
            plugin.unlink()
            plugin.symlink_to(actual)
        environment = dict(os.environ, CAPTURE=str(capture), OUTPUT=str(output),
                           ND_RUNTIME_INPUTS=str(frozen), ND_REPORTING_TOOLS=str(ROOT / "playbooks"),
                           TEST_RUN_MARKER="fixture131", ND_REPORT_DEBUG_ENABLED="false",
                           ANSIBLE_ACTION_PLUGINS="/fixture/existing action plugins", FAIL_MODULE=failure,
                           PATH=str(binary) + os.pathsep + str(Path(sys.executable).parent) +
                                os.pathsep + os.environ.get("PATH", ""))
        result = subprocess.run(["/bin/bash", str(script), *targets], cwd=collection, env=environment,
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        statuses = dict(line.split() for line in result.stdout.splitlines())
        calls = [json.loads(line) for line in capture.read_text().splitlines()] if capture.exists() else []
        after = {str(path.relative_to(collection)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in collection.rglob("*") if path.is_file()}
        assert after == original
        assert not (collection / "compat_action_plugins").exists()
        return statuses, calls, output, plugin

    return run


def test_only_two_exact_targets_get_scoped_action_path_and_json_timeout(runner):
    targets = [COMMUNITY[0], "nd_manage_policy", COMMUNITY[1], "nd_manage_community_list_extra",
               "nd_manage_community_list.yaml", "nd_vpc_pair.advanced"]
    statuses, calls, output, plugin = runner(targets)
    assert statuses == dict.fromkeys(targets, "0")
    assert [call["module"] for call in calls] == targets
    for call in calls:
        target = call["module"]
        expected = ["-i", "fixture-inventory.yaml", "run_integration_module.yaml", "-e", "test_module=" + target]
        if target in COMMUNITY:
            assert call["args"][:-2] == expected and call["args"][-2] == "-e"
            assert json.loads(call["args"][-1]) == {"nd_pipeline_community_timeout_compat": True,
                                                     "ansible_command_timeout": 300}
            assert call["action_plugins"] == str(plugin.parent) + ":/fixture/existing action plugins"
        else:
            assert call["args"] == expected
            assert call["action_plugins"] == "/fixture/existing action plugins"
        assert call["phase"] == "prerequisites" and call["stdout_callback"] == "nd_report"
        receipt = json.loads((output / (target + ".txt.execution.json")).read_text())
        assert receipt["module"] == target and receipt["exit_code"] == 0 and receipt["run_id"] == "fixture131"


def test_module_failure_still_returns_and_records_original_exit_status(runner):
    target = COMMUNITY[0]
    statuses, calls, output, _ = runner([target], failure=target)
    assert statuses == {target: "2"} and len(calls) == 1
    assert json.loads((output / (target + ".txt.execution.json")).read_text())["exit_code"] == 2


@pytest.mark.parametrize("problem", ["missing", "empty", "symlink"])
def test_unsafe_plugin_blocks_community_before_execution_but_other_modules_work(runner, problem):
    statuses, calls, output, _ = runner([*COMMUNITY, "nd_manage_policy"], plugin_state=problem)
    assert statuses == {**dict.fromkeys(COMMUNITY, "125"), "nd_manage_policy": "0"}
    assert [call["module"] for call in calls] == ["nd_manage_policy"]
    assert all(not (output / (target + ".txt.execution.json")).exists() for target in COMMUNITY)
