"""Execute the real branch-input Groovy and selected-origin shell gates offline."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import pytest
from test_five_issue_pipeline_fixes import PRELUDE
from test_pipeline_branch_checkout import VARIANTS, git, offline_environment

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("variant", VARIANTS)
def test_selected_branch_is_not_shadowed_by_declarative_environment(variant):
    source = (ROOT / variant).read_text()
    environment = source.split("    environment {", 1)[1].split("    options {", 1)[0]
    assert not re.search(r"^\s*ND_GIT_BRANCH\s*=", environment, re.M)
    assert "env.ND_GIT_BRANCH = sourceParts[-1]" in source


@pytest.fixture(scope="module", params=VARIANTS)
def branch_script(request):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA", "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java"))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("Local Groovy runtime is required")

    def run(selection):
        body = "script.binding.setVariable('params', [ND_GIT_BRANCH: " + json.dumps(selection) + "])\n" + r'''
script.metaClass.pipeline = { Closure work -> work.call() }
for (def name : ['agent', 'parameters', 'environment', 'options', 'post']) {
    script.metaClass."${name}" = { Closure ignored -> null }
}
script.metaClass.stages = { Closure work -> work.call() }
script.metaClass.stage = { Object name, Closure work ->
    if (name == 'Clone Repository') { work.call() }
}
script.metaClass.steps = { Closure work -> work.call() }
script.metaClass.script = { Closure work -> work.call() }
def commands = []
script.metaClass.sh = { Object options ->
    commands.add(options.toString())
    return options instanceof Map && options.returnStdout ? ('1' * 40) + '\n' : 0
}
def caught = null
try { script.run() } catch (Exception e) { caught = e }
println('SELECTION_RESULT:' + script.writeReportingJson([
    error: caught?.getMessage(), branch: script.binding.env.ND_GIT_BRANCH,
    repository: script.binding.env.ND_GIT_REPOSITORY, selection: script.binding.env.ND_GIT_SELECTION,
    commit: script.binding.env.ND_GIT_COMMIT, shell_calls: commands.size()]))
'''
        with tempfile.TemporaryDirectory(prefix="nd-branch-input-") as directory:
            harness = Path(directory) / "branch.groovy"
            harness.write_text(PRELUDE + "\n" + body)
            result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain",
                                     str(harness), str(ROOT / request.param)],
                                    text=True, capture_output=True, timeout=45)
            assert result.returncode == 0, result.stdout + result.stderr
            return json.loads(next(line.split(":", 1)[1] for line in result.stdout.splitlines()
                                   if line.startswith("SELECTION_RESULT:")))
    return run


@pytest.mark.parametrize("selection, branch, owner, label", [
    (None, "develop", "CiscoDevNet", "develop"),
    ("", "develop", "CiscoDevNet", "develop"),
    ("  \t ", "develop", "CiscoDevNet", "develop"),
    ("develop", "develop", "CiscoDevNet", "develop"),
    (" feature/foo ", "feature/foo", "CiscoDevNet", "feature/foo"),
    ("fixture-owner:feature/foo", "feature/foo", "fixture-owner", "fixture-owner:feature/foo"),
])
def test_parameter_selects_actual_branch_and_expected_repository(branch_script, selection, branch, owner, label):
    actual = branch_script(selection)
    assert actual == {"error": None, "branch": branch,
                      "repository": "https://github.com/" + owner + "/ansible-nd.git",
                      "selection": label, "commit": "1" * 40, "shell_calls": 2}


@pytest.mark.parametrize("selection", ["owner:", ":branch", "owner:branch:extra", "../owner:branch",
                                       "bad_owner:branch", "-bad:branch", "owner-:branch"])
def test_bad_fork_input_stops_before_any_checkout_shell(branch_script, selection):
    actual = branch_script(selection)
    assert "valid GitHub owner" in actual["error"]
    assert actual["shell_calls"] == 0
    assert actual["commit"] == ""


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("owner", ["CiscoDevNet", "fixture-owner"])
@pytest.mark.parametrize("gate_index", [0, 1], ids=["before-preflight", "before-each-target"])
@pytest.mark.parametrize("matches", [True, False])
def test_origin_gate_warns_on_an_unselected_repository_and_continues(tmp_path, variant, owner, gate_index, matches):
    repo = tmp_path / "collection"
    repo.mkdir()
    git(repo, "init", "-q")
    expected = "https://github.com/" + owner + "/ansible-nd.git"
    actual = expected if matches else "https://github.com/unselected-owner/ansible-nd.git"
    git(repo, "remote", "add", "origin", actual)
    (repo / "nd_verify_develop_sources.py").write_text("import sys\nsys.exit(0)\n")
    python = tmp_path / "base/venv/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(sys.executable)
    lines = (ROOT / variant).read_text().splitlines()
    gates = []
    for index, line in enumerate(lines):
        if "NDP_SELECTED_SOURCE_ORIGIN_MISMATCH" not in line:
            continue
        start = next(i for i in range(index, -1, -1) if lines[i].strip().startswith("if [ \"$(git"))
        end = next(i for i in range(index, len(lines)) if lines[i].strip() == "fi")
        gates.append("\n".join(item.strip() for item in lines[start:end + 1]))
    assert len(gates) == 2
    command = "set -e\n" + gates[gate_index] + "\necho GATE_PASSED\n"
    environment = dict(offline_environment(), COLLECTIONS_DIRECTORY=str(repo), ND_GIT_REPOSITORY=expected,
                       BASE_DIRECTORY=str(tmp_path / "base"), ND_GIT_BRANCH="develop", ND_GIT_COMMIT="1" * 40)
    environment["PATH"] = str(python.parent) + os.pathsep + environment.get("PATH", os.defpath)
    result = subprocess.run(["bash", "-c", command], cwd=repo, env=environment,
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "GATE_PASSED" in result.stdout
    assert ("NDP_SELECTED_SOURCE_ORIGIN_MISMATCH_CONTINUING" in result.stdout + result.stderr) is not matches
    assert "NDP_SELECTED_SOURCE_VERIFY_FAILED_CONTINUING" not in result.stdout + result.stderr
