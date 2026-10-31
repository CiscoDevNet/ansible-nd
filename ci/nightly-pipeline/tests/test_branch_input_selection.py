"""Execute the real branch-input Groovy and selected-origin shell gates offline."""
import json
import os
from pathlib import Path
import re
import subprocess
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
def test_origin_gate_requires_the_exact_selected_repository(tmp_path, variant, owner, gate_index, matches):
    repo = tmp_path / "collection"
    repo.mkdir()
    git(repo, "init", "-q")
    expected = "https://github.com/" + owner + "/ansible-nd.git"
    actual = expected if matches else "https://github.com/unselected-owner/ansible-nd.git"
    git(repo, "remote", "add", "origin", actual)
    gates = [line.strip() for line in (ROOT / variant).read_text().splitlines()
             if "NDP_SELECTED_SOURCE_ORIGIN_MISMATCH" in line]
    assert len(gates) == 2
    # The per-target gate returns from its shell function; retain that context.
    command = "set -e\ncheck_origin() {\n" + gates[gate_index] + "\n}\ncheck_origin\n"
    result = subprocess.run(["bash", "-c", command], cwd=repo,
                            env=dict(offline_environment(), COLLECTIONS_DIRECTORY=str(repo), ND_GIT_REPOSITORY=expected),
                            text=True, capture_output=True, timeout=10)
    assert (result.returncode == 0) is matches
    assert ("NDP_SELECTED_SOURCE_ORIGIN_MISMATCH" in result.stderr) is not matches
