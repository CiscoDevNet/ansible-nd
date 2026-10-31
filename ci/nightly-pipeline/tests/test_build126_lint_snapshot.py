"""Run the Jenkins lint shell against a real Git fixture; no ND or network access."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from test_build124_switch_preflight import groovy_runner

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)


def git(repo, *args, env=None):
    return subprocess.run(["git", "-C", str(repo), *args], env=env,
                          text=True, capture_output=True, check=True).stdout.strip()


@pytest.fixture
def fixture(tmp_path):
    repo = tmp_path / "collection with spaces"
    repo.mkdir()
    git(repo, "init", "-b", "develop")
    git(repo, "config", "user.name", "Offline fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    (repo / ".ansible-lint").write_text("exclude_paths:\n  - tests/\n")
    (repo / ".gitattributes").write_text("authored.yaml export-ignore\n")
    (repo / ".gitignore").write_text("ignored-runtime/\n")
    (repo / "authored.yaml").write_text("pinned: true\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "pinned sources")
    commit = git(repo, "rev-parse", "HEAD")
    (repo / "authored.yaml").write_text("newer_head: true\n")
    git(repo, "commit", "-am", "later branch work")
    (repo / "authored.yaml").write_text("dirty_user_work: true\n")
    (repo / "ansible.cfg").write_text("[defaults]\nstdout_callback = contaminated\n")
    (repo / "runtime.yaml").write_text("untracked: [invalid\n")
    (repo / "ignored-runtime").mkdir()
    (repo / "ignored-runtime" / "extra.yaml").write_text("ignored: [invalid\n")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    (base / "lint_summary.txt").write_text("OLD BUILD PASSED\n")
    commands = tmp_path / "bin"
    commands.mkdir()
    spy = commands / "ansible-lint"
    spy.write_text("#!" + sys.executable + '''
import json, os
from pathlib import Path
import sys
root = Path.cwd()
Path(os.environ['LINT_SPY']).write_text(json.dumps({
    'cwd': str(root), 'args': sys.argv[1:], 'files': sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()),
    'source': (root/'authored.yaml').read_text(), 'config': (root/'.ansible-lint').read_text(),
    'ansible_config': os.environ.get('ANSIBLE_CONFIG'), 'collections_path': os.environ.get('ANSIBLE_COLLECTIONS_PATH')}))
code = int(os.environ['LINT_FIXTURE_EXIT'])
print('Full linter diagnostic retained')
if code == 2:
    print('# Rule Violation Summary\\n  1 yaml\\nFailed: 1 failure(s), 0 warning(s). Profile production was required.')
elif code == 0:
    print('Passed: 0 failure(s), 0 warning(s).')
else:
    print('ERROR: fixture linter could not initialize')
raise SystemExit(code)
''')
    spy.chmod(0o700)
    env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
               COLLECTIONS_DIRECTORY=str(repo), ND_GIT_COMMIT=commit, WORKSPACE=str(workspace),
               BASE_DIRECTORY=str(base), BUILD_NUMBER="126", LINT_SPY=str(tmp_path / "spy.json"),
               ANSIBLE_CONFIG=str(repo / "ansible.cfg"))
    return repo, workspace, base, env, tmp_path


def shell(variant):
    source = (ROOT / variant).read_text().split("def runLintCheck() {", 1)[1].split("\ndef setFailureFlag", 1)[0]
    script = source.split("sh '''", 1)[1].split("'''", 1)[0]
    # Keep the production body, substituting only external venv activation.
    return script.replace("source $HOME/ansible/venv/bin/activate", ": # fixture activation")


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("lint_exit", [0, 2, 3])
def test_lint_uses_only_exact_pinned_sources_and_keeps_diagnostics(fixture, variant, lint_exit):
    repo, workspace, base, env, directory = fixture
    before_index = hashlib.sha256((repo / ".git/index").read_bytes()).hexdigest()
    before_status = git(repo, "status", "--porcelain", "--untracked-files=all")
    script = directory / "lint.sh"
    script.write_text(shell(variant))
    result = subprocess.run(["bash", str(script)], env=dict(env, LINT_FIXTURE_EXIT=str(lint_exit)),
                            text=True, capture_output=True, timeout=20)
    assert result.returncode == (0 if lint_exit == 0 else 1), result.stdout + result.stderr
    observed = json.loads(Path(env["LINT_SPY"]).read_text())
    assert observed["source"] == "pinned: true\n"  # Also survives export-ignore.
    assert observed["config"] == "exclude_paths:\n  - tests/\n"
    assert not {"ansible.cfg", "runtime.yaml", "ignored-runtime/extra.yaml"}.intersection(observed["files"])
    assert Path(observed["cwd"]).parts[-3:] == ("ansible_collections", "cisco", "nd")
    assert observed["ansible_config"] is None
    assert observed["args"] == ["-c", observed["cwd"] + "/.ansible-lint", "--project-dir", observed["cwd"], "--profile=production"]
    assert "Full linter diagnostic retained" in (workspace / "ansible_lint_build_126.txt").read_text()
    assert "OLD BUILD" not in (base / "lint_summary.txt").read_text()
    assert not list(workspace.glob("nd_lint.*"))
    assert hashlib.sha256((repo / ".git/index").read_bytes()).hexdigest() == before_index
    assert git(repo, "status", "--porcelain", "--untracked-files=all") == before_status
    assert (repo / "authored.yaml").read_text() == "dirty_user_work: true\n"


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("commit", [None, "not-a-real-commit"])
def test_missing_pinned_commit_cannot_reuse_old_success(fixture, variant, commit):
    _, workspace, base, env, directory = fixture
    env.pop("ND_GIT_COMMIT")
    if commit is not None:
        env["ND_GIT_COMMIT"] = commit
    script = directory / "lint.sh"
    script.write_text(shell(variant))
    result = subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode != 0
    assert "Lint did not complete" in (base / "lint_summary.txt").read_text()
    assert not Path(env["LINT_SPY"]).exists()
    assert not list(workspace.glob("nd_lint.*"))


@pytest.mark.parametrize("primary, secondary, expected", [
    ("abort", "ordinary", "primary"), ("java", "ordinary", "primary"),
    ("ordinary", "abort", "secondary"), ("abort", "abort", "primary"),
])
def test_lint_archive_preserves_failure_and_interruption_priority(groovy_runner, primary, secondary, expected):
    groovy_runner("def primaryKind = '" + primary + "'\ndef secondaryKind = '" + secondary + "'\ndef expected = '" + expected + "'\n" + r'''
def aborted = loader.loadClass('org.jenkinsci.plugins.workflow.steps.FlowInterruptedException')
def failure = primaryKind == 'abort' ? aborted.newInstance('primary') :
    (primaryKind == 'java' ? new InterruptedException('primary') : new IllegalStateException('primary'))
def archiveFailure = secondaryKind == 'abort' ? aborted.newInstance('secondary') : new IllegalStateException('secondary')
script.binding.setVariable('BASE_DIRECTORY', '/fixture/base')
script.metaClass.fileExists = { Object path -> false }
script.metaClass.sh = { Object options -> throw failure }
int archives = 0
script.metaClass.archiveArtifacts = { Map options ->
    archives++
    assert options.artifacts == 'ansible_lint_build_124.txt'
    throw archiveFailure
}
def caught = null
try { script.runLintCheck() } catch (Exception e) { caught = e }
assert archives == 1
assert caught.is(expected == 'primary' ? failure : archiveFailure)
''')
