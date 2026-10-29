"""Run the real checkout shell against disposable local Git repositories only."""

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)
CANONICAL_REPO = 'REPO_URL="https://github.com/CiscoDevNet/ansible-nd.git"'


def git(path, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(path), *arguments], text=True, stderr=subprocess.PIPE,
        env=offline_environment(),
    ).strip()


def offline_environment():
    return dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                GIT_TERMINAL_PROMPT="0", GIT_ALLOW_PROTOCOL="file")


def checkout_shell(variant, remote):
    source = (ROOT / variant).read_text()
    stage = source.split("stage('Clone Repository')", 1)[1]
    shell = stage.split("sh '''", 1)[1].split("'''", 1)[0]
    # Groovy triple-single-quoted strings decode escaped backslashes. Shell
    # continuations are otherwise left as written; bash accepts either form.
    shell = shell.replace("\\\\", "\\")
    assert shell.count(CANONICAL_REPO) == 1
    # This is the sole test substitution in the production checkout shell.
    return shell.replace(CANONICAL_REPO, 'REPO_URL="' + remote.as_uri() + '"')


@pytest.fixture(params=VARIANTS)
def checkout(tmp_path, request):
    seed = tmp_path / "seed"
    seed.mkdir()
    git(seed, "init", "-q", "-b", "develop")
    git(seed, "config", "user.name", "Offline checkout fixture")
    git(seed, "config", "user.email", "fixture@example.invalid")
    (seed / "payload.txt").write_text("develop fixture\n")
    git(seed, "add", "payload.txt")
    git(seed, "commit", "-qm", "Develop fixture")
    git(seed, "checkout", "-qb", "feature/foo")
    (seed / "payload.txt").write_text("feature fixture\n")
    git(seed, "commit", "-qam", "Feature fixture")
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "--bare", "-q", str(remote))
    git(seed, "remote", "add", "origin", remote.as_uri())
    git(seed, "push", "-q", "origin", "develop", "feature/foo")
    git(remote, "symbolic-ref", "HEAD", "refs/heads/develop")
    collections = tmp_path / "collections"
    collections.mkdir()
    base = tmp_path / "base"
    activate = base / "venv/bin/activate"
    activate.parent.mkdir(parents=True)
    activate.write_text(": # offline fixture virtual environment\n")
    return {
        "variant": request.param, "seed": seed, "remote": remote,
        "collections": collections, "target": collections / "nd", "base": base,
        "shell": checkout_shell(request.param, remote),
    }


def run_checkout(checkout, branch="feature/foo", **extra_environment):
    environment = dict(offline_environment(), COLL_DIR=str(checkout["collections"]),
                       BASE_DIRECTORY=str(checkout["base"]), ND_GIT_BRANCH=branch,
                       BUILD_NUMBER="offline", **extra_environment)
    return subprocess.run(
        ["/bin/bash", "-c", checkout["shell"]], cwd=checkout["collections"],
        env=environment, text=True, capture_output=True, timeout=30,
    )


def require_success(result):
    assert result.returncode == 0, result.stdout + result.stderr


def backups(checkout):
    return list((checkout["collections"] / ".nd-backups").glob("nd-*"))


def assert_clean_checkout(checkout, branch, commit):
    target = checkout["target"]
    assert git(target, "symbolic-ref", "--short", "HEAD") == branch
    assert git(target, "rev-parse", "HEAD") == commit
    assert git(target, "rev-parse", "HEAD^{tree}") == git(checkout["remote"], "rev-parse", commit + "^{tree}")
    assert git(target, "status", "--porcelain") == ""
    assert not list(checkout["collections"].glob(".nd-staging-*"))


def advance_remote(checkout):
    seed = checkout["seed"]
    with (seed / "payload.txt").open("a") as stream:
        stream.write("remote advancement\n")
    git(seed, "commit", "-qam", "Advance remote fixture")
    git(seed, "push", "-q", "origin", "feature/foo")
    return git(seed, "rev-parse", "HEAD")


def test_feature_branch_checks_out_requested_remote_commit(checkout):
    require_success(run_checkout(checkout))
    assert_clean_checkout(checkout, "feature/foo", git(checkout["seed"], "rev-parse", "feature/foo"))
    assert (checkout["target"] / "payload.txt").read_text() == "feature fixture\n"
    assert not backups(checkout)


def test_develop_parameter_default_is_a_valid_checkout(checkout):
    source = (ROOT / checkout["variant"]).read_text()
    assert re.search(r"string\(name: 'ND_GIT_BRANCH', defaultValue: 'develop'", source)
    # Assert the production environment maps omitted or whitespace-only input
    # to develop, then exercise that resulting context in the actual shell.
    assert 'ND_GIT_BRANCH = "${params.ND_GIT_BRANCH?.trim() ?: \'develop\'}"' in source
    require_success(run_checkout(checkout, "develop"))
    assert_clean_checkout(checkout, "develop", git(checkout["seed"], "rev-parse", "develop"))
    assert (checkout["target"] / "payload.txt").read_text() == "develop fixture\n"


def test_matching_commit_tree_branch_and_clean_tracked_state_reuses_checkout(checkout):
    require_success(run_checkout(checkout))
    target = checkout["target"]
    inode = target.stat().st_ino
    marker = target / "runtime-marker.txt"
    marker.write_text("existing runtime artifact\n")
    result = run_checkout(checkout)
    require_success(result)
    assert "reusing checkout" in result.stdout
    assert target.stat().st_ino == inode
    assert marker.read_text() == "existing runtime artifact\n"
    assert git(target, "status", "--porcelain", "--untracked-files=no") == ""
    assert not backups(checkout)


def test_remote_advance_stages_replacement_and_retains_one_private_backup(checkout):
    require_success(run_checkout(checkout))
    target = checkout["target"]
    old_commit = git(target, "rev-parse", "HEAD")
    old_inode = target.stat().st_ino
    (target / "inventory_fixture.yaml").write_text("fixture generated inventory\n")
    (target / "test_output_fixture.log").write_text("fixture generated output\n")
    previous_backup = checkout["collections"] / ".nd-backups/nd-19000101-old"
    previous_backup.mkdir(parents=True)
    (previous_backup / "old.txt").write_text("old backup\n")
    new_commit = advance_remote(checkout)
    result = run_checkout(checkout)
    require_success(result)
    assert "Staged clone verified" in result.stdout
    assert target.stat().st_ino != old_inode
    assert_clean_checkout(checkout, "feature/foo", new_commit)
    retained = backups(checkout)
    assert len(retained) == 1
    assert git(retained[0], "rev-parse", "HEAD") == old_commit
    assert stat.S_IMODE(retained[0].stat().st_mode) == 0o700
    assert stat.S_IMODE(retained[0].parent.stat().st_mode) == 0o700
    assert not (retained[0] / "inventory_fixture.yaml").exists()
    assert not (retained[0] / "test_output_fixture.log").exists()
    assert not previous_backup.exists()


def test_dirty_tracked_source_is_replaced_from_verified_remote(checkout):
    require_success(run_checkout(checkout))
    target = checkout["target"]
    commit = git(target, "rev-parse", "HEAD")
    old_inode = target.stat().st_ino
    (target / "payload.txt").write_text("local tracked edit\n")
    result = run_checkout(checkout)
    require_success(result)
    assert "Tracked working-tree changes require a clean replacement" in result.stdout
    assert target.stat().st_ino != old_inode
    assert_clean_checkout(checkout, "feature/foo", commit)
    assert len(backups(checkout)) == 1
    assert (backups(checkout)[0] / "payload.txt").read_text() == "local tracked edit\n"


@pytest.mark.parametrize("branch, error", (("missing/branch", "Unable to resolve remote branch"),
                                          ("invalid..branch", "Invalid Git branch name")))
def test_missing_or_invalid_branch_preserves_existing_checkout(checkout, branch, error):
    require_success(run_checkout(checkout))
    target = checkout["target"]
    old_inode = target.stat().st_ino
    commit = git(target, "rev-parse", "HEAD")
    (target / "payload.txt").write_text("existing local edit\n")
    result = run_checkout(checkout, branch)
    assert result.returncode != 0
    assert error in result.stderr
    assert target.stat().st_ino == old_inode
    assert git(target, "rev-parse", "HEAD") == commit
    assert (target / "payload.txt").read_text() == "existing local edit\n"
    assert not backups(checkout)
    assert not list(checkout["collections"].glob(".nd-staging-*"))


def test_remote_head_race_is_rejected_before_replacing_existing_checkout(checkout, tmp_path):
    require_success(run_checkout(checkout))
    target = checkout["target"]
    old_inode = target.stat().st_ino
    old_commit = git(target, "rev-parse", "HEAD")
    (checkout["seed"] / "payload.txt").write_text("racing remote advancement\n")
    git(checkout["seed"], "commit", "-qam", "Unpublished racing fixture")
    racing_commit = git(checkout["seed"], "rev-parse", "HEAD")
    # Transfer the new object without moving feature/foo, so the wrapper only
    # has to advance one local bare-repository ref after ls-remote has printed.
    git(checkout["seed"], "push", "-q", "origin", "HEAD:refs/heads/race-object")
    binary = tmp_path / "bin"
    binary.mkdir()
    wrapper = binary / "git"
    wrapper.write_text('''#!/bin/bash
set -euo pipefail
"$REAL_GIT" "$@"
if [ "${1:-}" = ls-remote ]; then
    "$REAL_GIT" --git-dir "$RACE_REMOTE" update-ref refs/heads/feature/foo "$RACE_COMMIT"
    : > "$RACE_TRIGGERED"
fi
''')
    wrapper.chmod(0o755)
    triggered = tmp_path / "race-triggered"
    result = run_checkout(
        checkout, PATH=str(binary) + os.pathsep + os.environ["PATH"],
        REAL_GIT=shutil.which("git"), RACE_REMOTE=str(checkout["remote"]),
        RACE_COMMIT=racing_commit, RACE_TRIGGERED=str(triggered),
    )
    assert triggered.is_file()
    assert result.returncode != 0
    assert "Remote branch changed during validation" in result.stderr
    assert target.stat().st_ino == old_inode
    assert_clean_checkout(checkout, "feature/foo", old_commit)
    assert not backups(checkout)
