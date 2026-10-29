"""Offline checks for pristine selected-branch execution; no ND calls."""
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = ROOT.parents[1]
SPEC = importlib.util.spec_from_file_location("develop_gate", ROOT / "playbooks/nd_verify_develop_sources.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def original_source(relative):
    return subprocess.check_output(["git", "-C", str(CHECKOUT), "show", "HEAD:" + str(relative)])


def original_yaml_sources(role):
    names = subprocess.check_output(["git", "-C", str(CHECKOUT), "ls-tree", "-r", "--name-only", "HEAD", "--", str(role)], text=True)
    return {name: original_source(name) for name in names.splitlines() if name.endswith((".yaml", ".yml"))}

@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "collection"
    path.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()
    git("init", "-q", "-b", "develop")
    git("config", "user.name", "Offline fixture")
    git("config", "user.email", "fixture@example.invalid")
    for name in ("plugins/modules/nd_example.py", "tests/integration/targets/nd_example/tasks/main.yaml"):
        file = path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("# original fixture\n")
    (path / ".gitignore").write_text("generated/\n")
    git("add", ".")
    git("commit", "-qm", "Original fixture")
    return path, git, git("rev-parse", "HEAD")

def test_original_sources_pass(repo):
    path, _, commit = repo
    assert GATE.verify(path, commit) == commit


@pytest.fixture(params=("develop", "feature/source-verification"))
def selected_branch_repo(repo, request):
    path, git, commit = repo
    branch = request.param
    if branch != "develop":
        git("checkout", "-qb", branch)
    return path, git, commit, branch


def test_selected_branch_original_sources_pass(selected_branch_repo):
    path, _, commit, branch = selected_branch_repo
    assert GATE.verify(path, commit, branch) == commit


def test_default_branch_remains_develop(repo):
    path, git, commit = repo
    git("checkout", "-qb", "feature/source-verification")
    with pytest.raises(ValueError, match="selected branch"):
        GATE.verify(path, commit)


def test_selected_branch_mismatch_fails(repo):
    path, _, commit = repo
    with pytest.raises(ValueError, match="selected branch"):
        GATE.verify(path, commit, "feature/source-verification")


def test_detached_head_fails(selected_branch_repo):
    path, git, commit, branch = selected_branch_repo
    git("checkout", "-q", "--detach", commit)
    with pytest.raises(ValueError, match="detached"):
        GATE.verify(path, commit, branch)


@pytest.mark.parametrize("branch", (None, "", " ", "feature invalid", "feature..invalid", "-invalid", "HEAD", "@{-1}"))
def test_invalid_selected_branch_fails(repo, branch):
    path, git, commit = repo
    # Give checkout shorthand a real previous branch so it would resolve.
    git("checkout", "-qb", "previous")
    git("checkout", "-q", "develop")
    with pytest.raises(ValueError, match="branch"):
        GATE.verify(path, commit, branch)


@pytest.mark.parametrize("commit", (None, "", "not-a-commit", "0" * 40))
def test_invalid_pinned_commit_fails(selected_branch_repo, commit):
    path, _, _, branch = selected_branch_repo
    with pytest.raises(ValueError, match="commit"):
        GATE.verify(path, commit, branch)


def test_cli_reports_actual_verified_branch(selected_branch_repo):
    path, _, commit, branch = selected_branch_repo
    command = [sys.executable, str(ROOT / "playbooks/nd_verify_develop_sources.py"),
               "--collection-root", str(path), "--expected-commit", commit]
    if branch != "develop":
        command += ["--expected-branch", branch]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "NDP_DEVELOP_SOURCES_VERIFIED: " + branch + " " + commit + "; no source patches\n"
    assert result.stderr == ""

@pytest.mark.parametrize("kind", ["tracked", "staged", "untracked", "branch", "commit"])
def test_source_deviations_fail(repo, kind):
    path, git, commit = repo
    if kind in ("tracked", "staged"):
        (path / "plugins/modules/nd_example.py").write_text("# modified\n")
        if kind == "staged":
            git("add", ".")
    elif kind == "untracked":
        (path / "tests/integration/targets/nd_example/tasks/extra.yaml").write_text("---\n")
    elif kind == "branch":
        git("checkout", "-qb", "other")
    else:
        commit = "0" * 40
    with pytest.raises(ValueError):
        GATE.verify(path, commit)


@pytest.mark.parametrize("kind", ("tracked", "staged", "untracked"))
def test_source_deviations_fail_on_selected_branch(selected_branch_repo, kind):
    path, git, commit, branch = selected_branch_repo
    if kind == "untracked":
        (path / "tests/integration/targets/nd_example/tasks/extra.yaml").write_text("---\n")
    else:
        (path / "plugins/modules/nd_example.py").write_text("# modified\n")
        if kind == "staged":
            git("add", ".")
    with pytest.raises(ValueError, match="tracked"):
        GATE.verify(path, commit, branch)

def test_ignored_generated_artifacts_are_allowed(repo):
    path, _, commit = repo
    directory = path / "generated"
    directory.mkdir()
    (directory / "result.txt").write_text("fixture")
    assert GATE.verify(path, commit) == commit


@pytest.fixture
def generated_output_repo(repo):
    path, git, _ = repo
    for target in ("nd_manage_switches", "nd_vpc_pair"):
        relative = Path("tests/integration/targets") / target
        for name in ("tasks/conf_prep_tasks.yaml", "files/.gitignore"):
            exists = subprocess.run(["git", "-C", str(CHECKOUT), "cat-file", "-e", "HEAD:" + str(relative / name)], capture_output=True)
            if exists.returncode == 0:
                copied = path / relative / name
                copied.parent.mkdir(parents=True, exist_ok=True)
                copied.write_bytes(original_source(relative / name))
    git("add", ".")
    git("commit", "-qm", "Original configuration preparation sources")
    return path, git, git("rev-parse", "HEAD")


def test_generated_allowlist_matches_only_original_develop_preparation_filenames():
    expected = set()
    for target in ("nd_manage_switches", "nd_vpc_pair"):
        role = Path("tests/integration/targets") / target
        for source in original_yaml_sources(role).values():
            # The original preparation tasks consume these literal file labels.
            for name in re.findall(rb"(?m)^\s+file:\s*([a-z0-9_]+)\s*$", source):
                name = name.decode("ascii")
                expected.add(str(role / "files" / (target + "_" + name + "_conf.yaml")))
    assert len(expected) == 17
    assert GATE.GENERATED_CONFIG_FILES == expected


@pytest.mark.parametrize("relative", sorted(GATE.GENERATED_CONFIG_FILES))
def test_original_generated_switch_and_vpc_payloads_are_allowed(generated_output_repo, relative):
    path, git, commit = generated_output_repo
    output = path / relative
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("[]\n")
    assert relative in git("ls-files", "--others", "--exclude-standard").splitlines()
    assert GATE.verify(path, commit) == commit


@pytest.mark.parametrize("relative", (
    "plugins/modules/nd_injected.py",
    "tests/integration/targets/nd_manage_switches/tests/extra.yaml",
    "tests/integration/targets/nd_vpc_pair/tasks/extra.yaml",
    "tests/integration/targets/nd_manage_switches/files/nd_manage_switches_unknown_conf.yaml",
    "tests/integration/targets/nd_vpc_pair/files/nd_vpc_pair_merge_full_conf.yaml.py",
))
def test_generated_allowlist_does_not_allow_injected_source(generated_output_repo, relative):
    path, _, commit = generated_output_repo
    output = path / relative
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("# injected\n")
    with pytest.raises(ValueError, match="untracked"):
        GATE.verify(path, commit)


def test_generated_payload_does_not_hide_modified_tracked_test(generated_output_repo):
    path, _, commit = generated_output_repo
    output = path / sorted(GATE.GENERATED_CONFIG_FILES)[0]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("[]\n")
    (path / "tests/integration/targets/nd_example/tasks/main.yaml").write_text("# modified authored test\n")
    with pytest.raises(ValueError, match="tracked"):
        GATE.verify(path, commit)


def test_generated_payload_symlinks_are_not_allowed(generated_output_repo, tmp_path):
    path, _, commit = generated_output_repo
    output = path / sorted(GATE.GENERATED_CONFIG_FILES)[0]
    output.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text("[]\n")
    output.symlink_to(outside)
    with pytest.raises(ValueError, match="untracked"):
        GATE.verify(path, commit)


@pytest.mark.parametrize("flag", ("--assume-unchanged", "--skip-worktree"))
def test_pinned_blob_check_rejects_changes_hidden_by_git_index_flags(selected_branch_repo, flag):
    path, git, commit, branch = selected_branch_repo
    relative = "plugins/modules/nd_example.py"
    git("update-index", flag, relative)
    (path / relative).write_text("# hidden source change\n")
    assert git("diff", "--name-only", "HEAD", "--", "plugins") == ""
    with pytest.raises(ValueError, match="tracked"):
        GATE.verify(path, commit, branch)


@pytest.mark.parametrize("relative", (
    "plugins/modules/nd_ignored.py",
    "tests/integration/targets/nd_example/tasks/ignored.yaml",
))
def test_ignored_additional_source_is_rejected(selected_branch_repo, relative):
    path, git, commit, branch = selected_branch_repo
    with (path / ".git/info/exclude").open("a") as stream:
        stream.write(relative + "\n")
    extra = path / relative
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_text("# ignored source injection\n")
    assert git("ls-files", "--others", "--exclude-standard", "--", relative) == ""
    with pytest.raises(ValueError, match="untracked"):
        GATE.verify(path, commit, branch)


def test_python_cache_requires_a_verified_tracked_source(selected_branch_repo):
    path, _, commit, branch = selected_branch_repo
    cache = path / "plugins/modules/__pycache__/nd_example.cpython-312.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"synthetic generated cache")
    assert GATE.verify(path, commit, branch) == commit
    cache.with_name("nd_injected.cpython-312.pyc").write_bytes(b"orphan cache")
    with pytest.raises(ValueError, match="untracked"):
        GATE.verify(path, commit, branch)


@pytest.mark.parametrize("target,prefix", (("nd_manage_vrfs", "nd_vrf"), ("nd_manage_networks", "nd_network")))
def test_ignored_generated_payloads_derive_only_from_verified_original_source(repo, target, prefix):
    path, git, _ = repo
    role = Path("tests/integration/targets") / target
    sources = original_yaml_sources(role)
    tokens = set()
    for relative, data in sources.items():
        copied = path / relative
        copied.parent.mkdir(parents=True, exist_ok=True)
        copied.write_bytes(data)
        tokens.update(name.decode("ascii") for name in re.findall(rb"(?m)^\s+file:\s*([a-z0-9_]+)\s*$", data))
    ignored = path / role / "files/.gitignore"
    ignored.parent.mkdir(parents=True, exist_ok=True)
    ignored.write_bytes(original_source(role / "files/.gitignore"))
    git("add", ".")
    git("commit", "-qm", "Original generated-data preparation")
    commit = git("rev-parse", "HEAD")
    assert tokens
    for token in tokens:
        (ignored.parent / (prefix + "_" + token + "_conf.yaml")).write_text("[]\n")
    assert GATE.verify(path, commit) == commit
    (ignored.parent / (prefix + "_injected_conf.yaml")).write_text("[]\n")
    with pytest.raises(ValueError, match="untracked"):
        GATE.verify(path, commit)


@pytest.mark.parametrize("name", ["Jenkinsfile_nd_jenkins_script"])
def test_pipeline_uses_selected_branch_without_test_patch_paths(name):
    source = (ROOT / name).read_text()
    assert re.search(r"string\(name:\s*'ND_GIT_BRANCH',\s*defaultValue:\s*'develop'", source)
    assert "ND_GIT_BRANCH = 'develop'" not in source
    assert 'ND_GIT_BRANCH = "${params.ND_GIT_BRANCH?.trim() ?: \'develop\'}"' in source
    for forbidden in ("prepareSwitchIntegrationBaseline", "materializeEmbeddedTests", "RUN_INTEGRATION_MODULE_YAML", "patch.git.diff"):
        assert forbidden not in source
    assert "'nd_verify_develop_sources.py'" in source
    assert "--expected-commit" in source
    assert '--expected-branch "${ND_GIT_BRANCH}"' in source

def walk(tasks):
    for task in tasks or []:
        yield task
        for field in ("block", "rescue", "always"):
            yield from walk(task.get(field))

def test_runner_does_not_rewrite_authored_tests():
    play = yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text())[0]
    tasks = list(walk(play["pre_tasks"] + play["tasks"]))
    for task in tasks:
        assert "ansible.builtin.replace" not in task
        facts = task.get("ansible.builtin.set_fact", {})
        assert not set(facts).intersection({"l3out_bgp", "l3out_bgp_updated", "l3out_svi", "l3out_static",
            "l3out_static_replaced", "subif_eth_3", "subif_eth_4", "subif_pc_5", "nd_test_manage_vpc_pairs"})
    runs = [task for task in tasks if task.get("ansible.builtin.include_role", {}).get("name") == "{{ test_module }}"
            and not task.get("ansible.builtin.include_role", {}).get("tasks_from")]
    assert runs
    assert all("nd_manage_tor" not in str(task.get("when")) and not task.get("ignore_errors") for task in runs)
    registry = yaml.safe_load((ROOT / "tests/nd_prerequisite_profiles.yaml").read_text())
    assert all("nd_test_manage_vpc_pairs" not in profile.get("runtime_vars", {}) for profile in registry["profiles"].values())
