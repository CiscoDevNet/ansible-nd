"""Missing-key and failed-read checks; no Consul or Jenkins connection is made."""
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("consul_completeness", ROOT / "consul_sync.py")
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(SYNC, "ROOT", str(tmp_path))
    script = tmp_path / "Jenkinsfile_nd_jenkins_script"
    script.parent.mkdir(exist_ok=True)
    script.write_text("""
def CONSUL_CONFIG_FILES = ['inventory.yaml', 'ansible.cfg']
def PLAYBOOK_FILES = []
def CONSUL_RUNNER_FILES = ['run_integration_module.yaml']
def CONSUL_PREREQUISITE_FILES = ['nd_prerequisite/repair.yaml']
def CONSUL_PREREQUISITE_SUPPORT_FILES = ['nd_verify_develop_sources.py']
def CONSUL_PREFLIGHT_FILES = ['nd_ensure_switches.yaml', 'action_plugins/nd_switch_discovery.py']
def SWITCH_LIFECYCLE_CONSUL_PREFIX = 'releases/fixture'
""")
    sources = SYNC.required_runtime_sources()
    for local in sources.values():
        path = Path(local)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture\n")
    monkeypatch.setattr(SYNC, "list_keys", lambda: pytest.fail("Audit relied on surviving keys"))
    monkeypatch.setattr(SYNC, "consul_put", lambda *args: pytest.fail("Audit attempted a write"))
    monkeypatch.setattr(SYNC, "consul_get", lambda key: (b"fixture\n", None))
    return sources, script


def test_audit_finds_deleted_required_key_without_listing_surviving_keys(runtime, monkeypatch, capsys):
    sources, _ = runtime
    missing = "nd_prerequisite/repair.yaml"
    monkeypatch.setattr(SYNC, "consul_get", lambda key: (None, "404") if key == missing else (b"fixture\n", None))
    assert SYNC.main(["audit"]) == 1
    output = capsys.readouterr().out
    assert missing in output and "CONSUL-MISSING" in output
    assert len(sources) == 7


def test_active_release_maps_to_canonical_files_without_mapping_historical_releases(runtime):
    sources, script = runtime
    key = "releases/fixture/nd_ensure_switches.yaml"
    assert Path(sources[key]) == script.parent / "playbooks/nd_ensure_switches.yaml"
    assert not any("playbooks/releases/" in local for local in sources.values())
    assert SYNC.main(["audit"]) == 0


def test_empty_audit_selection_cannot_report_success(runtime, monkeypatch):
    monkeypatch.setattr(SYNC, "consul_get", lambda key: pytest.fail("Empty selection made a request"))
    assert SYNC.main(["audit", "--only", "typo_missing.yaml"]) == 1


@pytest.mark.parametrize("problem,expected", [
    ("missing-local", "LOCAL-MISSING"), ("empty-local", "LOCAL-EMPTY"),
    ("empty-remote", "CONSUL-EMPTY"), ("different", "DIFF"),
])
def test_audit_reports_incomplete_sources(runtime, monkeypatch, capsys, problem, expected):
    sources, _ = runtime
    key = "inventory.yaml"
    path = Path(sources[key])
    if problem == "missing-local":
        path.unlink()
    elif problem == "empty-local":
        path.write_bytes(b"")
    else:
        value = b"" if problem == "empty-remote" else b"changed\n"
        monkeypatch.setattr(SYNC, "consul_get", lambda name: (value if name == key else b"fixture\n", None))
    assert SYNC.main(["audit"]) == 1
    assert expected in capsys.readouterr().out


@pytest.mark.parametrize("error", ["timeout", "http403", "connection refused"])
def test_failed_remote_read_is_not_deletion_and_cannot_be_pushed(runtime, monkeypatch, capsys, error):
    sources, _ = runtime
    monkeypatch.setattr(SYNC, "consul_get", lambda key: (None, error))
    rows = SYNC.gather(list(sources), sources)
    assert all(row["status"] == "CONSUL-ERROR" and row["cerr"] == error for row in rows)
    assert SYNC.do_push(rows, execute=True) == 1
    assert SYNC.main(["audit"]) == 1
    assert "CONSUL-MISSING" not in capsys.readouterr().out


def test_unreadable_baseline_blocks_other_writes_even_if_local_source_is_missing(runtime, monkeypatch):
    sources, _ = runtime
    Path(sources["inventory.yaml"]).unlink()
    monkeypatch.setattr(SYNC, "consul_get", lambda key: (None, "http403") if key == "inventory.yaml" else (b"older\n", None))
    rows = SYNC.gather(list(sources), sources)
    assert any(row["status"] == "LOCAL-MISSING" for row in rows)
    assert any(row["status"] == "DIFF" for row in rows)
    assert SYNC.do_push(rows, execute=True) == 1


@pytest.mark.parametrize("entry", ["../escape.py", "/absolute.yaml", "README.md", "patch.git.diff"])
def test_unsafe_or_document_manifest_entries_fail_closed(runtime, entry):
    _, script = runtime
    script.write_text(script.read_text().replace("'run_integration_module.yaml'", repr(entry)))
    with pytest.raises(ValueError, match="Unsupported runtime"):
        SYNC.required_runtime_sources()


def test_canonical_nightly_manifest_includes_all_existing_inputs_and_no_documents(monkeypatch):
    monkeypatch.setattr(SYNC, "ROOT", str(ROOT))
    sources = SYNC.required_runtime_sources()
    assert len(sources) == 36
    assert "ansible.cfg" in sources
    assert all(Path(local).is_file() and Path(local).stat().st_size for local in sources.values())
    assert not any(key.endswith((".md", ".doc", ".diff")) for key in sources)
    assert sum(key.startswith("releases/") for key in sources) == 2
