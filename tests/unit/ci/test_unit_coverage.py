# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Coverage batching keeps every test and branch while bounding raw-file storage."""

import importlib.util
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / ".github/scripts/run_unit_coverage.py"
SPEC = importlib.util.spec_from_file_location("unit_coverage_ci_helper", SCRIPT)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def write_coverage(path, files, *, context="", has_arcs="1"):
    """Create the native schema-7 fields consumed by the helper, without dependencies."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as database:
        with database:
            database.executescript(
                "CREATE TABLE coverage_schema (version INTEGER); INSERT INTO coverage_schema VALUES (7);"
                "CREATE TABLE meta (key TEXT, value TEXT);"
                "CREATE TABLE context (id INTEGER PRIMARY KEY, context TEXT);"
                "CREATE TABLE file (id INTEGER PRIMARY KEY, path TEXT UNIQUE);"
                "CREATE TABLE arc (file_id INTEGER, context_id INTEGER, fromno INTEGER, tono INTEGER);"
            )
            database.execute("INSERT INTO meta VALUES ('has_arcs', ?)", (has_arcs,))
            database.execute("INSERT INTO context VALUES (1, ?)", (context,))
            for index, (name, arcs) in enumerate(files.items(), 1):
                database.execute("INSERT INTO file VALUES (?, ?)", (index, name))
                database.executemany("INSERT INTO arc VALUES (?, 1, ?, ?)", [(index, *arc) for arc in arcs])


def raw(root, suffix="one"):
    return root / "tests/output/coverage" / ("units=controller=docker=python-3.13=coverage." + suffix)


def normalize(filename):
    return filename.removeprefix("/remote/")


def export_runner(files, *, code=0, missing=False):
    def run(command, **_kwargs):
        assert command[1:3] == ["coverage", "combine"]
        assert "--requirements" in command
        if not missing:
            destination = Path(command[command.index("--export") + 1]) / "various=various=various=python-3.13=coverage.combined"
            write_coverage(destination, files)
        return code

    return run


def test_partition_covers_every_selected_target_exactly_once():
    targets = [f"tests/unit/test_{index}.py" for index in range(43)]
    batches = helper.partition_targets(targets, 20)
    assert [len(batch) for batch in batches] == [20, 20, 3]
    assert [target for batch in batches for target in batch] == targets


@pytest.mark.parametrize("targets,size", [([], 20), (["one", "one"], 20), (["one"], 0)])
def test_partition_rejects_empty_duplicate_or_invalid_target_contracts(targets, size):
    with pytest.raises(helper.CoverageBatchError):
        helper.partition_targets(targets, size)


def test_verified_compaction_keeps_all_branch_arcs_and_zero_arc_files(tmp_path):
    first, second = raw(tmp_path), raw(tmp_path, "two")
    write_coverage(first, {"/remote/plugins/module.py": {(-1, 1), (1, 2)}, "/remote/plugins/empty.py": set()})
    write_coverage(second, {"/remote/plugins/module.py": {(2, -1)}})
    helper.compact_coverage(tmp_path, runner=export_runner({"plugins/module.py": {(-1, 1), (1, 2), (2, -1)}}), normalize=normalize)
    paths = helper.coverage_inputs(first.parent)
    assert len(paths) == 1 and paths[0].name.endswith("=coverage.combined")
    assert not first.exists() and not second.exists()
    assert helper.read_branch_data(paths, normalize) == {"python-3.13": {"plugins/module.py": {(-1, 1), (1, 2), (2, -1)}, "plugins/empty.py": set()}}


@pytest.mark.parametrize("has_arcs", ["1", "0"])
def test_coverage_read_closes_database_even_when_validation_fails(tmp_path, monkeypatch, has_arcs):
    source = raw(tmp_path)
    write_coverage(source, {"module.py": {(1, 2)}}, has_arcs=has_arcs)
    connect = sqlite3.connect
    connections = []

    def recording_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(helper.sqlite3, "connect", recording_connect)
    if has_arcs == "1":
        helper.read_branch_data([source], normalize)
    else:
        with pytest.raises(helper.CoverageBatchError):
            helper.read_branch_data([source], normalize)
    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_path_mapping_is_cached_per_read_without_losing_arcs_or_ignored_names(tmp_path):
    paths = [raw(tmp_path), raw(tmp_path, "two")]
    for index, path in enumerate(paths, 1):
        write_coverage(path, {"/remote/module.py": {(index, index + 1)}, "/remote/__init__.py": set()})
    calls = []

    def mapping(name):
        calls.append(name)
        return None if name.endswith("__init__.py") else normalize(name)

    expected = {"python-3.13": {"module.py": {(1, 2), (2, 3)}}}
    assert helper.read_branch_data(paths, mapping) == expected
    assert sorted(calls) == ["/remote/__init__.py", "/remote/module.py"]
    assert helper.read_branch_data(paths, mapping) == expected
    assert len(calls) == 4  # A fresh read performs fresh source-path validation.


@pytest.mark.parametrize("failure", ["command", "missing", "lost_arc", "corrupt"])
def test_failed_export_never_deletes_any_input(tmp_path, failure):
    source = raw(tmp_path)
    write_coverage(source, {"plugins/module.py": {(1, 2), (2, -1)}})
    original = source.read_bytes()
    runner = export_runner({"plugins/module.py": {(1, 2)}}, code=1 if failure == "command" else 0, missing=failure == "missing")
    if failure == "corrupt":

        def runner(command, **_kwargs):
            destination = Path(command[command.index("--export") + 1]) / "various=various=various=python-3.13=coverage.combined"
            destination.write_bytes(b"not coverage")
            return 0

    with pytest.raises(helper.CoverageBatchError):
        helper.compact_coverage(tmp_path, runner=runner, normalize=normalize)
    assert source.read_bytes() == original


def test_failed_atomic_publication_keeps_inputs_and_the_previous_aggregate(tmp_path):
    source = raw(tmp_path)
    aggregate = source.parent / "various=various=various=python-3.13=coverage.combined"
    write_coverage(source, {"module.py": {(2, -1)}})
    write_coverage(aggregate, {"module.py": {(-1, 2)}})
    original = {path: path.read_bytes() for path in (source, aggregate)}

    def failed_publish(*_args):
        raise OSError("simulated interrupted rename")

    with pytest.raises(OSError, match="interrupted rename"):
        helper.compact_coverage(tmp_path, runner=export_runner({"module.py": {(-1, 2), (2, -1)}}), normalize=normalize, publish=failed_publish)
    assert all(path.read_bytes() == data for path, data in original.items())


def test_next_compaction_includes_the_previous_aggregate_and_never_unlinks_its_replacement(tmp_path):
    source = raw(tmp_path)
    write_coverage(source, {"module.py": {(1, 2)}})
    helper.compact_coverage(tmp_path, runner=export_runner({"module.py": {(1, 2)}}), normalize=normalize)
    write_coverage(raw(tmp_path, "next"), {"module.py": {(2, -1)}})
    helper.compact_coverage(tmp_path, runner=export_runner({"module.py": {(1, 2), (2, -1)}}), normalize=normalize)
    paths = helper.coverage_inputs(source.parent)
    assert len(paths) == 1
    assert helper.read_branch_data(paths, normalize)["python-3.13"]["module.py"] == {(1, 2), (2, -1)}


@pytest.mark.parametrize("context,has_arcs", [("named-test-context", "1"), ("", "0")])
def test_unsupported_context_or_line_data_is_not_silently_discarded(tmp_path, context, has_arcs):
    source = raw(tmp_path)
    write_coverage(source, {"module.py": {(1, 2)}}, context=context, has_arcs=has_arcs)
    with pytest.raises(helper.CoverageBatchError):
        helper.compact_coverage(tmp_path, runner=lambda *_args, **_kwargs: pytest.fail("must reject before export"), normalize=normalize)
    assert source.exists()


def test_corrupt_input_is_rejected_before_ansible_test_can_skip_it(tmp_path):
    source = raw(tmp_path)
    source.parent.mkdir(parents=True)
    source.write_bytes(b"not a SQLite coverage file")
    with pytest.raises(helper.CoverageBatchError, match="Unreadable coverage data"):
        helper.compact_coverage(tmp_path, runner=lambda *_args, **_kwargs: pytest.fail("must not export corrupt input"), normalize=normalize)
    assert source.read_bytes() == b"not a SQLite coverage file"


def test_all_batches_run_after_a_failed_test_batch_and_keep_unique_junit(tmp_path):
    targets = [f"tests/unit/test_{index}.py" for index in range(3)]
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        report = tmp_path / "tests/output/junit/python3.13-controller-units.xml"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(f'<testsuite tests="1" failures="{int(len(calls) == 1)}"/>')
        return 1 if len(calls) == 1 else 0

    code = helper.run_batches(tmp_path, "3.13", batch_size=1, runner=runner, discover=lambda _root: targets, compact=lambda *_args, **_kwargs: {})
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert code == 1 and len(calls) == 3
    assert manifest["complete"] is True and manifest["failed_batches"] == [1]
    assert manifest["invalid_junit_batches"] == []
    assert [batch["junit_summary"]["failures"] for batch in manifest["batches"]] == [1, 0, 0]
    assert [target for batch in manifest["batches"] for target in batch["targets"]] == targets
    assert len({batch["junit"][0] for batch in manifest["batches"]}) == 3
    assert all("--docker" in command and "--coverage" in command for command in calls)


def test_compaction_failure_stops_before_more_batches_and_keeps_manifest(tmp_path):
    calls = []

    def compact(*_args, **_kwargs):
        raise helper.CoverageBatchError("export verification failed")

    with pytest.raises(helper.CoverageBatchError, match="export verification failed"):
        helper.run_batches(
            tmp_path,
            "3.13",
            batch_size=1,
            runner=lambda command, **_kwargs: calls.append(command) or 0,
            discover=lambda _root: ["one", "two"],
            compact=compact,
        )
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert len(calls) == 1 and manifest["complete"] is False
    assert "export verification failed" in manifest["batches"][0]["compaction_error"]


def test_local_subset_and_worker_settings_do_not_change_case_selection(tmp_path):
    target = "tests/unit/test_selected.py"
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        path = tmp_path / "tests/output/junit/unit.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('<testsuite tests="1"/>')
        return 0

    result = helper.run_batches(
        tmp_path,
        "3.11",
        targets=[target],
        local=True,
        num_workers=1,
        ansible_test="/tools/ansible-test",
        runner=runner,
        discover=lambda _root: [target, "another"],
        compact=lambda *_args, **_kwargs: {},
    )
    assert result == 0 and len(calls) == 1
    assert calls[0][0] == "/tools/ansible-test" and "--local" in calls[0] and "--docker" not in calls[0]
    assert calls[0][-1] == target
    assert calls[0][calls[0].index("--num-workers") + 1] == "1"


def test_successful_command_without_junit_is_not_reported_as_complete_coverage(tmp_path):
    code = helper.run_batches(
        tmp_path,
        "3.13",
        runner=lambda *_args, **_kwargs: 0,
        discover=lambda _root: ["tests/unit/test_one.py"],
        compact=lambda *_args, **_kwargs: {},
    )
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert code == 1
    assert manifest["missing_junit_batches"] == [1]


def test_identical_reports_and_timestamps_are_preserved_for_every_batch(tmp_path):
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        path = tmp_path / "tests/output/junit/units.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('<testsuite tests="1"/>')
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        return 0

    code = helper.run_batches(
        tmp_path,
        "3.13",
        batch_size=1,
        runner=runner,
        discover=lambda _root: ["one", "two", "three"],
        compact=lambda *_args, **_kwargs: {},
    )
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert code == 0 and len(calls) == 3
    assert manifest["missing_junit_batches"] == manifest["invalid_junit_batches"] == []
    reports = [tmp_path / batch["junit"][0] for batch in manifest["batches"]]
    assert len(set(reports)) == 3
    assert all(path.read_text() == '<testsuite tests="1"/>' for path in reports)
    assert all(path.stat().st_mtime_ns == 1_000_000_000 for path in reports)


def test_initial_junit_is_preserved_and_excluded_from_the_new_batch(tmp_path):
    report = tmp_path / "tests/output/junit/units.xml"
    report.parent.mkdir(parents=True)
    initial = '<testsuite tests="1" failures="1"/>'
    report.write_text(initial)

    def runner(_command, **_kwargs):
        assert not report.exists()
        report.write_text('<testsuite tests="1"/>')
        return 0

    code = helper.run_batches(
        tmp_path,
        "3.13",
        runner=runner,
        discover=lambda _root: ["one"],
        compact=lambda *_args, **_kwargs: {},
    )
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert code == 0
    assert manifest["previous_junit"] == ["tests/output/coverage-batches/previous-junit/units.xml"]
    assert (tmp_path / manifest["previous_junit"][0]).read_text() == initial
    assert (tmp_path / manifest["batches"][0]["junit"][0]).read_text() == '<testsuite tests="1"/>'
    assert not report.exists()


def test_junit_archive_refuses_to_overwrite_existing_evidence(tmp_path):
    report = tmp_path / "tests/output/junit/units.xml"
    report.parent.mkdir(parents=True)
    report.write_text("new evidence")
    destination = tmp_path / "existing-archive"
    destination.mkdir()
    archived = destination / report.name
    archived.write_text("previous evidence")
    with pytest.raises(helper.CoverageBatchError, match="will not be overwritten"):
        helper.archive_junit(tmp_path, destination)
    assert report.read_text() == "new evidence" and archived.read_text() == "previous evidence"


@pytest.mark.parametrize(
    "reports,expected",
    [
        (["<testsuite tests='2'/>"], {"tests": 2, "failures": 0, "errors": 0, "skipped": 0}),
        (
            ["<testsuites tests='3'><testsuite tests='1'/><testsuite tests='2' skipped='1'><testcase><skipped/></testcase></testsuite></testsuites>"],
            {"tests": 3, "failures": 0, "errors": 0, "skipped": 1},
        ),
        (
            ["<testsuite tests='1' skipped='1'><testcase><skipped/></testcase></testsuite>"],
            {"tests": 1, "failures": 0, "errors": 0, "skipped": 1},
        ),
        (
            ["<testsuite tests='3'><testsuite tests='1'/><testsuite tests='2'/></testsuite>"],
            {"tests": 3, "failures": 0, "errors": 0, "skipped": 0},
        ),
        (["<testsuite tests='1'/>", "<testsuite tests='2'/>"], {"tests": 3, "failures": 0, "errors": 0, "skipped": 0}),
    ],
    ids=["standalone", "wrapper-multiple-suites", "all-skipped", "nested-suite-totals", "multiple-reports"],
)
def test_junit_summary_accepts_pytest_reports_and_counts_each_suite_once(tmp_path, reports, expected):
    paths = []
    for index, text in enumerate(reports):
        path = tmp_path / f"report-{index}.xml"
        path.write_text(text)
        paths.append(path.name)
    assert helper.summarize_junit(tmp_path, paths) == expected


def test_empty_context_report_cannot_hide_behind_another_contexts_nonempty_report(tmp_path):
    paths = ["empty.xml", "nonempty.xml"]
    (tmp_path / paths[0]).write_text("<testsuites><testsuite tests='0'/></testsuites>")
    (tmp_path / paths[1]).write_text("<testsuites><testsuite tests='3'/></testsuites>")
    with pytest.raises(helper.CoverageBatchError, match="no executed or skipped test cases"):
        helper.summarize_junit(tmp_path, paths)


@pytest.mark.parametrize(
    "bad_report",
    [
        "<testsuite",
        "<testsuite tests='0'/>",
        "<testsuites/>",
        "<testsuite/>",
        "<testsuite tests='one'/>",
        "<testsuite tests='-1'/>",
        "<unexpected tests='1'/>",
        "<testsuite tests='1' failures='1'/>",
        "<testsuite tests='1' errors='1'/>",
        "<testsuite tests='1'><testcase><failure>failure despite successful exit</failure></testcase></testsuite>",
        "<testsuite tests='1'><testcase><error>error despite successful exit</error></testcase></testsuite>",
    ],
    ids=[
        "malformed",
        "zero-tests",
        "no-suites",
        "missing-count",
        "noninteger-count",
        "negative-count",
        "unexpected-root",
        "failure",
        "error",
        "failure-element",
        "error-element",
    ],
)
def test_invalid_success_report_fails_run_but_archives_it_and_runs_later_batches(tmp_path, bad_report):
    targets = ["tests/unit/test_first.py", "tests/unit/test_later.py"]
    reports = [bad_report, "<testsuites><testsuite tests='1'/></testsuites>"]
    calls = []
    compactions = []

    def runner(command, **_kwargs):
        report = tmp_path / "tests/output/junit/units.xml"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(reports[len(calls)])
        calls.append(command)
        return 0

    code = helper.run_batches(
        tmp_path,
        "3.13",
        batch_size=1,
        runner=runner,
        discover=lambda _root: targets,
        compact=lambda *_args, **_kwargs: compactions.append(True) or {},
    )
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert code == 1 and len(calls) == len(compactions) == 2
    assert manifest["complete"] is True and manifest["failed_batches"] == []
    assert manifest["missing_junit_batches"] == [] and manifest["invalid_junit_batches"] == [1]
    assert manifest["batches"][0]["junit_error"]
    assert "junit_error" not in manifest["batches"][1]
    assert manifest["batches"][1]["junit_summary"]["tests"] == 1
    assert [(tmp_path / batch["junit"][0]).read_text() for batch in manifest["batches"]] == reports


def successful_native_runner(root, calls, *, first_exit=0, first_report=None, keep_raw=False):
    """Record real command boundaries without running Docker or a controller."""

    def runner(command, **kwargs):
        assert kwargs == {"cwd": root.resolve(), "check": False}
        calls.append(command)
        report = root / "tests/output/junit/units.xml"
        report.parent.mkdir(parents=True, exist_ok=True)
        text = first_report if len(calls) == 1 and first_report is not None else '<testsuite tests="1"/>'
        if text != "missing":
            report.write_text(text)
        if keep_raw:
            source = raw(root, str(len(calls)))
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"retained raw " + str(len(calls)).encode())
            if len(calls) == 1:
                (source.parent / "various=various=various=python-3.13=coverage.combined").write_bytes(b"retained previous aggregate")
        return first_exit if len(calls) == 1 else 0

    return runner


@pytest.mark.parametrize(
    "exception", [ImportError, AttributeError, RuntimeError, None], ids=["import-error", "attribute-error", "unexpected-error", "empty-discovery"]
)
@pytest.mark.parametrize("selection", [None, ["tests/unit/test_selected.py"]], ids=["full-scope", "explicit-selection"])
@pytest.mark.parametrize("local", [False, True], ids=["docker", "local"])
def test_discovery_failure_uses_one_native_command_with_the_original_scope_and_options(tmp_path, exception, selection, local):
    calls = []

    def unavailable(_root):
        if exception is None:
            return []
        raise exception("native discovery API changed")

    code = helper.run_batches(
        tmp_path,
        "3.13",
        targets=selection,
        local=local,
        num_workers=2,
        ansible_test="/tools/ansible-test",
        runner=successful_native_runner(tmp_path, calls),
        discover=unavailable,
        compact=lambda *_args, **_kwargs: pytest.fail("native fallback must not invoke compaction"),
    )
    assert code == 0 and len(calls) == 1
    command = calls[0]
    assert command[:3] == ["/tools/ansible-test", "units", "--local" if local else "--docker"]
    assert command[command.index("--python") + 1] == "3.13"
    assert command[command.index("--num-workers") + 1] == "2"
    assert "--coverage" in command
    assert command[command.index("--num-workers") + 2 :] == (selection or [])
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert manifest["complete"] is True and manifest["mode"] == "native" and manifest["discovery"] == "native"
    assert manifest["fallbacks"][0]["stage"] == "discovery"
    assert manifest["fallbacks"][0]["mode"] == "native-full"


@pytest.mark.parametrize("exception", [ImportError, AttributeError, RuntimeError])
def test_discovery_failure_with_fallback_disabled_never_starts_native_tests(tmp_path, exception):
    calls = []

    def unavailable(_root):
        raise exception("discovery unavailable")

    with pytest.raises(helper.CoverageCompatibilityError, match="discovery unavailable"):
        helper.run_batches(tmp_path, "3.13", fallback=False, discover=unavailable, runner=lambda *args, **kwargs: calls.append((args, kwargs)))
    assert calls == []


@pytest.mark.parametrize("dirty", ["coverage", "batch-archive", "unknown-coverage-name", "coverage-symlink", "archive-symlink"])
def test_dirty_output_is_rejected_before_discovery_or_any_fallback(tmp_path, dirty):
    if dirty == "coverage":
        retained = raw(tmp_path)
        retained.parent.mkdir(parents=True)
        retained.write_bytes(b"previous coverage evidence")
    elif dirty == "batch-archive":
        retained = tmp_path / "tests/output/coverage-batches/manifest.json"
        retained.parent.mkdir(parents=True)
        retained.write_bytes(b"previous batch evidence")
    elif dirty == "unknown-coverage-name":
        retained = tmp_path / "tests/output/coverage/new-native-format.sqlite"
        retained.parent.mkdir(parents=True)
        retained.write_bytes(b"unrecognized previous evidence")
    else:
        preserved = tmp_path / "preserved-results"
        preserved.mkdir()
        (preserved / "evidence.txt").write_bytes(b"symlink destination evidence")
        linked = tmp_path / "tests/output" / ("coverage" if dirty == "coverage-symlink" else "coverage-batches")
        linked.parent.mkdir(parents=True)
        linked.symlink_to(preserved, target_is_directory=True)
        retained = linked / "evidence.txt"
    original = retained.read_bytes()
    with pytest.raises(helper.CoverageBatchError, match="clean coverage outputs"):
        helper.run_batches(
            tmp_path,
            "3.13",
            discover=lambda *_args: pytest.fail("dirty-output check must run before private discovery"),
            runner=lambda *_args, **_kwargs: pytest.fail("must never fallback over existing results"),
        )
    assert retained.read_bytes() == original


@pytest.mark.parametrize("settings", [{"batch_size": 0}, {"targets": ["one", "one"]}])
def test_invalid_batch_arguments_are_rejected_before_private_discovery(tmp_path, settings):
    with pytest.raises(helper.CoverageBatchError):
        helper.run_batches(
            tmp_path,
            "3.13",
            **settings,
            discover=lambda *_args: pytest.fail("invalid arguments must be checked before private discovery"),
            runner=lambda *_args, **_kwargs: pytest.fail("invalid arguments cannot authorize fallback"),
        )


def test_unknown_explicit_selector_is_fatal_after_successful_discovery(tmp_path):
    with pytest.raises(helper.CoverageBatchError, match="discoverable"):
        helper.run_batches(
            tmp_path,
            "3.13",
            targets=["unknown"],
            discover=lambda _root: ["known"],
            runner=lambda *_args, **_kwargs: pytest.fail("invalid selection cannot authorize native fallback"),
        )


@pytest.mark.parametrize("failure_batch", [1, 2, 3], ids=["first", "middle", "final"])
@pytest.mark.parametrize("exception_name", ["CoverageCompatibilityError", "RuntimeError"])
def test_compaction_fallback_runs_only_remaining_batches_once_and_retains_inputs(tmp_path, failure_batch, exception_name):
    targets = [f"tests/unit/test_{index}.py" for index in range(3)]
    calls, compactions = [], []

    def compact(root, **_kwargs):
        compactions.append(True)
        # Native completion must already be durable before helper postprocessing.
        current = json.loads((root / "tests/output/coverage-batches/manifest.json").read_text())
        assert current["batches"][-1]["exit_code"] == 0
        assert current["batches"][-1]["targets"] == [targets[len(calls) - 1]]
        if len(compactions) == failure_batch:
            exception = RuntimeError if exception_name == "RuntimeError" else helper.CoverageCompatibilityError
            raise exception("compactor no longer supports this coverage format")
        return {}

    code = helper.run_batches(
        tmp_path,
        "3.13",
        batch_size=1,
        local=True,
        num_workers=1,
        runner=successful_native_runner(tmp_path, calls, keep_raw=True),
        discover=lambda _root: targets,
        compact=compact,
    )
    assert code == 0 and len(calls) == 3 and len(compactions) == failure_batch
    assert [command[-1] for command in calls] == targets
    assert all("--local" in command and "--coverage" in command and command[command.index("--num-workers") + 1] == "1" for command in calls)
    assert all(raw(tmp_path, str(index)).read_bytes() == b"retained raw " + str(index).encode() for index in (1, 2, 3))
    aggregate = raw(tmp_path).parent / "various=various=various=python-3.13=coverage.combined"
    assert aggregate.read_bytes() == b"retained previous aggregate"
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert manifest["complete"] is True and manifest["mode"] == "native"
    assert len(manifest["fallbacks"]) == 1
    assert manifest["fallbacks"][0]["stage"] == "compaction" and manifest["fallbacks"][0]["mode"] == "native-remaining"
    assert manifest["fallbacks"][0]["after_batch"] == failure_batch


@pytest.mark.parametrize("exception_name", ["CoverageCompatibilityError", "RuntimeError"])
def test_strict_compaction_failure_never_runs_later_batches(tmp_path, exception_name):
    calls = []

    def compact(*_args, **_kwargs):
        exception = RuntimeError if exception_name == "RuntimeError" else helper.CoverageCompatibilityError
        raise exception("unsupported compaction")

    with pytest.raises(helper.CoverageBatchError, match="unsupported compaction"):
        helper.run_batches(
            tmp_path,
            "3.13",
            fallback=False,
            batch_size=1,
            runner=successful_native_runner(tmp_path, calls),
            discover=lambda _root: ["one", "two"],
            compact=compact,
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "first_exit,first_report",
    [
        (1, '<testsuite tests="1" failures="1"/>'),
        (0, '<testsuite tests="1" failures="1"/>'),
        (0, '<testsuite tests="1" errors="1"/>'),
        (0, "<testsuite"),
        (0, "missing"),
    ],
    ids=["native-exit-failure", "junit-failure", "junit-error", "malformed-junit", "missing-junit"],
)
def test_later_compaction_fallback_cannot_erase_an_earlier_test_or_report_failure(tmp_path, first_exit, first_report):
    calls, compactions = [], []

    def compact(*_args, **_kwargs):
        compactions.append(True)
        if len(compactions) == 2:
            raise helper.CoverageCompatibilityError("later unsupported format")
        return {}

    code = helper.run_batches(
        tmp_path,
        "3.13",
        batch_size=1,
        runner=successful_native_runner(tmp_path, calls, first_exit=first_exit, first_report=first_report),
        discover=lambda _root: ["one", "two", "three"],
        compact=compact,
    )
    assert code == 1 and len(calls) == 3 and len(compactions) == 2
    assert [command[-1] for command in calls] == ["one", "two", "three"]


def test_integrity_failure_stops_without_fallback_even_when_enabled(tmp_path):
    calls = []

    def compact(*_args, **_kwargs):
        raise helper.CoverageIntegrityError("proven branch loss")

    with pytest.raises(helper.CoverageBatchError, match="proven branch loss"):
        helper.run_batches(
            tmp_path,
            "3.13",
            batch_size=1,
            runner=successful_native_runner(tmp_path, calls, keep_raw=True),
            discover=lambda _root: ["one", "two"],
            compact=compact,
        )
    assert len(calls) == 1 and raw(tmp_path, "1").exists()


@pytest.mark.parametrize("incompatibility", ["schema", "named-context", "export-command"])
def test_native_coverage_compatibility_errors_are_distinguished_without_deleting_inputs(tmp_path, incompatibility):
    source = raw(tmp_path)
    write_coverage(source, {"module.py": {(1, 2)}}, context="test-context" if incompatibility == "named-context" else "")
    if incompatibility == "schema":
        with closing(sqlite3.connect(source)) as database:
            with database:
                database.execute("UPDATE coverage_schema SET version = 8")
    original = source.read_bytes()
    runner = (
        export_runner({"module.py": {(1, 2)}}, code=1)
        if incompatibility == "export-command"
        else lambda *_args, **_kwargs: pytest.fail("reject before export")
    )
    with pytest.raises(helper.CoverageCompatibilityError):
        helper.compact_coverage(tmp_path, runner=runner, normalize=normalize)
    assert source.read_bytes() == original


@pytest.mark.parametrize("bad_input", ["empty", "symlink", "corrupt", "lost-arc"])
def test_proven_or_invalid_coverage_data_is_a_fatal_integrity_error(tmp_path, bad_input):
    source = raw(tmp_path)
    source.parent.mkdir(parents=True)
    if bad_input == "empty":
        source.touch()
    elif bad_input == "symlink":
        target = tmp_path / "retained.sqlite"
        write_coverage(target, {"module.py": {(1, 2)}})
        source.symlink_to(target)
    elif bad_input == "corrupt":
        source.write_bytes(b"not sqlite")
    else:
        write_coverage(source, {"module.py": {(1, 2), (2, -1)}})
    original = source.read_bytes()
    with pytest.raises(helper.CoverageIntegrityError):
        helper.compact_coverage(tmp_path, runner=export_runner({"module.py": {(1, 2)}}), normalize=normalize)
    assert source.read_bytes() == original


@pytest.mark.parametrize("strict", [False, True], ids=["automatic-fallback", "no-fallback"])
def test_cli_preserves_explicit_native_arguments_and_fallback_setting(monkeypatch, strict):
    captured = []

    def run(root, **kwargs):
        captured.append((root, kwargs))
        return 7

    arguments = ["run_unit_coverage.py", "--python", "3.13", "--local", "--num-workers", "2", "tests/unit/test_selected.py"]
    if strict:
        arguments.insert(1, "--no-fallback")
    monkeypatch.setattr(helper.sys, "argv", arguments)
    monkeypatch.setattr(helper, "run_batches", run)
    assert helper.main() == 7
    assert captured[0][0] == Path.cwd()
    assert captured[0][1]["fallback"] is (not strict)
    assert captured[0][1]["local"] is True and captured[0][1]["num_workers"] == 2
    assert captured[0][1]["targets"] == ["tests/unit/test_selected.py"]


@pytest.mark.parametrize("first_exit,first_report", [(1, '<testsuite tests="1" failures="1"/>'), (0, '<testsuite tests="1" errors="1"/>')])
def test_test_failures_do_not_disable_compaction_or_trigger_optimization_fallback(tmp_path, first_exit, first_report):
    calls, compactions = [], []
    code = helper.run_batches(
        tmp_path,
        "3.13",
        batch_size=1,
        runner=successful_native_runner(tmp_path, calls, first_exit=first_exit, first_report=first_report),
        discover=lambda _root: ["one", "two"],
        compact=lambda *_args, **_kwargs: compactions.append(True) or {},
    )
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert code == 1 and len(calls) == len(compactions) == 2
    assert manifest["mode"] == "batched" and manifest["fallbacks"] == []


@pytest.mark.parametrize("native_exit", [1, 3])
def test_full_native_discovery_fallback_preserves_failure_status(tmp_path, native_exit):
    calls = []

    def unavailable(_root):
        raise ImportError("changed ansible internals")

    code = helper.run_batches(
        tmp_path,
        "3.13",
        discover=unavailable,
        runner=successful_native_runner(tmp_path, calls, first_exit=native_exit),
        compact=lambda *_args, **_kwargs: pytest.fail("native fallback cannot compact"),
    )
    assert code != 0 and len(calls) == 1
    manifest = json.loads((tmp_path / "tests/output/coverage-batches/manifest.json").read_text())
    assert manifest["batches"][0]["exit_code"] == native_exit


def test_changed_native_input_names_are_recoverable_before_export_and_remain_untouched(tmp_path):
    source = tmp_path / "tests/output/coverage/new-native-format.sqlite"
    write_coverage(source, {"module.py": {(1, 2)}})
    original = source.read_bytes()
    with pytest.raises(helper.CoverageCompatibilityError):
        helper.compact_coverage(
            tmp_path,
            normalize=normalize,
            runner=lambda *_args, **_kwargs: pytest.fail("unknown input naming must be recognized before export"),
        )
    assert source.read_bytes() == original


def test_changed_native_export_names_are_recoverable_without_deleting_raw_inputs(tmp_path):
    source = raw(tmp_path)
    write_coverage(source, {"module.py": {(1, 2)}})
    original = source.read_bytes()
    commands = []

    def changed_export(command, **_kwargs):
        commands.append(command)
        stage = Path(command[command.index("--export") + 1])
        write_coverage(stage / "new-native-export.sqlite", {"module.py": {(1, 2)}})
        return 0

    with pytest.raises(helper.CoverageCompatibilityError):
        helper.compact_coverage(tmp_path, normalize=normalize, runner=changed_export)
    assert len(commands) == 1 and commands[0][1:3] == ["coverage", "combine"]
    assert source.read_bytes() == original


def test_new_raw_naming_beside_a_known_aggregate_cannot_be_ignored_or_exported(tmp_path):
    directory = tmp_path / "tests/output/coverage"
    aggregate = directory / "various=various=various=python-3.13=coverage.combined"
    unknown = directory / "new-native-raw.sqlite"
    write_coverage(aggregate, {"module.py": {(1, 2)}})
    write_coverage(unknown, {"module.py": {(2, -1)}})
    original = {path: path.read_bytes() for path in (aggregate, unknown)}
    with pytest.raises(helper.CoverageCompatibilityError):
        helper.compact_coverage(
            tmp_path,
            normalize=normalize,
            runner=lambda *_args, **_kwargs: pytest.fail("a recognized aggregate must not hide unknown raw evidence from the exporter"),
        )
    assert all(path.read_bytes() == content for path, content in original.items())


def test_mixed_known_and_new_export_names_never_publish_an_incomplete_known_subset(tmp_path):
    source = raw(tmp_path)
    write_coverage(source, {"module.py": {(1, 2), (2, -1)}})
    original = source.read_bytes()
    commands = []

    def changed_export(command, **_kwargs):
        commands.append(command)
        stage = Path(command[command.index("--export") + 1])
        write_coverage(stage / "various=various=various=python-3.13=coverage.combined", {"module.py": {(1, 2), (2, -1)}})
        write_coverage(stage / "new-native-export.sqlite", {"other.py": {(5, 6)}})
        return 0

    with pytest.raises(helper.CoverageCompatibilityError):
        helper.compact_coverage(
            tmp_path,
            normalize=normalize,
            runner=changed_export,
            publish=lambda *_args: pytest.fail("unknown export evidence must be accounted for before any publication"),
        )
    assert len(commands) == 1 and source.read_bytes() == original
    assert helper.coverage_inputs(source.parent) == [source]


def test_unknown_named_symlink_beside_a_known_aggregate_is_fatal_before_export(tmp_path):
    directory = tmp_path / "tests/output/coverage"
    aggregate = directory / "various=various=various=python-3.13=coverage.combined"
    target = tmp_path / "retained.sqlite"
    write_coverage(aggregate, {"module.py": {(1, 2)}})
    write_coverage(target, {"other.py": {(3, 4)}})
    unknown = directory / "new-native-format.sqlite"
    unknown.symlink_to(target)
    original = {path: path.read_bytes() for path in (aggregate, target)}
    with pytest.raises(helper.CoverageIntegrityError):
        helper.compact_coverage(
            tmp_path,
            normalize=normalize,
            runner=lambda *_args, **_kwargs: pytest.fail("unknown input naming cannot hide a symlink behind compatibility fallback"),
        )
    assert unknown.is_symlink()
    assert all(path.read_bytes() == content for path, content in original.items())


@pytest.mark.parametrize("versions", [[], ["bad"], [7, 7], [0]], ids=["missing-row", "malformed-version", "duplicate-rows", "nonpositive-version"])
def test_invalid_schema_metadata_is_fatal_integrity_before_export_and_preserves_raw(tmp_path, versions):
    source = raw(tmp_path)
    write_coverage(source, {"module.py": {(1, 2)}})
    with closing(sqlite3.connect(source)) as database:
        with database:
            database.execute("DELETE FROM coverage_schema")
            database.executemany("INSERT INTO coverage_schema (version) VALUES (?)", [(version,) for version in versions])
    original = source.read_bytes()
    with pytest.raises(helper.CoverageIntegrityError):
        helper.read_branch_data([source], normalize)
    with pytest.raises(helper.CoverageIntegrityError):
        helper.compact_coverage(
            tmp_path,
            normalize=normalize,
            runner=lambda *_args, **_kwargs: pytest.fail("corrupt schema metadata must never authorize export or compatibility fallback"),
        )
    assert source.read_bytes() == original
