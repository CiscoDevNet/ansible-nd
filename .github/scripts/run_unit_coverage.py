# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Run every selected ansible-test unit target with bounded coverage storage.

Only file selection is batched: pytest parametrization and ansible-test's
per-test fork isolation stay intact. Each batch's reusable coverage export is
verified before replacing its inputs. A failed test batch does not skip later
batches; a failed compaction stops before more data can fill the runner disk.
"""

from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote
from xml.etree import ElementTree


class CoverageBatchError(RuntimeError):
    """Stop an unsafe or incomplete coverage compaction without deleting inputs."""


@contextmanager
def in_directory(root):
    """Keep ansible-test's collection-relative discovery and normalization exact."""
    previous = Path.cwd()
    os.chdir(root)
    try:
        yield
    finally:
        os.chdir(previous)


def discover_targets(root):
    """Use the installed ansible-test target discovery, including its exclusions."""
    with in_directory(root):
        from ansible_test._internal.target import walk_units_targets

        return sorted(target.path for target in walk_units_targets())


def partition_targets(targets, size):
    """Partition every unique selected file exactly once; never reduce test cases."""
    if size < 1 or not targets or len(targets) != len(set(targets)):
        raise CoverageBatchError("Require nonempty, unique unit targets and a positive batch size.")
    return [targets[index : index + size] for index in range(0, len(targets), size)]


def coverage_inputs(directory):
    """Match ansible-test's native Python coverage input naming convention."""
    return sorted(path for path in directory.iterdir() if "=coverage." in path.name and "=python" in path.name) if directory.exists() else []


def make_normalizer(root):
    """Reuse ansible-test's path mapping without importing the coverage package."""
    from ansible_test._internal.commands.coverage import get_collection_path_regexes, get_python_modules, sanitize_filename

    search, replace = get_collection_path_regexes()
    modules = get_python_modules()

    def normalize(filename):
        mapped = sanitize_filename(filename, modules=modules, collection_search_re=search, collection_sub_re=replace)
        if mapped is None:
            raise CoverageBatchError(f"Cannot map coverage source {filename!r}.")
        path = Path(mapped)
        if not path.is_file():
            # The collection loader reports implicit namespace __init__ files.
            # Existing ansible-test reports omit these nonexistent source files.
            if search and search.search(mapped) and path.name == "__init__.py":
                return None
            raise CoverageBatchError(f"Coverage source does not exist: {mapped}")
        try:
            return path.relative_to(root).as_posix()
        except ValueError as error:
            raise CoverageBatchError(f"Coverage source is outside the collection: {mapped}") from error

    return normalize


def read_branch_data(paths, normalize):
    """Read schema-7 branch data with stdlib SQLite, preserving empty file rows.

    Current ansible-test coverage has no named contexts and its exporter merges
    them. Reject unexpected named contexts rather than silently discard them.
    """
    groups = {}
    # Source paths repeat across thousands of per-test databases. Resolve each
    # once per read, while still validating every database and every branch arc.
    normalized_names = {}
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise CoverageBatchError(f"Coverage input is empty or not a regular file: {path}")
        parts = path.name.split("=", 4)
        if len(parts) != 5 or not parts[3].startswith("python-") or not parts[4].startswith("coverage."):
            raise CoverageBatchError(f"Unexpected coverage input name: {path.name}")
        group = groups.setdefault(parts[3], {})
        try:
            uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                if connection.execute("SELECT version FROM coverage_schema").fetchone() != (7,):
                    raise CoverageBatchError(f"Unsupported coverage schema: {path}")
                if dict(connection.execute("SELECT key, value FROM meta")).get("has_arcs") != "1":
                    raise CoverageBatchError(f"Coverage file does not contain branch data: {path}")
                if any(context for (context,) in connection.execute("SELECT context FROM context")):
                    raise CoverageBatchError(f"Named coverage contexts need an explicit preservation strategy: {path}")
                file_names = {}
                for file_id, filename in connection.execute("SELECT id, path FROM file"):
                    if filename not in normalized_names:
                        normalized_names[filename] = normalize(filename)
                    mapped = normalized_names[filename]
                    if mapped is not None:
                        file_names[file_id] = mapped
                        group.setdefault(mapped, set())
                for file_id, start, end in connection.execute("SELECT file_id, fromno, tono FROM arc"):
                    if file_id in file_names:
                        group[file_names[file_id]].add((start, end))
        except sqlite3.Error as error:
            raise CoverageBatchError(f"Unreadable coverage data {path}: {error}") from error
    return groups


def _nonempty_arcs(groups):
    return {version: {name: arcs for name, arcs in files.items() if arcs} for version, files in groups.items()}


def _invoke(runner, command, root):
    result = runner(command, cwd=root, check=False)
    return result if isinstance(result, int) else result.returncode


def compact_coverage(root, runner=subprocess.run, ansible_test="ansible-test", normalize=None, publish=os.replace):
    """Publish a verified reusable aggregate before deleting only consumed inputs."""
    root = Path(root).resolve()
    directory = root / "tests/output/coverage"
    inputs = coverage_inputs(directory)
    if not inputs:
        raise CoverageBatchError("No raw coverage inputs were produced by the unit batch.")
    with in_directory(root):
        normalize = normalize or make_normalizer(root)
        expected = read_branch_data(inputs, normalize)
        with tempfile.TemporaryDirectory(prefix="coverage-export-", dir=directory.parent) as temporary:
            stage = Path(temporary)
            command = [ansible_test, "coverage", "combine", "--export", str(stage), "--requirements"]
            if _invoke(runner, command, root):
                raise CoverageBatchError("Coverage export failed; raw coverage inputs were retained.")
            exports = coverage_inputs(stage)
            if not exports or any(not path.name.endswith("=coverage.combined") for path in exports):
                raise CoverageBatchError("Coverage export is empty or has unexpected names; raw inputs were retained.")
            exported = read_branch_data(exports, normalize)
            if not any(expected.values()) or _nonempty_arcs(exported) != _nonempty_arcs(expected):
                raise CoverageBatchError("Coverage export did not preserve every source branch arc; raw inputs were retained.")
            # ansible-test's exporter skips measured files with zero arcs. Keep
            # their schema-7 file entries so even that evidence is not dropped.
            for path in exports:
                version = path.name.split("=", 4)[3]
                missing = set(expected.get(version, {})) - set(exported.get(version, {}))
                if missing:
                    with closing(sqlite3.connect(path)) as connection:
                        with connection:
                            connection.executemany("INSERT OR IGNORE INTO file (path) VALUES (?)", [(name,) for name in sorted(missing)])
            if read_branch_data(exports, normalize) != expected:
                raise CoverageBatchError("Verified coverage differs from the input union; raw inputs were retained.")
            destinations = {directory / path.name for path in exports}
            for path in exports:
                publish(path, directory / path.name)
            # If publication fails partway, every raw input remains available.
            # Existing aggregate names may have just been atomically replaced;
            # never unlink those new files as if they were the old inputs.
            for path in inputs:
                if path not in destinations:
                    path.unlink()
    return {"input_files": len(inputs), "aggregate_files": len(destinations), "source_files": sum(len(files) for files in expected.values())}


def coverage_usage(directory):
    paths = coverage_inputs(directory)
    return {"files": len(paths), "bytes": sum(path.stat().st_size for path in paths)}


def archive_junit(root, destination):
    """Move reports to an exclusive archive so each invocation starts without stale XML."""
    archived_paths = []
    if destination.exists():
        raise CoverageBatchError(f"JUnit archive already exists and will not be overwritten: {destination}")
    reports = sorted((root / "tests/output/junit").glob("*.xml"))
    if reports:
        destination.mkdir(parents=True)
        for path in reports:
            archived = destination / path.name
            path.rename(archived)
            archived_paths.append(str(archived.relative_to(root)))
    return archived_paths


def summarize_junit(root, paths):
    """Validate archived reports and count leaf suites without counting wrappers twice."""
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    for path in paths:
        try:
            report = ElementTree.parse(root / path).getroot()
        except (ElementTree.ParseError, OSError) as error:
            raise CoverageBatchError(f"Unreadable JUnit report {path}: {error}") from error
        if report.tag not in ("testsuite", "testsuites"):
            raise CoverageBatchError(f"Unexpected JUnit report root in {path}: {report.tag}")
        suites = list(report.iter("testsuite"))
        if not suites:
            raise CoverageBatchError(f"JUnit report contains no test suites: {path}")
        report_tests = 0
        for suite in suites:
            try:
                counts = {name: int(suite.attrib.get(name, "0")) for name in totals}
                if "tests" not in suite.attrib or any(count < 0 for count in counts.values()):
                    raise ValueError("require nonnegative counts and a tests attribute")
            except ValueError as error:
                raise CoverageBatchError(f"Invalid JUnit test counts in {path}: {error}") from error
            if any(child.tag == "testsuite" for child in suite.iter() if child is not suite):
                continue
            report_tests += counts["tests"]
            # Also honor explicit failure/error elements if summary attributes
            # were omitted or contradict the testcase diagnostics.
            for name, tag in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped")):
                counts[name] = max(counts[name], sum(1 for unused_element in suite.iter(tag)))
            for name, count in counts.items():
                totals[name] += count
        if not report_tests:
            raise CoverageBatchError(f"JUnit report contains no executed or skipped test cases: {path}")
    if not totals["tests"]:
        raise CoverageBatchError("JUnit reports contain no executed or skipped test cases.")
    return totals


def run_batches(
    root,
    python_version,
    *,
    batch_size=20,
    targets=None,
    local=False,
    ansible_test="ansible-test",
    num_workers=None,
    runner=subprocess.run,
    discover=discover_targets,
    compact=compact_coverage,
):
    """Run all batches, retaining test failures while keeping coverage disk use bounded."""
    root = Path(root).resolve()
    available = discover(root)
    selected = list(targets) if targets else available
    if set(selected) - set(available):
        raise CoverageBatchError("Selected targets are not all discoverable ansible-test unit files.")
    batches = partition_targets(selected, batch_size)
    output = root / "tests/output/coverage-batches"
    if output.exists() or coverage_inputs(root / "tests/output/coverage"):
        raise CoverageBatchError("Use clean coverage outputs; existing results will not be overwritten or erased.")
    output.mkdir(parents=True)
    manifest = {"python": python_version, "targets": selected, "batch_size": batch_size, "batches": [], "complete": False}
    manifest_path = output / "manifest.json"

    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    save()
    manifest["previous_junit"] = archive_junit(root, output / "previous-junit")
    save()
    for index, paths in enumerate(batches, 1):
        command = [ansible_test, "units", "--local" if local else "--docker", "-v", "--color", "--truncate", "0", "--python", python_version, "--coverage"]
        if num_workers is not None:
            command.extend(["--num-workers", str(num_workers)])
        command.extend(paths)
        print(f"Coverage batch {index}/{len(batches)}: {len(paths)} unit files", flush=True)
        started = time.monotonic()
        code = _invoke(runner, command, root)
        record = {"number": index, "targets": paths, "command": command, "exit_code": code, "elapsed_seconds": round(time.monotonic() - started, 3)}
        manifest["batches"].append(record)
        record["junit"] = archive_junit(root, output / f"batch-{index:03d}" / "junit")
        if record["junit"]:
            try:
                record["junit_summary"] = summarize_junit(root, record["junit"])
                if not code and (record["junit_summary"]["failures"] or record["junit_summary"]["errors"]):
                    raise CoverageBatchError("JUnit reports failures or errors although the unit command succeeded.")
            except CoverageBatchError as error:
                record["junit_error"] = str(error)
        record["coverage_before_compaction"] = coverage_usage(root / "tests/output/coverage")
        save()
        try:
            record["compaction"] = compact(root, runner=runner, ansible_test=ansible_test)
            record["coverage_after_compaction"] = coverage_usage(root / "tests/output/coverage")
        except Exception as error:
            record["compaction_error"] = str(error)
            save()
            raise CoverageBatchError(f"Batch {index} coverage compaction stopped: {error}") from error
        save()
    manifest["complete"] = True
    manifest["failed_batches"] = [record["number"] for record in manifest["batches"] if record["exit_code"]]
    manifest["missing_junit_batches"] = [record["number"] for record in manifest["batches"] if not record["junit"]]
    manifest["invalid_junit_batches"] = [record["number"] for record in manifest["batches"] if record.get("junit_error")]
    save()
    return 1 if manifest["failed_batches"] or manifest["missing_junit_batches"] or manifest["invalid_junit_batches"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, dest="python_version")
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--local", action="store_true", help="Use local ansible-test instead of its normal Docker controller.")
    parser.add_argument("--ansible-test", default="ansible-test")
    parser.add_argument("--num-workers", type=int)
    parser.add_argument("targets", nargs="*", help="Optional exact unit files for a focused benchmark; default is every discoverable file.")
    arguments = parser.parse_args()
    try:
        return run_batches(Path.cwd(), **vars(arguments))
    except (CoverageBatchError, OSError) as error:
        print(f"Coverage batching failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
