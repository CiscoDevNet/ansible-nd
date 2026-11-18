# Unit coverage CI

The coverage-enabled unit job uses `run_unit_coverage.py` to run the complete
selection in batches of 20 unit files. Pytest parametrization and Ansible's
per-test fork isolation are unchanged. The other unit matrix entries use the
normal `ansible-test units` command.

After each batch, the helper exports coverage through `ansible-test coverage
combine --export`. It checks that the export preserves the measured files and
branch arcs, publishes the reusable aggregate, and only then removes its
consumed raw inputs. Final XML generation and Codecov upload still use the
existing workflow steps.

## Compatibility and maintenance

The helper depends on these implementation details:

- `ansible_test._internal.target.walk_units_targets` for file discovery.
- `get_collection_path_regexes`, `get_python_modules`, and `sanitize_filename`
  from `ansible_test._internal.commands.coverage` for source-path mapping.
- SQLite coverage schema 7 with branch data (`has_arcs=1`) and unnamed contexts.
- Native filenames of the form
  `command=target=environment=python-X.Y=coverage.*`. Reusable exports use
  `various=various=various=python-X.Y=coverage.combined`.

When upgrading Ansible or coverage, run `tests/unit/ci/test_unit_coverage.py`
and a real Docker coverage run followed by `ansible-test coverage xml
--requirements`. Check case selection, source-path mapping, and branch
preservation before updating these assumptions. Do not bypass an integrity
error or delete raw inputs to make an export appear valid.

Keep this directory in collection artifacts: CI runs the helper from the
installed collection, and its unit tests load it from this location. The script
is invoked with Python and intentionally has no executable shebang.

## Fallback behavior

By default, a recoverable helper compatibility or compaction failure falls back
to native Ansible execution:

- If private discovery is unavailable before any tests run, one native unit
  invocation performs discovery and runs the selection.
- If compaction becomes unavailable after a batch, existing coverage evidence
  is retained in raw inputs or a verified aggregate. The helper disables further
  compaction and runs only the remaining file batches. Completed tests are not
  replayed.

Fallback can accumulate raw coverage for the rest of the run, so its disk and
runtime costs can return to those of the native command. Test failures remain
failures. Invalid configuration, corrupt data, lost coverage evidence, or
missing/invalid JUnit reports are not converted into success by fallback.

For strict investigation, disable automatic fallback:

```sh
python .github/scripts/run_unit_coverage.py --python 3.13 --batch-size 20 --no-fallback
```

To bypass the helper entirely, run the original commands from a clean collection
checkout or installed collection root:

```sh
ansible-test units --docker -v --color --truncate 0 --python 3.13 --coverage
ansible-test coverage xml -v --requirements
```

Preserve an earlier failed run's evidence before starting a fresh run. The
helper refuses to overwrite existing raw coverage or batch archives.

## Diagnostics

`tests/output/coverage-batches/manifest.json` records selected files, commands,
batch results, coverage compaction, and fallback details. Each batch's JUnit
reports have a separate archive under `coverage-batches/batch-*/junit/`.
Pre-existing reports are preserved separately and do not count as new results.

The coverage CI cell makes a best-effort upload of the manifest and per-batch
JUnit XML, including on failure. This diagnostic artifact excludes raw coverage
databases, which can be large. An upload failure does not replace the test
result.
