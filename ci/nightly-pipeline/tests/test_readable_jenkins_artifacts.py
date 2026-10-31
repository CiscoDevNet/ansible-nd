"""Execute artifact publication and ZIP selection without Jenkins or network access."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import zipfile

import pytest

from test_five_issue_pipeline_fixes import PRELUDE

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)


@pytest.fixture(scope="module", params=VARIANTS)
def pipeline(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA") or shutil.which("java") or "")
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", ""))
    if not java.is_file() or not jar.is_file():
        pytest.skip("A local JVM and Groovy jar are required")
    directory = tmp_path_factory.mktemp("readable-artifacts")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        script = directory / (str(sequence) + ".groovy")
        script.write_text(PRELUDE + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain",
                                 str(script), str(ROOT / request.param)],
                                text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout

    return run


PUBLISHER = r'''
def archived = []
int nextCalls = 0
script.metaClass.sh = { Object options ->
    if (options instanceof Map && options.returnStdout) {
        nextCalls++
        return nextCalls == 1 ? script.writeReportingJson([done: false,
            execution: [id: 'fixture-job', files: selectedFiles, attempt: 1]]) : '{"done":true}'
    }
    return ''
}
script.metaClass.archiveArtifacts = { Map options -> archived.add(options.artifacts.toString()) }
script.metaClass.timeout = { Map options, Closure work -> work.call() }
script.metaClass.retry = { int attempts, Closure work -> work.call() }
script.metaClass.withEnv = { List entries, Closure work -> work.call() }
script.publishStructuredArtifacts()
'''


def test_publisher_archives_only_the_flat_round_labelled_module_log(pipeline):
    pipeline("def selectedFiles = ['test_output_fabric_ND43_IBGP_nd_example.txt']\n" + PUBLISHER + r'''
assert archived == selectedFiles
assert nextCalls == 2
assert !logs.any { it.startsWith('NDP_REPORTER_FAILED:') }
''')


@pytest.mark.parametrize("files", [
    ["fixture-reports/executions/log.txt"],
    ["test_output_fabric_ND43_EBGP_nd_example.txt", "log.summary.json"],
    ["../test_output_fabric_ND43_IBGP_nd_example.txt"],
    ["aggregate.json"],
])
def test_publisher_rejects_internal_metadata_and_unsafe_descriptors(pipeline, files):
    literal = json.dumps(json.dumps(files)).replace("$", "\\$")
    pipeline("def selectedFiles = script.parseReportingJson(" + literal + ")\n" + PUBLISHER + r'''
assert archived.isEmpty()
assert logs.any { it.startsWith('NDP_REPORTER_FAILED:') }
''')


def test_final_fold_publishes_the_combined_skip_list_and_no_internal_json(pipeline):
    pipeline(r'''
def archived = []
script.metaClass.sh = { Object options -> '' }
script.metaClass.readFile = { Map options ->
    script.writeReportingJson([rows: [], reporting_errors: [], failed: false,
        skiplist_file: 'skipped_tests_build_122.txt'])
}
script.metaClass.archiveArtifacts = { Map options -> archived.add(options.artifacts.toString()) }
script.foldStructuredResults()
assert archived == ['skipped_tests_build_122.txt']
assert script.SKIPLIST_FILES_BUF.contains('skipped_tests_build_122.txt')
assert !script.SKIPLIST_FILES_BUF.contains('progress')
''')


@pytest.mark.parametrize("variant", VARIANTS)
def test_real_bundle_contains_only_this_builds_human_readable_outputs(tmp_path, variant):
    source = (ROOT / variant).read_text().split('def bundleAllLogs()', 1)[1]
    code = source.split('import json\n', 1)[1].split('\nPY\n', 1)[0]
    code = 'import json\n' + code
    report = tmp_path / 'reports'
    report.mkdir()
    logs = ["test_output_fabric_ND43_IBGP_nd_example.txt",
            "test_output_fabric_eBGP_ND43_EBGP_nd_example.txt"]
    raw = b"TASK [nd_example : MERGED TC1] ***\n" * 3000
    for name in logs:
        (tmp_path / name).write_bytes(raw)
    (report / 'aggregate.json').write_text(json.dumps({'rows': [{'artifact': n} for n in logs]}))
    unwanted = ['producer.json', 'reporter.json', 'module_progress_build_128.txt',
                'test_output_fabric_ND43_IBGP_nd_example.txt.summary.json',
                'test_output_fabric_ND43_IBGP_nd_example.txt.events.jsonl',
                'test_output_stale_ND43_IBGP_nd_unselected.txt']
    for name in unwanted:
        (tmp_path / name).write_text('INTERNAL_OR_STALE_CANARY')
    reports = ['pipeline_summary_build_128.txt', 'module_test_activity_build_128.txt',
               'skipped_tests_build_128.txt', 'ansible_lint_build_128.txt']
    for name in reports:
        (tmp_path / name).write_text('human-readable report')
    result = subprocess.run([sys.executable, '-c', code], text=True, capture_output=True,
                            env=dict(os.environ, WORKSPACE=str(tmp_path), ND_REPORTING_ROOT=str(report),
                                     BUILD_NUMBER='128', LOG_ZIP='logs.zip'), timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    with zipfile.ZipFile(tmp_path / 'logs.zip') as archive:
        assert set(archive.namelist()) == set(logs + reports)
        assert all(archive.read(name) == raw for name in logs)
        assert all(Path(name).suffix in {'.txt', '.log'} for name in archive.namelist())
