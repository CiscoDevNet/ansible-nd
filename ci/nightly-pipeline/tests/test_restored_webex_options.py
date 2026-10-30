"""Run the restored notification options through each real Jenkinsfile offline."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from test_five_issue_pipeline_fixes import PRELUDE


ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)


@pytest.fixture(scope="module", params=VARIANTS)
def groovy_runner(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA", "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java"))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("A local JVM and Groovy jar are required")
    directory = tmp_path_factory.mktemp("restored-webex")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        path = directory / f"check-{sequence}.groovy"
        path.write_text(PRELUDE + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain", str(path), str(ROOT / request.param)],
                                text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout

    return run


def literal(value):
    encoded = json.dumps(value).replace("\\", "\\\\").replace("'", "\\'")
    return "script.parseReportingJson('" + encoded + "')"


POST = r'''
def sent = []
script.metaClass.pipeline = { Closure work -> work.call() }
for (def name : ['agent', 'parameters', 'environment', 'options', 'stages', 'cleanup']) {
    script.metaClass."${name}" = { Closure ignored -> null }
}
script.metaClass.post = { Closure work -> work.call() }
script.metaClass.always = { Closure work -> work.call() }
script.metaClass.script = { Closure work -> work.call() }
script.metaClass.success = { Closure ignored -> null }
script.metaClass.failure = { Closure ignored -> null }
script.metaClass.sendWebexNotificationMessages = { Object messages -> sent.addAll(messages) }
script.binding.env.putAll([ACTIVE_DCNM_VERSIONS: '4.3', ND_GIT_BRANCH: 'feature/example',
    ND_GIT_SELECTION: 'fixture-owner:feature/example', ND_GIT_COMMIT: 'a' * 40,
    LOG_BUNDLE_FILE: 'all-logs.zip', MODULE_ACTIVITY_REPORT_FILE: 'activity.txt'])
assert source.contains("string(name: 'WEBEX_CUSTOM_MESSAGE'")
'''


@pytest.mark.parametrize("rounds, note", [("iBGP + eBGP", "Private regression run — **keep this note**"),
                                         ("", " \n "), ("iBGP", "Quotes '\"; ${notGroovy}; 😀")])
def test_actual_post_restores_optional_note_round_title_and_fork_label(groovy_runner, rounds, note):
    groovy_runner(POST + "script.binding.env.ACTIVE_FABRIC_ROUNDS = " + literal(rounds) + "\n" +
                  "script.binding.params.WEBEX_CUSTOM_MESSAGE = " + literal(note) + "\n" + r'''
script.run()
assert sent.size() == 1 : logs
def rounds = script.binding.env.ACTIVE_FABRIC_ROUNDS
def title = 'ND 4.3' + (rounds ? ' (' + rounds + ')' : '') + ' NIGHTLY NOTIFICATION'
def note = script.binding.params.WEBEX_CUSTOM_MESSAGE.trim()
assert sent[0].startsWith(title + '\n' + (note ? note + '\n\n' : '📊'))
assert sent[0].contains('ansible-nd branch: fixture-owner:feature/example\n')
assert sent[0].contains('ansible-nd commit: ' + ('a' * 40))
assert sent[0].contains('All logs (zip)') && sent[0].contains('/artifact/all-logs.zip')
assert sent[0].contains('Module test activity table') && sent[0].contains('/artifact/activity.txt')
assert sent[0].length() <= 7000
assert !logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_FAILED:') }
''')


def test_long_report_keeps_every_module_and_link_with_bounded_note(groovy_runner):
    groovy_runner(POST + r'''
script.binding.env.ACTIVE_FABRIC_ROUNDS = 'iBGP + eBGP'
script.binding.params.WEBEX_CUSTOM_MESSAGE = 'x' * 5000
220.times { index ->
    def name = 'fixture_module_' + index
    script.MODULE_ACTIVITY_RESULTS[name] = [module: name, nd: '4.3', scope: index % 2 ? 'eBGP' : 'iBGP',
        fabric: 'fixture-fabric', round_label: index % 2 ? 'eBGP' : 'iBGP', result: 'PASS',
        coverage: 'COMPLETE', validated: true,
        case_totals: [started: 1, passed: 1, failed: 0, skipped: 0, incomplete: 0],
        counts: [merged: [started: 1]], base: 'Ran', cleanup: 'Ran', duration: '1m', failure: '']
}
script.run()
assert sent.size() > 1
assert sent.every { it.length() <= 7000 }
def combined = sent.join('\n')
assert combined.contains('x' * 1200) && !combined.contains('x' * 1201)
assert sent.every { it.contains('ND 4.3 (iBGP + eBGP) NIGHTLY NOTIFICATION') }
assert sent.every { it.contains('ansible-nd branch: fixture-owner:feature/example') }
220.times { index -> assert combined.contains('fixture_module_' + index) }
assert combined.contains('/artifact/all-logs.zip') && combined.contains('/artifact/activity.txt')
assert combined.contains('Test cases passed: 220')
assert !logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_FAILED:') }
''')


def test_minimal_fallback_retains_rounds_note_and_raw_fork_selection(groovy_runner):
    groovy_runner(r'''
script.binding.env.putAll([ACTIVE_DCNM_VERSIONS: '4.3', ACTIVE_FABRIC_ROUNDS: 'iBGP + eBGP',
    ND_GIT_BRANCH: 'feature/example', ND_GIT_SELECTION: 'fixture-owner:feature/example', ND_GIT_COMMIT: 'b' * 40])
script.binding.params.WEBEX_CUSTOM_MESSAGE = 'x' * 5000
def fallback = script.minimalBuildNotification('fixture.ReportingError')
assert fallback.startsWith('ND 4.3 (iBGP + eBGP) NIGHTLY NOTIFICATION - Build 122\n' + ('x' * 1200) + '\n\n')
assert !fallback.contains('x' * 1201)
assert fallback.contains('Branch: fixture-owner:feature/example\nCommit: ' + ('b' * 40))
assert fallback.length() < 7000
assert fallback.contains('Test-case counts are unknown')
''')


def test_custom_note_cap_cannot_split_an_emoji_surrogate_pair(groovy_runner):
    groovy_runner(POST + r'''
script.binding.env.ACTIVE_FABRIC_ROUNDS = 'iBGP + eBGP'
script.binding.params.WEBEX_CUSTOM_MESSAGE = ('x' * 1199) + '😀'
script.run()
assert sent.size() == 1
assert sent[0].contains(('x' * 1199) + '\n\n📊')
def fallback = script.minimalBuildNotification()
assert fallback.contains(('x' * 1199) + '\n\nBranch:')
''')


@pytest.mark.parametrize("selection", ["fixture-owner:feature/example", "feature/example", "   ", "", None])
def test_early_failure_reports_requested_branch_before_checkout_initializes_environment(groovy_runner, selection):
    expected = selection.strip() if selection and selection.strip() else "develop"
    groovy_runner(POST + "script.binding.params.ND_GIT_BRANCH = " + literal(selection) + "\n" +
                  "def expected = " + literal(expected) + "\n" + r'''
script.binding.env.remove('ND_GIT_SELECTION')
script.binding.env.remove('ND_GIT_BRANCH')
script.binding.env.remove('ND_GIT_COMMIT')
script.run()
assert sent.size() == 1 : logs
assert sent[0].contains('ansible-nd branch: ' + expected + '\n')
assert sent[0].contains('ansible-nd commit: unavailable')
def fallback = script.minimalBuildNotification()
assert fallback.contains('Branch: ' + expected + '\nCommit: unavailable\n')
def summaries = []
script.metaClass.writeFile = { Map options -> summaries.add(options.text.toString()) }
script.metaClass.withEnv = { List ignored, Closure work -> null }
script.metaClass.timeout = { Map ignored, Closure work -> work.call() }
script.metaClass.archiveArtifacts = { Map ignored -> null }
script.bundleAllLogs()
assert summaries.size() == 1
assert summaries[0].contains('Branch: ' + expected + '\nCommit: unavailable\n')
''')
