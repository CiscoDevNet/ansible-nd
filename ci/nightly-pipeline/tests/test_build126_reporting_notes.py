"""Exercise both full Jenkinsfiles through an offline, real Groovy runtime."""

import json

import pytest
from test_build124_switch_preflight import PRODUCER, groovy_runner


def literal(value):
    return "script.parseReportingJson(" + json.dumps(json.dumps(value)) + ")"


@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            "Module case progress and skips|reports/progress.txt",
            "📋 [Module case progress and skips](https://jenkins.example/job/nd/124/artifact/reports/progress.txt)",
        ),
        (
            "  reports/legacy.txt  ",
            "📋 [Skipped tests](https://jenkins.example/job/nd/124/artifact/reports/legacy.txt)",
        ),
        (
            "reports/one.txt\nreports/two.txt",
            "📋 [Skipped tests 1](https://jenkins.example/job/nd/124/artifact/reports/one.txt)\n"
            "📋 [Skipped tests 2](https://jenkins.example/job/nd/124/artifact/reports/two.txt)",
        ),
        (
            "  Module_[case]*\\detail | reports/progress.txt \n\nreports/legacy.txt",
            "📋 [Module\\_\\[case\\]\\*\\\\detail](https://jenkins.example/job/nd/124/artifact/reports/progress.txt)\n"
            "📋 [Skipped tests 2](https://jenkins.example/job/nd/124/artifact/reports/legacy.txt)",
        ),
        (
            "|reports/progress.txt\nMissing path|  ",
            "📋 [Skipped tests 1](https://jenkins.example/job/nd/124/artifact/reports/progress.txt)",
        ),
        (" \n ", ""),
    ],
)
def test_skipped_links_preserve_paths_and_escape_labels(groovy_runner, raw, expected):
    groovy_runner(
        "assert script.formatSkippedTestLinks(" + literal(raw) + ") == " + literal(expected)
    )


@pytest.mark.parametrize(
    "reason, expected_fragment, forbidden",
    [
        (
            "Switch membership pre-flight failed: phase=pre, fabric=VXLAN_EVPN_Fabric, "
            "exit_code=2, classification=ANSIBLE_FAILED, timeout_limit_seconds=3600.",
            "classification=ANSIBLE_FAILED",
            None,
        ),
        (
            "setup rejected\r\npassword=sensitive-fixture-value",
            "setup rejected  [credential details redacted]",
            "sensitive-fixture-value",
        ),
        ("x" * 2000, "x" * 100, None),
        (None, "round stopped before module execution", None),
    ],
    ids=["guard-summary", "redacted", "bounded", "empty-message"],
)
def test_zero_module_round_failure_survives_real_fold_and_reaches_webex(
    groovy_runner, reason, expected_fragment, forbidden
):
    # Keep the real recordUnstartedRound and foldStructuredResults implementations.
    producer = "\n".join(
        line
        for line in PRODUCER.splitlines()
        if not line.startswith("script.metaClass.recordUnstartedRound =")
        and not line.startswith("script.metaClass.foldStructuredResults =")
    )
    body = (
        "def failureMode = 'infrastructure'\n"
        "def failure = new IllegalStateException((String)" + literal(reason) + ")\n"
        + producer
        + "\n"
        + r'''
script.metaClass.sh = { Object options -> '' }
script.metaClass.readFile = { Map options ->
    calls.add('read-aggregate')
    assert options.file.endsWith('/aggregate.json')
    return '{"rows":[],"reporting_errors":[],"failed":true,"skiplist_file":"skipped_tests_build_124.txt"}'
}
script.metaClass.archiveArtifacts = { Map options -> null }
def caught = null
try { script.run() } catch (Exception e) { caught = e }
assert caught != null && caught.is(failure)
assert !calls.contains('round:eBGP') && !calls.contains('reset')
assert calls.any { it.startsWith('home:') }
assert calls.contains('finish:failed')
assert calls.contains('read-aggregate') : calls
assert script.MODULE_ACTIVITY_RESULTS
assert script.MODULE_ACTIVITY_RESULTS.values().every { it.result == 'NOT_RUN' }
def totals = script.moduleCaseTotals(script.MODULE_ACTIVITY_RESULTS.values().toList())
assert totals.keySet() == ['passed', 'failed', 'skipped'] as Set
assert totals.values().every { it.toString() == '0' }
def notes = script.BUILD_FAILURE_REASON_BUF
assert notes.startsWith('\nRound ND 4.3 iBGP (VXLAN_EVPN_Fabric): ')
assert notes.length() <= 2400
assert !notes.contains('\r')
assert notes.count('\n') == 1
// Offline DSL closures can create binding shadows. Verify the actual @Field
// preservation separately, using the producer's observed round note.
def noteField = script.getClass().getDeclaredField('BUILD_FAILURE_REASON_BUF')
noteField.setAccessible(true)
noteField.set(script, notes)
script.foldStructuredResults()
assert noteField.get(script) == notes
'''
        + "assert notes.contains(" + literal(expected_fragment) + ")\n"
    )
    if forbidden:
        body += "assert !notes.contains(" + literal(forbidden) + ")\n"
    body += r'''
if (failure.message != null && failure.message.size() == 2000) {
    assert notes.endsWith('x' * 500)
    assert !notes.endsWith('x' * 501)
}
def skipField = script.getClass().getDeclaredField('SKIPLIST_FILES_BUF')
skipField.setAccessible(true)
assert script.formatSkippedTestLinks(skipField.get(script)) ==
    '📋 [Module skips and cases not reached](https://jenkins.example/job/nd/124/artifact/skipped_tests_build_124.txt)'

// Execute the real post-notification DSL with HTTP sending replaced locally.
def sent = []
script.metaClass.stages = { Closure ignored -> null }
script.metaClass.post = { Closure work -> work.call() }
script.metaClass.always = { Closure work -> work.call() }
script.metaClass.success = { Closure ignored -> null }
script.metaClass.failure = { Closure ignored -> null }
script.metaClass.cleanup = { Closure ignored -> null }
script.metaClass.sendWebexNotificationMessages = { Object messages -> sent.add(messages.join('\n')) }
script.run()
assert sent.size() == 1
assert sent[0].contains('Test cases passed: 0')
assert sent[0].contains('Test cases failed: 0')
assert sent[0].contains('Build result: FAILURE')
assert !sent[0].contains('Execution/reporting notes:')
assert !sent[0].contains(notes.trim())
assert sent[0].contains('DETAILED TEST RESULTS:')
'''
    groovy_runner(body)
