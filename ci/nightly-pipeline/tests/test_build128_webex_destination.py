"""Exercise the real Webex sender without credentials, HTTP or Jenkins access."""
import json
import os
from pathlib import Path
import re
import subprocess
import shutil

import pytest

from test_five_issue_pipeline_fixes import PRELUDE

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script",)
EXPECTED_SELECTION = {"Jenkinsfile_nd_jenkins_script": "PUBLIC"}


def rooms(source):
    return dict(re.findall(r"""^def\s+(WEBEX_ROOM_ID_(?:PUBLIC|PRIVATE))\s*=\s*["']([^"']+)["']""",
                           source, re.M))


@pytest.mark.parametrize("variant", VARIANTS)
def test_declared_room_selector_preserves_the_intended_destination(variant):
    canonical = rooms((ROOT / VARIANTS[0]).read_text())
    source = (ROOT / variant).read_text()
    definitions = rooms(source)
    assert definitions == canonical
    selected = re.search(r'^\s*WEBEX_ROOM_ID\s*=\s*"\$\{([^}]+)\}"', source, re.M).group(1)
    assert selected in definitions
    assert selected == "WEBEX_ROOM_ID_" + EXPECTED_SELECTION[variant]
    assert definitions[selected] == canonical[selected]
    assert canonical["WEBEX_ROOM_ID_PUBLIC"] != canonical["WEBEX_ROOM_ID_PRIVATE"]


@pytest.fixture(scope="module", params=VARIANTS)
def sender(request, tmp_path_factory):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA") or shutil.which("java") or "")
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", ""))
    if not java.is_file() or not jar.is_file():
        pytest.skip("Set ND_WEBEX_TEST_JAVA and ND_WEBEX_TEST_GROOVY for sender execution")
    directory = tmp_path_factory.mktemp("build128-webex")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        harness = directory / f"sender-{sequence}.groovy"
        harness.write_text(PRELUDE + "\n" + MOCK_DELIVERY + "\n" + body + '\nprintln("CHECK_PASSED")\n')
        result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain",
                                 str(harness), str(ROOT / request.param)],
                                text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout

    return run


MOCK_DELIVERY = r'''
def requests = []
int credentialBindings = 0
int responseStatus = 200
script.metaClass.string = { Map options -> options }
script.metaClass.withCredentials = { List bindings, Closure body ->
    credentialBindings++
    assert bindings == [[credentialsId: 'ANSIBLE_WEBEX_TOKEN', variable: 'WEBEX_TOKEN']]
    script.binding.env.WEBEX_TOKEN = 'fixture-token-sensitive'
    try { return body.call() }
    finally { script.binding.env.remove('WEBEX_TOKEN') }
}
script.metaClass.httpRequest = { Map options ->
    requests.add(options)
    assert options.customHeaders[0].maskValue == true
    assert options.customHeaders[0].value == 'Bearer fixture-token-sensitive'
    [status: responseStatus, content: 'fixture-sensitive-response-body']
}
'''


def literal(value):
    encoded = json.dumps(value).replace("\\", "\\\\").replace("'", "\\'")
    return "script.parseReportingJson('" + encoded + "')"


def test_invalid_destinations_cannot_reach_serialization_credentials_or_http(sender):
    invalid = [None, "", " \t\n ", "null", " NULL ", "undefined", " Undefined ",
               "$" + "{WEBEX_ROOM_ID_PUBLIC}", "{{ missing_room }}"]
    sender("def invalid = " + literal(invalid) + "\n" + r'''
script.metaClass.writeReportingJson = { Object ignored ->
    throw new AssertionError('Invalid room reached JSON serialization')
}
invalid.each { room ->
    script.binding.env.WEBEX_ROOM_ID = room
    def caught = null
    try { script.sendWebexNotificationMessages(['fixture report']) }
    catch (IllegalStateException failure) { caught = failure }
    assert caught != null
    assert caught.message.contains('NDP_WEBEX_ROOM_INVALID')
}
assert credentialBindings == 0
assert requests.isEmpty()
''')


@pytest.mark.parametrize("room", ["12345678-1234-4000-8000-123456789abc", "fixture-opaque-room"])
def test_valid_destination_is_trimmed_and_delivered_without_changing_its_identity(sender, room):
    sender("def expectedRoom = " + literal(room) + "\n" + r'''
script.binding.env.WEBEX_ROOM_ID = ' \t' + expectedRoom + '\n'
script.sendWebexNotificationMessages(['fixture report'])
assert requests.size() == 1
assert credentialBindings == 1
def payload = script.parseReportingJson(requests[0].requestBody)
assert payload.roomId == expectedRoom
assert payload.markdown == 'fixture report'
assert logs.any { it.startsWith('NDP_WEBEX_NOTIFICATION_SENT: part 1/1') }
assert !logs.join('\n').contains('fixture-token-sensitive')
''')


def test_404_gives_a_safe_actionable_diagnosis_without_using_another_room(sender):
    sender(r'''
def room = 'fixture-room-sensitive'
script.binding.env.WEBEX_ROOM_ID = room
responseStatus = 404
def caught = null
try { script.sendWebexNotificationMessages(['fixture report']) }
catch (IllegalStateException failure) { caught = failure }
assert caught != null
assert requests.size() == 1
assert script.parseReportingJson(requests[0].requestBody).roomId == room
def diagnosis = caught.message + '\n' + logs.join('\n')
assert diagnosis.contains('NDP_WEBEX_ROOM_UNAVAILABLE')
assert diagnosis.contains('404')
assert diagnosis.toLowerCase().contains('room')
assert diagnosis.toLowerCase().contains('bot')
assert !diagnosis.contains(room)
assert !diagnosis.contains('fixture-token-sensitive')
assert !diagnosis.contains('fixture-sensitive-response-body')
assert !logs.any { it.startsWith('NDP_WEBEX_NOTIFICATION_SENT:') }
''')


def test_other_http_errors_remain_failures_without_leaking_response_body(sender):
    sender(r'''
script.binding.env.WEBEX_ROOM_ID = 'fixture-room-sensitive'
[400, 401, 403, 429, 500].each { code ->
    responseStatus = code
    def caught = null
    try { script.sendWebexNotificationMessages(['fixture report']) }
    catch (IllegalStateException failure) { caught = failure }
    assert caught != null && caught.message.contains(code.toString())
    assert !caught.message.contains('fixture-sensitive-response-body')
}
assert requests.size() == 5
assert !logs.any { it.startsWith('NDP_WEBEX_NOTIFICATION_SENT:') }
''')


def test_actual_post_does_not_repeat_http_with_an_unresolved_destination(sender):
    sender(r'''
script.binding.env.WEBEX_ROOM_ID = 'null'
script.metaClass.pipeline = { Closure body -> body.call() }
for (def name : ['agent', 'parameters', 'environment', 'options', 'stages', 'cleanup']) {
    script.metaClass."$name" = { Closure ignored -> null }
}
script.metaClass.post = { Closure body -> body.call() }
script.metaClass.always = { Closure body -> body.call() }
script.metaClass.script = { Closure body -> body.call() }
script.metaClass.success = { Closure ignored -> null }
script.metaClass.failure = { Closure ignored -> null }
script.run()
assert credentialBindings == 0
assert requests.isEmpty()
assert logs.any { it.startsWith('NDP_WEBEX_REPORT_SIZE:') }
assert logs.any { it.startsWith('NDP_DETAILED_NOTIFICATION_FAILED:') }
assert logs.any { it.startsWith('NDP_WEBEX_NOTIFICATION_FAILED:') }
''')
