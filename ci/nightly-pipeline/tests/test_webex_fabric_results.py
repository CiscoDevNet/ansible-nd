"""Execute the Jenkinsfile's real Groovy fabric reporting helpers offline.

Set ND_WEBEX_TEST_JAVA and ND_WEBEX_TEST_GROOVY to use a local JVM and Groovy
jar. The temporary verified runtime is also discovered when present. These
checks never invoke Jenkins, Ansible, or Webex.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


JENKINSFILE = Path(__file__).resolve().parents[1] / "Jenkinsfile_nd_jenkins_script"


@pytest.fixture(scope="module")
def source():
    return JENKINSFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def groovy_runner(source, tmp_path_factory):
    java = os.environ.get("ND_WEBEX_TEST_JAVA")
    if not java:
        candidates = list(Path("/private/tmp/nd-webex-runtime").glob("*/Contents/Home/bin/java"))
        candidates += list(Path("/private/tmp/nd-local-groovy-runtime").glob("*/Contents/Home/bin/java"))
        java = str(candidates[0]) if candidates else shutil.which("java")
    jar = os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar")
    if not java or not Path(jar).is_file():
        pytest.skip("A JVM and Groovy jar are required for actual Jenkins helper execution")

    start = source.index("def fabricScopeLabel(")
    end = source.index("/**\n * Escapes text that is shown in a Webex Markdown link label.", start)
    helpers = source[start:end]
    directory = tmp_path_factory.mktemp("webex-groovy")
    sequence = 0

    def run(body):
        nonlocal sequence
        sequence += 1
        script = directory / f"check_{sequence}.groovy"
        script.write_text(helpers + "\n" + body + '\nprintln("CHECK_PASSED")\n', encoding="utf-8")
        result = subprocess.run(
            [java, "-cp", jar, "groovy.ui.GroovyMain", str(script)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "CHECK_PASSED" in result.stdout
        return result.stdout

    return run


def groovy_json(value):
    """Pass fixtures as JSON data, without interpolating them as Groovy code."""
    payload = json.dumps(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"new groovy.json.JsonSlurper().parseText('{payload}')"


CONFIG = {"fabric_name": "VXLAN_EVPN_Fabric", "fabric_name_2": "External_Connectivity_Fabric", "version": "4.3"}
PAIRS = [
    {"id": "advanced", "fabric": "VXLAN_EVPN_Fabric", "type": "vxlanIbgp"},
    {"id": "external", "fabric": "External_Connectivity_Fabric", "type": "externalConnectivity"},
]


@pytest.mark.parametrize(("token", "scope", "fabric"), [
    ("nd_manage_networks", "eBGP", "VXLAN_EVPN_Fabric_eBGP"),
    ("nd_manage_networks.yaml", "eBGP", "VXLAN_EVPN_Fabric_eBGP"),
    ("nd_manage_policy", "iBGP", "VXLAN_EVPN_Fabric"),
    ("nd_vpc_pair.advanced", "iBGP", "VXLAN_EVPN_Fabric"),
    ("nd_vpc_pair.external", "External", "External_Connectivity_Fabric"),
    ("nd_manage_l3out", "iBGP+External", "VXLAN_EVPN_Fabric, External_Connectivity_Fabric"),
    ("nd_manage_links", "iBGP+External", "VXLAN_EVPN_Fabric, External_Connectivity_Fabric"),
    ("nd_manage_fabric", "Mixed", "disposable fabric matrix"),
    ("nd_manage_fabric_group_vxlan", "Logical", "logical fabric groups"),
    ("nd_manage_fabric_group_members", "Logical", "logical fabric groups"),
    ("nd_local_user", "Controller", "controller"),
])
def test_target_context_uses_effective_fabric(groovy_runner, token, scope, fabric):
    groovy_runner(f"""
def actual = resultContextForTarget({groovy_json(CONFIG)}, {groovy_json(token)},
    'VXLAN_EVPN_Fabric_eBGP', {groovy_json(PAIRS)})
assert actual == {groovy_json({'scope': scope, 'fabric': fabric})}
""")


def test_scope_labels_and_unknown_context_do_not_claim_a_fabric(groovy_runner):
    groovy_runner("""
assert fabricScopeLabel('vxlanIbgp') == 'iBGP'
assert fabricScopeLabel('vxlanEbgp') == 'eBGP'
assert fabricScopeLabel('externalConnectivity') == 'External'
assert fabricScopeLabel(null) == 'Unknown'
assert fabricScopeLabel('custom-fabric') == 'Unknown'
assert fabricScopeLabel('eBGP+External') == 'eBGP+External'
assert resultContextForTarget([fabric_name: 'custom-fabric'], 'nd_manage_policy').scope == 'Unknown'
assert resultContextForTarget([fabric_name: 'custom-fabric', vpc_pair_fabric_type: 'vxlanIbgp'],
    'nd_manage_policy').scope == 'iBGP'
assert resultContextForTarget([fabric_name: 'VXLAN_EVPN_Fabric'], 'nd_vpc_pair.missing').scope == 'Unknown'
assert resultContextForTarget([fabric_name: 'VXLAN_EVPN_Fabric_eBGP'], 'nd_manage_links').scope == 'eBGP+External'
""")


ROW_PARSER = """
def resultRows = { table ->
    boolean fenced = false
    table.readLines().findAll { line ->
        if (line.trim().startsWith('```')) { fenced = !fenced; return false }
        fenced && line.trim() && !line.startsWith('Module ') && !line.startsWith('---')
    }
        .collect { it.trim().split(/\\s{2,}/).toList() }
}
"""


def test_missing_counterparts_have_no_counts_or_duplicate_actual_result(groovy_runner):
    groovy_runner(ROW_PARSER + """
def summary = 'OK|nd_manage_policy|VXLAN_EVPN_Fabric|4.3|357|0|237|23m 29s||iBGP\\n' +
    'FAIL|nd_manage_networks|VXLAN_EVPN_Fabric_eBGP|4.3|271|1|266|8m 0s||eBGP'
def original = summary
def table = formatResultsTable(summary)
def rows = resultRows(table)
assert rows.size() == 2
assert rows.find { it[0] == 'nd_manage_policy' } ==
    ['nd_manage_policy', 'OK', '357', '0', '237', '23m 29s', 'NOT_RUN', '-', '-', '-', 'not scheduled']
assert rows.find { it[0] == 'nd_manage_networks' } ==
    ['nd_manage_networks', 'NOT_RUN', '-', '-', '-', 'not scheduled', 'FAIL', '271', '1', '266', '8m 0s']
assert rows[0][2].toInteger() + rows[1][7].toInteger() == 628
assert rows[0][3].toInteger() + rows[1][8].toInteger() == 1
assert !table.contains('VXLAN_EVPN_Fabric')
assert !table.readLines().any { it.startsWith('Module') && it.contains('Fabric') }
assert summary == original
assert !table.contains('Passed/Failed/Skipped =')
assert !table.contains('Mixed/shared rows')
assert !table.contains('? = case count')
""")


def test_both_actual_fabrics_render_once_without_synthetic_rows(groovy_runner):
    groovy_runner(ROW_PARSER + """
def table = formatResultsTable('OK|nd_manage_policy|VXLAN_EVPN_Fabric|4.3|101|0|5|1m 0s||iBGP\\n' +
    'FAIL|nd_manage_policy|VXLAN_EVPN_Fabric_eBGP|4.3|202|1|6|2m 0s||eBGP')
def rows = resultRows(table)
assert rows == [['nd_manage_policy', 'OK', '101', '0', '5', '1m 0s', 'FAIL', '202', '1', '6', '2m 0s']]
assert !table.contains('VXLAN_EVPN_Fabric')
assert !table.contains('not scheduled')
""")


def test_shared_mixed_logical_and_controller_results_are_not_split(groovy_runner):
    groovy_runner(ROW_PARSER + """
def scopes = ['iBGP+External', 'eBGP+External', 'External', 'Mixed', 'Logical', 'Controller', 'Unknown']
def raw = scopes.withIndex().collect { scope, i ->
    "OK|module_${i}|actual-fabric|4.3|${101+i}|0|2|1m 0s||${scope}"
}.join('\\n')
def rows = resultRows(formatResultsTable(raw))
assert rows.size() == scopes.size()
assert rows[0][2] == '101' && rows[1][7] == '102'
assert rows.drop(2).collect { it[12] as int }.sum() == (103..107).sum()
assert rows.drop(2).every { it[1] == 'NOT_RUN' && it[6] == 'NOT_RUN' && it[11] == 'OK' }
assert !rows.flatten().any { it in ['VXLAN+External', 'External', 'Mixed', 'Logical', 'Controller', 'Unknown'] }
""")


def test_legacy_nine_field_records_and_empty_summary(groovy_runner):
    groovy_runner(ROW_PARSER + """
def rows = resultRows(formatResultsTable('OK|legacy|VXLAN_EVPN_Fabric|4.3|14|0|2|1m 2s|'))
assert rows == [['legacy', 'OK', '14', '0', '2', '1m 2s', 'NOT_RUN', '-', '-', '-', 'not scheduled']]
assert !rows.flatten().contains('VXLAN_EVPN_Fabric')
assert formatResultsTable(null) == '(no per-module results captured)'
assert formatResultsTable('  \\n  ') == '(no per-module results captured)'
""")


def test_multiple_nd_versions_keep_separate_fabric_pairs(groovy_runner):
    groovy_runner(ROW_PARSER + """
def table = formatResultsTable('OK|module|VXLAN_EVPN_Fabric|4.2|42|0|2|1m 0s||iBGP\\n' +
    'OK|module|VXLAN_EVPN_Fabric_eBGP|4.3|43|0|3|2m 0s||eBGP')
def rows = resultRows(table)
assert table.readLines().any { it.startsWith('Module') && it.contains('ND') && !it.contains('Fabric') }
assert rows.size() == 2
assert rows.find { it[1] == '4.2' }[2..7] == ['OK', '42', '0', '2', '1m 0s', 'NOT_RUN']
assert rows.find { it[1] == '4.3' }[7..11] == ['OK', '43', '0', '3', '2m 0s']
assert !table.contains('VXLAN_EVPN_Fabric')
""")


def test_skipped_missing_output_and_parser_error_retain_scope(groovy_runner):
    groovy_runner(ROW_PARSER + """
def table = formatResultsTable('SKIP|skip_module|VXLAN_EVPN_Fabric|4.3|-|-|-|1m 0s|cable unavailable|iBGP\\n' +
    'NOT_RUN|missing_module|VXLAN_EVPN_Fabric_eBGP|4.3|0|0|0|not reached|output file missing|eBGP\\n' +
    'ERR|error_module|External_Connectivity_Fabric|4.3|-|-|-|-|no recap|External')
def rows = resultRows(table)
assert rows.size() == 3
assert rows.find { it[0] == 'skip_module' }[1] == 'SKIP'
assert table.contains('skip_module (iBGP): cable unavailable')
assert rows.find { it[0] == 'missing_module' }[6..10] == ['NOT_RUN', '-', '-', '-', 'not reached']
assert rows.find { it[0] == 'error_module' }[11] == 'ERR'
assert rows.every { !(it[1] in ['OK', 'FAIL']) && !(it[6] in ['OK', 'FAIL']) }
assert !table.contains('VXLAN_EVPN_Fabric') && !table.contains('External_Connectivity_Fabric')
""")


@pytest.mark.parametrize("limit", [1200, 7000])
def test_chunking_keeps_all_rows_once_balances_fences_and_preserves_identity(groovy_runner, limit):
    groovy_runner(ROW_PARSER + f"""
def sha = '0123456789abcdef0123456789abcdef01234567'
def header = "ND 4.3 NIGHTLY NOTIFICATION - Build 119\\n" +
    "ansible-nd branch: develop\\nansible-nd commit: ${{sha}}\\n\\n"
def raw = (1..60).collect {{ i ->
    def scope = i % 2 ? 'iBGP' : 'eBGP'
    "OK|nd_interface_regression_module_${{i.toString().padLeft(2, '0')}}|fabric|4.3|${{1000+i}}|0|${{i}}|1m 0s||${{scope}}"
}}.join('\\n')
def message = header + 'Total Passed: 61830\\nTotal Failed: 0\\n\\n' +
    formatResultsTable(raw) + '\\n[All logs](https://jenkins.example/artifact/logs.zip)'
def original = message
def parts = splitWebexMessage(message, header, {limit})
assert message.length() > {limit} ? parts.size() > 1 : parts == [message]
assert parts.every {{ it.length() <= {limit} }}
assert parts.every {{ it.readLines().count {{ line -> line.trim().startsWith('```') }} % 2 == 0 }}
assert parts.every {{ part -> !resultRows(part) || part.readLines().any {{ line ->
    line.startsWith('Module') && !line.contains('Fabric') && line.contains('iBGP') && line.contains('eBGP')
}} }}
assert parts.every {{ it.contains('ND 4.3 NIGHTLY NOTIFICATION - Build 119') }}
assert parts.every {{ it.contains('ansible-nd branch: develop') && it.contains('ansible-nd commit: ' + sha) }}
assert parts.every {{ it.indexOf('ansible-nd branch:') < it.indexOf('ansible-nd commit:') }}
def joined = parts.join('\\n')
assert joined.count('Total Passed: 61830') == 1
assert joined.count('Total Failed: 0') == 1
assert joined.count('[All logs]') == 1
def rows = parts.collectMany {{ resultRows(it) }}
assert rows.size() == 60
assert rows.count {{ it[1] == 'OK' }} == 30
assert rows.count {{ it[6] == 'OK' }} == 30
(1..60).each {{ i ->
    def name = "nd_interface_regression_module_${{i.toString().padLeft(2, '0')}}".toString()
    def matching = rows.findAll {{ it[0] == name }}
    assert matching.size() == 1
    def actual = i % 2 ? 1 : 6
    def missing = i % 2 ? 6 : 1
    assert matching[0][actual] == 'OK'
    assert matching[0][actual + 1] == (1000+i).toString()
    assert matching[0][missing..missing + 4] == ['NOT_RUN', '-', '-', '-', 'not scheduled']
}}
assert rows.collect {{ (it[1] == 'OK' ? it[2] : it[7]) as int }}.sum() == 61830
assert message == original
""")


def test_shared_rounds_share_module_row_without_combining_counts(groovy_runner):
    groovy_runner(ROW_PARSER + """
def raw = 'FAIL|shared_module|external|4.3|3|1|0|1m||External|eBGP\\n' +
    'OK|shared_module|external|4.3|7|0|2|2m||External|iBGP'
def original = raw
assert resultRows(formatResultsTable(raw)) == [
    ['shared_module', 'OK', '7', '0', '2', '2m', 'FAIL', '3', '1', '0', '1m']]
assert raw == original
""")


def test_short_messages_are_unchanged_and_diagnostic_lines_are_not_truncated(groovy_runner):
    groovy_runner("""
assert splitWebexMessage('short report', 'unused', 7000) == ['short report']
def longLine = 'x' * 15000
def parts = splitWebexMessage(longLine, 'continuation\\n', 1000)
assert parts.size() > 1
assert parts.every { it.length() <= 1000 }
assert parts.collect { it.count('x') }.sum() == 15000
""")


def test_structured_summary_and_unstarted_round_rows_retain_effective_scope(source):
    fold = source.split("def foldStructuredResults(", 1)[1].split("\n}\n", 1)[0]
    assert '"${row.version_id}|${row.module}|${row.run_id}".toString()' in fold
    assert "MODULE_ACTIVITY_RESULTS[key] = row" in fold
    assert '${row.module} (${row.scope}; ${row.round_label} round)|${row.artifact}' in fold
    assert "resultContextForTarget(ndfcConfig, target[0], networkFabricName, vpcPairRows)" in source
    missing = source.split("def recordUnstartedRound(", 1)[1].split("\n}\n", 1)[0]
    assert "fabric: context.fabric, scope: context.scope" in missing
    assert "result: 'NOT_RUN', coverage: 'UNKNOWN', counts: [:], case_totals: [:]" in missing
    assert "MODULE_ACTIVITY_RESULTS.keySet().any" in missing


def test_notification_sends_each_bounded_part_and_preserves_branch_commit(source):
    assert "splitWebexMessage(message, continuationHeader, WEBEX_SAFE_MESSAGE_LIMIT)" in source
    assert "sendWebexNotificationMessages(notificationMessages)" in source
    delivery = source.split("def sendWebexNotificationMessages(messages)", 1)[1].split("\ndef minimalBuildNotification(", 1)[0]
    assert "for (int messageIndex = 0; messageIndex < messages.size(); messageIndex++)" in delivery
    assert "def notificationMessage = messages[messageIndex]" in delivery
    assert "markdown: notificationMessage.toString()" in delivery
    assert "writeReportingJson(" in delivery
    assert "httpRequest(" in delivery
    header = source.split("def continuationHeader =", 1)[1].split("def notificationMessages", 1)[0]
    assert "${selectedBranch}" in header and "${selectedCommit}" in header
    assert header.index("${selectedBranch}") < header.index("${selectedCommit}")
