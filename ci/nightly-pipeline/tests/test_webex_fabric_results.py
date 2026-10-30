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
        java = str(candidates[0]) if candidates else shutil.which("java")
    jar = os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-webex-groovy-all-2.4.21.jar")
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
    table.readLines().findAll { it ==~ /^(OK|FAIL|SKIP|NOT_RUN|ERR)\\s+.*/ }
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
assert rows.size() == 4
assert rows.find { it[1] == 'nd_manage_policy' && it[2] == 'iBGP' } ==
    ['OK', 'nd_manage_policy', 'iBGP', '357', '0', '237', '23m 29s']
assert rows.find { it[1] == 'nd_manage_policy' && it[2] == 'eBGP' } ==
    ['NOT_RUN', 'nd_manage_policy', 'eBGP', '-', '-', '-', 'not scheduled']
assert rows.find { it[1] == 'nd_manage_networks' && it[2] == 'iBGP' } ==
    ['NOT_RUN', 'nd_manage_networks', 'iBGP', '-', '-', '-', 'not scheduled']
assert rows.find { it[1] == 'nd_manage_networks' && it[2] == 'eBGP' } ==
    ['FAIL', 'nd_manage_networks', 'eBGP', '271', '1', '266', '8m 0s']
assert rows.findAll { it[0] != 'NOT_RUN' }.collect { it[3] as int }.sum() == 628
assert rows.findAll { it[0] != 'NOT_RUN' }.collect { it[4] as int }.sum() == 1
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
assert rows.size() == 2
assert rows.collect { it[2] } == ['iBGP', 'eBGP']
assert rows.collect { it[3] } == ['101', '202']
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
assert rows.collect { it[2] } == scopes
assert rows.collect { it[3] as int }.sum() == (101..107).sum()
assert rows.every { it[0] == 'OK' }
""")


def test_legacy_nine_field_records_and_empty_summary(groovy_runner):
    groovy_runner(ROW_PARSER + """
def rows = resultRows(formatResultsTable('OK|legacy|VXLAN_EVPN_Fabric|4.3|14|0|2|1m 2s|'))
assert rows.size() == 2
assert rows[0] == ['OK', 'legacy', 'iBGP', '14', '0', '2', '1m 2s']
assert rows[1][0..2] == ['NOT_RUN', 'legacy', 'eBGP']
assert formatResultsTable(null) == '(no per-module results captured)'
assert formatResultsTable('  \\n  ') == '(no per-module results captured)'
""")


def test_multiple_nd_versions_keep_separate_fabric_pairs(groovy_runner):
    groovy_runner(ROW_PARSER + """
def table = formatResultsTable('OK|module|VXLAN_EVPN_Fabric|4.2|42|0|2|1m 0s||iBGP\\n' +
    'OK|module|VXLAN_EVPN_Fabric_eBGP|4.3|43|0|3|2m 0s||eBGP')
def rows = resultRows(table)
assert table.readLines().any { it.contains('Fabric') && it.contains('ND') }
assert rows.size() == 4
assert rows.findAll { it[3] == '4.2' }.collect { it[2] } == ['iBGP', 'eBGP']
assert rows.findAll { it[3] == '4.3' }.collect { it[2] } == ['iBGP', 'eBGP']
assert rows.find { it[0] == 'OK' && it[3] == '4.2' }[4] == '42'
assert rows.find { it[0] == 'OK' && it[3] == '4.3' }[4] == '43'
""")


def test_skipped_missing_output_and_parser_error_retain_scope(groovy_runner):
    groovy_runner(ROW_PARSER + """
def table = formatResultsTable('SKIP|skip_module|VXLAN_EVPN_Fabric|4.3|-|-|-|1m 0s|cable unavailable|iBGP\\n' +
    'NOT_RUN|missing_module|VXLAN_EVPN_Fabric_eBGP|4.3|0|0|0|not reached|output file missing|eBGP\\n' +
    'ERR|error_module|External_Connectivity_Fabric|4.3|-|-|-|-|no recap|External')
def rows = resultRows(table)
assert rows.size() == 5
assert rows.find { it[0] == 'SKIP' }[2] == 'iBGP'
assert table.contains('skip_module (iBGP): cable unavailable')
assert rows.find { it[1] == 'missing_module' && it[2] == 'eBGP' } ==
    ['NOT_RUN', 'missing_module', 'eBGP', '-', '-', '-', 'not reached']
assert rows.find { it[1] == 'error_module' }[0..2] == ['ERR', 'error_module', 'External']
assert rows.every { !(it[0] in ['OK', 'FAIL']) }
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
assert parts.size() > 1
assert parts.every {{ it.length() <= {limit} }}
assert parts.every {{ it.readLines().count {{ line -> line.trim().startsWith('```') }} % 2 == 0 }}
assert parts.every {{ part -> !resultRows(part) || part.readLines().any {{ line ->
    line.startsWith('Status') && line.contains('Module') && line.contains('Fabric') && line.contains('Passed')
}} }}
assert parts.every {{ it.contains('ND 4.3 NIGHTLY NOTIFICATION - Build 119') }}
assert parts.every {{ it.contains('ansible-nd branch: develop') && it.contains('ansible-nd commit: ' + sha) }}
assert parts.every {{ it.indexOf('ansible-nd branch:') < it.indexOf('ansible-nd commit:') }}
def joined = parts.join('\\n')
assert joined.count('Total Passed: 61830') == 1
assert joined.count('Total Failed: 0') == 1
assert joined.count('[All logs]') == 1
def rows = parts.collectMany {{ resultRows(it) }}
assert rows.size() == 120
assert rows.findAll {{ it[0] == 'OK' }}.size() == 60
assert rows.findAll {{ it[0] == 'NOT_RUN' }}.size() == 60
(1..60).each {{ i ->
    def name = "nd_interface_regression_module_${{i.toString().padLeft(2, '0')}}".toString()
    def matching = rows.findAll {{ it[1] == name }}
    assert matching.size() == 2
    assert matching.collect {{ it[2] }}.sort() == ['eBGP', 'iBGP']
    assert matching.find {{ it[0] == 'OK' }}[3] == (1000+i).toString()
    assert matching.find {{ it[0] == 'NOT_RUN' }}[3..5] == ['-', '-', '-']
}}
assert rows.findAll {{ it[0] == 'OK' }}.collect {{ it[3] as int }}.sum() == 61830
assert message == original
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
