"""Offline HTTP contract tests; no controller or switch is contacted."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types

import pytest
import requests

SPEC = importlib.util.spec_from_file_location(
    "switch_discovery_diagnostic", Path(__file__).resolve().parents[1] / "tools" / "nd_switch_discovery_diagnostic.py")
DIAGNOSTIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTIC)
ENV = dict(zip(DIAGNOSTIC.CREDENTIALS, ("nd-user-secret", 'nd-pass-"\\secret', "sw-user-secret", 'sw-pass-"\\secret')))
TOKEN = "bearer-token-secret"
IP, SERIAL = DIAGNOSTIC.DEFAULT_SEED
DISCOVERY = "https://192.0.2.117/api/v1/manage/fabrics/VXLAN_EVPN_Fabric/actions/shallowDiscovery"


class Response:
    def __init__(self, body, status=200):
        self.body, self.status_code = body, status

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class Client:
    def __init__(self, discovery, inventory=None, login=None):
        self.responses = [login or Response({"jwttoken": TOKEN}), discovery]
        if inventory is not None:
            self.responses.append(inventory)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def record(**changes):
    return {"ip": IP, "serialNumber": SERIAL, "status": "manageable", **changes}


def run(capsys, response, args=(), env=None, **client_options):
    client = Client(response, **client_options)
    code = DIAGNOSTIC.main(args, environ=ENV if env is None else env, session=client)
    raw = capsys.readouterr().out
    return code, json.loads(raw), raw, client


def test_success_calls_only_login_and_discovery_with_exact_source_payload(capsys):
    code, report, _, client = run(capsys, Response({"switches": [record()]}))
    assert code == 0 and report["ok"]
    assert [(method, url) for method, url, _ in client.calls] == [("POST", "https://192.0.2.117/login"), ("POST", DISCOVERY)]
    assert client.calls[0][2]["json"] == {"userName": ENV["NDFC_USER"], "userPasswd": ENV["NDFC_PASSWORD"], "domain": "local"}
    assert client.calls[1][2]["json"] == {"seedIpCollection": [IP], "maxHop": 0, "platformType": "nx-os", "snmpV3AuthProtocol": "md5",
                                         "username": ENV["ANSIBLE_NXOS_SWITCH_USERNAME"], "password": ENV["ANSIBLE_NXOS_SWITCH_PASSWORD"]}
    assert client.calls[1][2]["headers"]["Authorization"] == "Bearer " + TOKEN
    assert all(call[2]["verify"] is True and call[2]["allow_redirects"] is False for call in client.calls)
    assert client.trust_env is False


@pytest.mark.parametrize("status", ["ok", "alreadyManaged", "MANAGEABLE"])
def test_accepted_statuses_still_require_actual_identity(capsys, status):
    assert run(capsys, Response({"switches": [record(status=status)]}))[0] == 0


@pytest.mark.parametrize("status", ["notReachable", "notReacheable", "notAuthorized", "unauthorized", "notManageable", "unknown", None, {}, 1])
def test_failure_statuses_cannot_be_bypassed_by_a_known_serial(capsys, status):
    code, report, _, _ = run(capsys, Response({"switches": [record(status=status, statusReason="diagnostic reason")]}))
    assert code == 1 and not report["ok"]
    assert "ND did not confirm manageability" in report["results"][0]["errors"]


@pytest.mark.parametrize("serial", [None, "", "   ", "DIFFERENT", 42, {}])
def test_serial_omission_or_mismatch_never_uses_the_expected_serial(capsys, serial):
    code, report, _, _ = run(capsys, Response({"switches": [record(serialNumber=serial)]}))
    assert code == 1 and not report["results"][0]["ok"]


@pytest.mark.parametrize("body", [{}, {"switches": None}, {"switches": {}}, {"switches": [None]},
                                  {"switches": []}, {"switches": [record(), record()]},
                                  {"switches": [record(ip="10.1.1.1")]}, {"switches": [record(ip=None)]},
                                  {"switches": [record(ip={})]}, {"switches": [record(ip=[IP])]},
                                  {"switches": [record(statusReason={})]}, {"switches": [record()], "warning": {}}])
def test_malformed_missing_duplicate_or_foreign_results_fail(capsys, body):
    assert run(capsys, Response(body))[0] == 1


def test_both_seeds_are_independently_checked_and_optional_inventory_is_get_only(capsys):
    second = {"seedIp": "192.0.2.196", "serialNumber": "SERIAL00002", "status": "ok"}
    args = ["--seed", IP + "=" + SERIAL, "--seed", "192.0.2.196=SERIAL00002", "--inventory"]
    inventory = Response({"switches": [{"fabricManagementIp": IP, "serialNumber": SERIAL, "password": "do-not-print"}]})
    code, report, raw, client = run(capsys, Response({"DATA": {"switches": [record(), second]}}), args, inventory=inventory)
    assert code == 0 and len(report["results"]) == 2
    assert [(method, url) for method, url, _ in client.calls][-1] == ("GET", "https://192.0.2.117/api/v1/manage/inventory/switches?max=10000")
    assert "do-not-print" not in raw


def test_all_credentials_and_bearer_token_are_redacted_even_when_json_escaped(capsys):
    echoed = " ".join([*ENV.values(), TOKEN])
    code, report, raw, _ = run(capsys, Response({"switches": [record(statusReason=echoed)], "warning": echoed}))
    assert code == 0 and "[REDACTED]" in raw
    for secret in [*ENV.values(), TOKEN]:
        assert secret not in raw and json.dumps(secret)[1:-1] not in raw
    assert report["warning"].count("[REDACTED]") == 5


@pytest.mark.parametrize("response", [Response({"password": ENV["NDFC_PASSWORD"]}, 401), Response({}, 302),
                                     Response(ValueError("RAW " + ENV["NDFC_PASSWORD"])),
                                     requests.ConnectionError("RAW " + ENV["NDFC_PASSWORD"])])
def test_http_redirect_parse_and_transport_failures_do_not_print_raw_errors(capsys, response):
    code, report, raw, _ = run(capsys, response)
    assert code == 1 and report["error"]
    assert "RAW" not in raw and ENV["NDFC_PASSWORD"] not in raw


@pytest.mark.parametrize("error", [{"code": 500, "message": "controller error"}, {"error": {"code": 500}}])
def test_embedded_controller_errors_cannot_be_mistaken_for_success(capsys, error):
    code, report, _, _ = run(capsys, Response({"switches": [record()], **error}))
    assert code == 1 and report["stage"] == "discovery" and report["error"]


@pytest.mark.parametrize("login", [Response({}, 401), Response({}), Response({"jwttoken": {}})])
def test_failed_login_prevents_discovery(capsys, login):
    code, report, _, client = run(capsys, Response({"switches": [record()]}), login=login)
    assert code == 1 and report["stage"] == "login" and len(client.calls) == 1


@pytest.mark.parametrize("fabric", ["test/../../switchActions/remove", "..", "."])
def test_fabric_name_cannot_select_a_different_endpoint(capsys, fabric):
    code, _, _, client = run(capsys, Response({"switches": [record()]}), ["--fabric", fabric])
    assert code == 1 and not client.calls


@pytest.mark.parametrize("args,env,expected", [([], ENV, True), ([], {**ENV, "ND_VERIFY_CERTS": "false"}, False),
                                             (["--ca-bundle", "/tmp/company-ca.pem"], {**ENV, "ND_VERIFY_CERTS": "false"}, "/tmp/company-ca.pem")])
def test_certificate_policy_defaults_to_verification_and_ca_bundle_takes_priority(capsys, args, env, expected):
    code, _, _, client = run(capsys, Response({"switches": [record()]}), args, env)
    assert code == 0 and all(call[2]["verify"] == expected for call in client.calls)


@pytest.mark.parametrize("args,env", [([], {}), ([], {**ENV, "ND_VERIFY_CERTS": "invalid"}),
                                     (["--host", "user:pass@unexpected/path"], ENV),
                                     (["--host", "host:invalid-port"], ENV),
                                     (["--seed", IP + "=" + SERIAL, "--seed", IP + "=OTHER"], ENV)])
def test_invalid_configuration_stops_before_any_http(capsys, args, env):
    code, _, _, client = run(capsys, Response({}), args, env)
    assert code == 1 and not client.calls


@pytest.fixture
def jenkins_probe(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "Jenkinsfile_leaf1_discovery_diagnostic"
    source = path.read_text().split("<<'PY'", 1)[1].split("\n", 1)[1].split("\nPY\n", 1)[0]
    tree = ast.parse(source)
    assert any(isinstance(node, ast.FunctionDef) and node.name == "main" for node in tree.body)
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    module = types.ModuleType("jenkins_discovery_probe")
    exec(compile(tree, str(path), "exec"), module.__dict__)
    return module


def deep_observation():
    return {
        "ping": {"ok": True}, "tcp22_open": True,
        "ssh": {"inventory": {"ok": True, "serial_matches_expected": True},
                "license_host_id": {"ok": True}},
        "snmp": {"serial_matches_expected": True, "attempts": []},
        "nd": {"identity_confirmed": True},
    }


def test_jenkins_missing_tools_are_unavailable_not_device_failures(jenkins_probe, monkeypatch):
    monkeypatch.setattr(jenkins_probe.shutil, "which", lambda name: None)
    monkeypatch.setattr(jenkins_probe.subprocess, "run", lambda *args, **kwargs: pytest.fail("must not execute"))
    result = jenkins_probe.run_command(["ping", "-c", "1", IP], timeout=4)
    assert result["error"] == "tool_missing" and result["tool"] == "ping"
    result = jenkins_probe.snmp_identity(IP, SERIAL)
    assert result["error"] == "tool_missing" and result["serial_matches_expected"] is None


def test_jenkins_snmp_discovers_chassis_index_and_keeps_password_off_argv(jenkins_probe, monkeypatch):
    calls, directories = [], []

    def command(arguments, timeout, env=None):
        assert ENV["ANSIBLE_NXOS_SWITCH_PASSWORD"] not in " ".join(arguments)
        assert "-A" not in arguments and "-X" not in arguments
        config = Path(env["SNMPCONFPATH"]) / "snmp.conf"
        directories.append(config.parent)
        assert config.parent.stat().st_mode & 0o777 == 0o700
        assert config.stat().st_mode & 0o777 == 0o600
        assert "defAuthPassphrase" in config.read_text()
        calls.append(arguments)
        output = jenkins_probe.ENTITY_CLASS_OID + ".149 3\n" if arguments[0] == "snmpwalk" else '"' + SERIAL + '"\n'
        return {"ok": True, "stdout": output, "stderr": "", "returncode": 0}

    monkeypatch.setattr(jenkins_probe.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(jenkins_probe, "run_command", command)
    result = jenkins_probe.snmp_identity(IP, SERIAL)
    assert result["serial_matches_expected"] is True
    assert calls[1][0] == "snmpget" and calls[1][-1] == jenkins_probe.ENTITY_SERIAL_OID + ".149"
    assert all(not directory.exists() for directory in directories)


def test_jenkins_ssh_rejects_any_non_show_command(jenkins_probe):
    with pytest.raises(ValueError, match="read-only"):
        jenkins_probe.ssh_show(IP, "configure terminal")


@pytest.mark.parametrize("events,ok,error", [
    ([(0, "login banner"), (2, "NAME: chassis SN: " + SERIAL)], True, None),
    ([(0, ""), (0, "")], False, "ssh_authentication_failed"),
    ([(3, "still connecting")], False, "ssh_timeout"),
    ([(2, "% Invalid command")], False, None),
])
def test_jenkins_ssh_password_is_sent_only_through_pty(jenkins_probe, monkeypatch, events, ok, error):
    sent, spawned, closed = [], [], []
    responses = iter(events)

    class Child:
        before = ""
        exitstatus = 0

        def expect(self, patterns, timeout):
            assert 0 < timeout <= 20
            choice, self.before = next(responses)
            return choice

        def sendline(self, value):
            sent.append(value)

        def close(self, force=False):
            closed.append(force)

    def spawn(executable, arguments, **kwargs):
        spawned.append((executable, arguments, kwargs))
        assert ENV["ANSIBLE_NXOS_SWITCH_PASSWORD"] not in arguments
        return Child()

    class ProbeException(Exception):
        pass

    fake = types.SimpleNamespace(spawn=spawn, EOF=object(), TIMEOUT=object(), ExceptionPexpect=ProbeException)
    monkeypatch.setitem(sys.modules, "pexpect", fake)
    monkeypatch.setattr(jenkins_probe.shutil, "which", lambda name: "/usr/bin/" + name)
    result = jenkins_probe.ssh_show(IP, "show inventory")
    assert result["ok"] is ok and result.get("error") == error
    assert spawned[0][0] == "ssh" and spawned[0][1][-1] == "show inventory"
    assert spawned[0][2]["echo"] is False
    assert sent == ([ENV["ANSIBLE_NXOS_SWITCH_PASSWORD"]] if events[0][0] == 0 else [])
    assert closed[-1] is True


def test_jenkins_command_timeout_is_bounded_and_does_not_echo_exception(jenkins_probe, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("SECRET " + ENV["ANSIBLE_NXOS_SWITCH_PASSWORD"], 4)

    monkeypatch.setattr(jenkins_probe.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(jenkins_probe.subprocess, "run", timeout)
    result = jenkins_probe.run_command(["ping", IP], timeout=4)
    assert result == {"ok": False, "error": "timeout", "timeout_seconds": 4}


@pytest.mark.parametrize("change,expected", [
    ({}, "identity_confirmed"),
    ({"ssh": {"inventory": {"ok": True, "serial_matches_expected": False}}}, "device_identity_missing_or_mismatch"),
    ({"snmp": {"serial_matches_expected": False}}, "snmp_identity_unconfirmed"),
    ({"nd": {"identity_confirmed": False}}, "nd_discovery_unconfirmed"),
    ({"snmp": {"error": "tool_missing", "serial_matches_expected": None}}, "probe_tool_missing"),
    ({"ssh": {"inventory": {"ok": False}}}, "ssh_identity_unconfirmed"),
])
def test_jenkins_probe_localizes_only_the_supported_layer(jenkins_probe, change, expected):
    observation = deep_observation()
    observation.update(change)
    assert jenkins_probe.classify(observation) == expected


def test_jenkins_samples_both_peers_twice_and_retains_eight_switch_sweep(jenkins_probe, monkeypatch, capsys):
    probes, discoveries, delays = [], [], []

    def probe_devices():
        probes.append(True)
        return {switch["ip"]: deep_observation() for switch in jenkins_probe.DEEP_SEEDS}

    def discover(session, fabric, switches):
        discoveries.append((fabric, [switch["ip"] for switch in switches]))
        return {switch["ip"]: {
            "identity_confirmed": len(probes) > 1 or switch["ip"] != IP,
            "snmp_protocol": "md5", "attempts": [{"statusReason": "first-sample reason"}],
        } for switch in switches}

    monkeypatch.setattr(jenkins_probe, "probe_devices", probe_devices)
    monkeypatch.setattr(jenkins_probe, "discover", discover)
    monkeypatch.setattr(jenkins_probe, "login", lambda session: None)
    monkeypatch.setattr(jenkins_probe, "tcp22_open", lambda ip: True)
    monkeypatch.setattr(jenkins_probe.time, "sleep", delays.append)
    assert jenkins_probe.main() == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(probes) == 2 and delays == [60]
    assert [len(seeds) for _, seeds in discoveries] == [6, 2, 2]
    summary = next(event for event in events if "roster_summary" in event)
    assert summary["confirmed"] == summary["total"] == 8
    comparison = next(event for event in events if "timing_comparison" in event)["timing_comparison"]
    assert comparison[IP]["timing"] == "recovered_between_samples"
    assert comparison["192.0.2.196"]["timing"] == "stable"


def test_jenkins_discovery_keeps_status_reason_and_retries_actual_identity(jenkins_probe, capsys):
    responses = [Response({"switches": [record(serialNumber="", statusReason="SNMP identity not ready")]}),
                 Response({"switches": [record(statusReason="ready")]})]
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return responses.pop(0)

    result = jenkins_probe.discover(types.SimpleNamespace(post=post), "VXLAN_EVPN_Fabric", jenkins_probe.DEEP_SEEDS[:1])
    assert result[IP]["identity_confirmed"] is True
    assert result[IP]["attempts"][0]["serialNumber"] == ""
    assert result[IP]["attempts"][0]["statusReason"] == "SNMP identity not ready"
    assert result[IP]["snmp_protocol"] == "sha"
    assert all(url == DISCOVERY and kwargs["allow_redirects"] is False for url, kwargs in calls)
    assert [kwargs["json"]["snmpV3AuthProtocol"] for _, kwargs in calls] == ["md5", "sha"]


def test_jenkins_deep_outputs_redact_escaped_credentials_and_token(jenkins_probe, capsys):
    jenkins_probe.secrets.append(TOKEN)
    jenkins_probe.emit({"ssh": {"stdout": " ".join([*ENV.values(), TOKEN])}})
    raw = capsys.readouterr().out
    assert json.loads(raw)["ssh"]["stdout"].count("<redacted>") == 5
    for secret in [*ENV.values(), TOKEN]:
        assert secret not in raw and json.dumps(secret)[1:-1] not in raw


def test_jenkins_second_sample_does_not_reuse_first_nd_success(jenkins_probe, monkeypatch, capsys):
    probes = []

    def probe_devices():
        probes.append(True)
        return {switch["ip"]: deep_observation() for switch in jenkins_probe.DEEP_SEEDS}

    def discover(session, fabric, switches):
        return {switch["ip"]: {"identity_confirmed": len(probes) == 1 or switch["ip"] != IP,
                               "snmp_protocol": "md5", "attempts": []} for switch in switches}

    monkeypatch.setattr(jenkins_probe, "probe_devices", probe_devices)
    monkeypatch.setattr(jenkins_probe, "discover", discover)
    monkeypatch.setattr(jenkins_probe, "login", lambda session: None)
    monkeypatch.setattr(jenkins_probe, "tcp22_open", lambda ip: True)
    monkeypatch.setattr(jenkins_probe.time, "sleep", lambda seconds: None)
    assert jenkins_probe.main() == 1
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    comparison = next(event for event in events if "timing_comparison" in event)["timing_comparison"]
    assert comparison[IP]["timing"] == "regressed_between_samples"
    summary = next(event for event in events if "roster_summary" in event)
    assert summary["confirmed"] == 7


def test_jenkins_shells_parse_and_redacted_artifact_is_archived():
    path = Path(__file__).resolve().parents[1] / "Jenkinsfile_leaf1_discovery_diagnostic"
    source = path.read_text()
    for block in source.split("sh '''")[1:]:
        shell = block.split("'''", 1)[0]
        result = subprocess.run(["bash", "-n"], input=shell, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
    assert "tee discovery_diagnostic.jsonl || probe_exit=$?" in source
    assert "chmod 0644 discovery_diagnostic.jsonl" in source
    assert "archiveArtifacts artifacts: 'discovery_diagnostic.jsonl'" in source
    dockerfile = path.with_name("Dockerfile_nd").read_text()
    assert {"iputils-ping", "snmp"}.issubset(dockerfile.split())
