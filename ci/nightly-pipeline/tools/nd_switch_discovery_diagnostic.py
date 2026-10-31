#!/usr/bin/env python3
"""Isolate ND shallow discovery without importing, deleting, or deploying switches.

Uses the Jenkins NDFC_USER/NDFC_PASSWORD and ANSIBLE_NXOS_SWITCH_USERNAME/
ANSIBLE_NXOS_SWITCH_PASSWORD environment bindings. --seed replaces the default;
repeat it to compare switches, for example --seed 192.0.2.195=SERIAL00001
--seed 192.0.2.196=SERIAL00002. TLS verification defaults to true; a CA bundle
is preferred. Existing lab runtime ND_VERIFY_CERTS=false is explicitly honored.
"""
import argparse
import ipaddress
import json
import os
import re
from urllib.parse import quote, urlsplit

import requests

CREDENTIALS = ("NDFC_USER", "NDFC_PASSWORD", "ANSIBLE_NXOS_SWITCH_USERNAME", "ANSIBLE_NXOS_SWITCH_PASSWORD")
DEFAULT_SEED = ("192.0.2.195", "SERIAL00001")
ACCEPTED = {"manageable", "ok", "alreadymanaged"}


class DiagnosticError(Exception):
    """A deliberately safe message, without request/response contents."""


def seed_pair(value):
    try:
        address, serial = value.split("=", 1)
        address = str(ipaddress.ip_address(address))
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", serial):
            raise ValueError
        return address, serial
    except ValueError:
        raise argparse.ArgumentTypeError("seed must be IP=EXPECTED_SERIAL") from None


def redact(value, secrets):
    if isinstance(value, str):
        for secret in sorted(set(filter(None, secrets)), key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {redact(key, secrets): redact(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    return value


def discovery_rows(body, seeds):
    records = body.get("switches")
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise DiagnosticError("Discovery returned a malformed switches list")
    expected_ips = {address for address, _ in seeds}
    if any(not isinstance(row.get("ip") or row.get("seedIp"), str)
           or (row.get("ip") or row.get("seedIp")) not in expected_ips for row in records):
        raise DiagnosticError("Discovery returned a missing or unexpected seed IP")
    rows = []
    for address, expected in seeds:
        matches = [row for row in records if (row.get("ip") or row.get("seedIp")) == address]
        row = {"seed_ip": address, "expected_serial": expected, "ok": False}
        if len(matches) != 1:
            row["errors"] = ["Missing discovery record" if not matches else "Duplicate discovery records"]
        else:
            record = matches[0]
            status, serial, reason = (record.get(key) for key in ("status", "serialNumber", "statusReason"))
            errors = []
            normalized = "".join(char for char in status.lower() if char.isalnum()) if isinstance(status, str) else ""
            if normalized not in ACCEPTED:
                errors.append("ND did not confirm manageability")
            if not isinstance(serial, str) or not serial.strip():
                errors.append("Discovery returned no valid serial number")
            elif serial != expected:
                errors.append("Returned serial does not match expected serial")
            if reason is not None and not isinstance(reason, str):
                errors.append("Malformed statusReason")
            row.update(status=status if isinstance(status, str) else None,
                       actual_serial=serial if isinstance(serial, str) else None,
                       status_reason=reason if isinstance(reason, str) else None,
                       errors=errors, ok=not errors)
        rows.append(row)
    return rows


def main(argv=None, *, environ=None, session=None):
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=env.get("ND_HOST", "192.0.2.117"))
    parser.add_argument("--fabric", default="VXLAN_EVPN_Fabric")
    parser.add_argument("--seed", action="append", type=seed_pair)
    parser.add_argument("--snmp-auth", default="md5")
    parser.add_argument("--ca-bundle")
    parser.add_argument("--inventory", action="store_true", help="Also GET the controller switch inventory")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)
    secrets = [env.get(name, "") for name in CREDENTIALS]
    report = {"controller": args.host, "fabric": args.fabric, "ok": False}
    try:
        if any(not value.strip() for value in secrets):
            raise DiagnosticError("All four Jenkins credential environment bindings must be nonempty")
        if not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", args.host) or not urlsplit("https://" + args.host).hostname:
            raise DiagnosticError("ND host must be a bare hostname or IP, optionally with a port")
        urlsplit("https://" + args.host).port  # Reject malformed ports before preparing a request.
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*", args.fabric) or args.timeout <= 0:
            raise DiagnosticError("Fabric must be a plain identifier and timeout must be positive")
        seeds = args.seed or [DEFAULT_SEED]
        if len({address for address, _ in seeds}) != len(seeds) or len({serial for _, serial in seeds}) != len(seeds):
            raise DiagnosticError("Seed IPs and expected serials must each be unique")
        verify_env = env.get("ND_VERIFY_CERTS", "true").lower()
        if verify_env not in {"true", "false"}:
            raise DiagnosticError("ND_VERIFY_CERTS must be true or false")
        verify = args.ca_bundle or (verify_env == "true")
        report["verify_certs"] = bool(verify)
        discovery_path = "/api/v1/manage/fabrics/" + quote(args.fabric, safe="") + "/actions/shallowDiscovery"
        inventory_path = "/api/v1/manage/inventory/switches?max=10000"
        allowed = {("POST", "/login"), ("POST", discovery_path)}
        if args.inventory:
            allowed.add(("GET", inventory_path))
        client = session if session is not None else requests.Session()
        client.trust_env = False

        def call(method, path, payload=None, token=None):
            if (method, path) not in allowed:
                raise DiagnosticError("Refused an endpoint outside the diagnostic allowlist")
            headers = {"Accept": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            response = client.request(method, "https://" + args.host + path, json=payload,
                                      headers=headers, timeout=args.timeout, verify=verify, allow_redirects=False)
            if not 200 <= response.status_code < 300:
                raise DiagnosticError("Controller request failed (HTTP %s)" % response.status_code)
            body = response.json()
            if not isinstance(body, dict):
                raise DiagnosticError("Controller returned a malformed JSON object")
            for key in ("DATA", "body"):
                if isinstance(body.get(key), dict):
                    body = body[key]
                    break
            if "code" in body or isinstance(body.get("error"), dict) and "code" in body["error"]:
                raise DiagnosticError("Controller returned an embedded error")
            return body

        report["stage"] = "login"
        login = call("POST", "/login", {"userName": secrets[0], "userPasswd": secrets[1], "domain": "local"})
        token = login.get("jwttoken") or login.get("token")
        if not isinstance(token, str) or not token.strip():
            raise DiagnosticError("Login returned no valid bearer token")
        secrets.append(token)
        report["stage"] = "discovery"
        body = call("POST", discovery_path, {"seedIpCollection": [address for address, _ in seeds], "maxHop": 0,
                    "platformType": "nx-os", "snmpV3AuthProtocol": args.snmp_auth,
                    "username": secrets[2], "password": secrets[3]}, token)
        warning = body.get("warning", "")
        if not isinstance(warning, str):
            raise DiagnosticError("Discovery returned a malformed warning")
        report.update(warning=warning, results=discovery_rows(body, seeds))
        if args.inventory:
            report["stage"] = "inventory"
            inventory = call("GET", inventory_path, token=token).get("switches")
            if not isinstance(inventory, list) or any(not isinstance(row, dict) for row in inventory):
                raise DiagnosticError("Controller returned a malformed inventory")
            report["inventory"] = [{key: row.get(key) if isinstance(row.get(key), str) else None
                                    for key in ("fabricManagementIp", "serialNumber", "switchId", "fabricName")}
                                   for row in inventory if isinstance(row.get("fabricManagementIp"), str)
                                   and row["fabricManagementIp"] in dict(seeds)]
        report["ok"] = all(row["ok"] for row in report["results"])
        report["stage"] = "complete"
    except (DiagnosticError, requests.RequestException, ValueError, OSError) as exc:
        report["error"] = str(exc) if isinstance(exc, DiagnosticError) else "Controller request failed (%s)" % type(exc).__name__
    print(json.dumps(redact(report, secrets), indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
