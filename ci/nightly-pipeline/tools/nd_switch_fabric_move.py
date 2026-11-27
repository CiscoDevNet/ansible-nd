#!/usr/bin/env python3
"""Standalone copy of the nd_ensure_switches.yaml re-home (fabric transfer) flow.

Moves switches from one ND fabric to another with the same REST sequence the
Jenkins pre-flight uses, so failures can be iterated on outside Jenkins:

  1. audit      fabric types, membership, vPC pairs, ToR associations, anomalies
  2. unpair     vPC pairs that hold a moving switch (PUT .../vpcPair vpcAction=unPair)
  3. predeploy  copyRunStart, Recalculate (configSave) + Deploy source, wait inSync
  4. remove     switchActions/remove; on per-switch refusal run the remediation
                ladder (ToR disassociate -> Recalculate & Deploy -> per-switch
                deploy -> retry), then a Leaf-ToR role bypass for leaves blocked by
                an orphaned markDeleted ToR pair (temporary leaf -> border role,
                normal remove), then one force=true retry for refused switches
  5. absence    wait until the switches are gone from the source fabric
  6. add        shallowDiscovery + POST /fabrics/{dst}/switches (preserveConfig=false)
  7. converge   wait for discovery, Recalculate & Deploy destination, wait inSync/normal

Use `move` to run every phase, or a phase name to run just that phase. The switch
plan (name, IP, serial, model, version, role, vPC peer) is written to a state file
before anything is removed, so `add`/`converge` can be rerun after a failure even
when the switches are no longer in any fabric. With `--roster FILE` the plan comes
from nd_test_fabric_switches (roster roles; switches in neither fabric included)
instead of the source membership; the Jenkins eBGP round uses this as its fallback.

Credentials come only from the environment and are never printed:
  ND_HOST (default 192.0.2.117), ND_USERNAME (default admin), ND_PASSWORD,
  ND_DOMAIN (default local), SWITCH_USERNAME (default admin),
  SWITCH_PASSWORD (defaults to ND_PASSWORD)
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MANAGE = "/api/v1/manage"
LEAF_TOR_TEXT = "leaf-tor unpairing"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class ND:
    def __init__(self, host: str, user: str, password: str, domain: str, timeout: int = 600):
        self.base = f"https://{host}"
        self.user, self.password, self.domain = user, password, domain
        self.timeout = timeout
        self.ctx = ssl._create_unverified_context()
        self.token = ""
        self.login()

    def login(self) -> None:
        status, body = self._raw("POST", "/login", {"userName": self.user, "userPasswd": self.password, "domain": self.domain}, auth=False)
        if status != 200 or not isinstance(body, dict) or not (body.get("token") or body.get("jwttoken")):
            reason = f" ({body})" if status == 0 else ""
            raise SystemExit(f"ND login failed for {self.base}: HTTP {status}{reason}")
        self.token = body.get("token") or body.get("jwttoken")

    def _raw(self, method, path, body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, method=method, data=data, headers={"Content-Type": "application/json"})
        if auth:
            req.add_header("Authorization", f"Bearer {self.token}")
            req.add_header("Cookie", f"AuthCookie={self.token}")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw.strip() else None)
        except urllib.error.HTTPError as err:
            raw = err.read().decode(errors="replace")
            try:
                return err.code, json.loads(raw)
            except ValueError:
                return err.code, raw
        except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
            return 0, str(err)

    def call(self, method, path, body=None, retries=3):
        for attempt in range(retries + 1):
            status, data = self._raw(method, path, body)
            if status == 401:
                self.login()
                continue
            if status in (0, 429) or status >= 500:
                if attempt < retries:
                    time.sleep(10)
                    continue
            return status, data
        return status, data

    def get(self, path):
        return self.call("GET", path)


# ----------------------------------------------------------------- reads
def fabric_type(nd: ND, fabric: str) -> str:
    status, body = nd.get(f"{MANAGE}/fabrics/{q(fabric)}")
    if status != 200 or not isinstance(body, dict):
        raise SystemExit(f"cannot read fabric {fabric}: HTTP {status}")
    return (body.get("management") or {}).get("type", "")


def fabric_switches(nd: ND, fabric: str) -> list[dict]:
    status, body = nd.get(f"{MANAGE}/fabrics/{q(fabric)}/switches?max=10000")
    if status != 200 or not isinstance(body, dict):
        raise RuntimeError(f"cannot read switches of {fabric}: HTTP {status}")
    return body.get("switches") or []


def vpc_pairs(nd: ND, fabric: str) -> list[dict]:
    status, body = nd.get(f"{MANAGE}/fabrics/{q(fabric)}/vpcPairs")
    return (body or {}).get("vpcPairs", []) if status == 200 and isinstance(body, dict) else []


def anomalies(nd: ND, fabric: str) -> list[dict]:
    status, body = nd.get(f"/api/v1/analyze/anomalies/details?fabricName={q(fabric)}&max=500")
    return (body or {}).get("anomalies", []) if status == 200 and isinstance(body, dict) else []


def leaf_tor_anomalies(nd: ND, fabric: str) -> list[dict]:
    return [a for a in anomalies(nd, fabric) if not a.get("cleared") and LEAF_TOR_TEXT in str(a.get("anomalyString", "")).lower()]


def tor_associations(nd: ND, fabric: str, serial: str) -> list[dict]:
    status, body = nd.get(f"{MANAGE}/fabrics/{q(fabric)}/accessAssociations?aggregationOrLeafSwitchId={serial}")
    return (body or {}).get("associations", []) if status == 200 and isinstance(body, dict) else []


def q(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def sw_view(sw: dict) -> dict:
    ad = sw.get("additionalData") or {}
    return {
        "name": sw.get("hostname"), "serial": sw.get("switchId"), "ip": sw.get("fabricManagementIp"),
        "role": sw.get("switchRole"), "model": sw.get("model"), "version": sw.get("softwareVersion"),
        "sync": ad.get("configSyncStatus"), "mode": ad.get("systemMode"), "discovery": ad.get("discoveryStatus"),
    }


# ----------------------------------------------------------------- state
def load_state(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, path)


def roster_moves(nd: ND, args) -> list[dict]:
    """Plan from the canonical roster (tests/integration_config.yml nd_test_fabric_switches).

    Takes the destination's roster entry when the roster was rendered for that
    fabric, else the source's. Roles come from the roster, so a switch already
    moved (or stranded with a temporary role) is still planned with its real role.
    """
    import yaml

    with open(args.roster, encoding="utf-8") as fh:
        roster = (yaml.safe_load(fh) or {}).get("nd_test_fabric_switches") or {}
    entries = roster.get(args.dst) or roster.get(args.src)
    if not entries:
        raise SystemExit(f"roster {args.roster} has no switches for {args.dst} or {args.src}")
    live = {}
    for fab in (args.src, args.dst):
        for sw in fabric_switches(nd, fab):
            live.setdefault(sw.get("switchId"), sw_view(sw))
    moves = []
    for e in entries:
        v = dict(live.get(e["serial"]) or {})
        v.update({"name": e["name"], "serial": e["serial"], "ip": e["seed_ip"], "role": e["role"]})
        v.setdefault("model", None)
        v.setdefault("version", None)
        moves.append(v)
    return moves


def build_plan(nd: ND, args) -> dict:
    src_type, dst_type = fabric_type(nd, args.src), fabric_type(nd, args.dst)
    log(f"source {args.src} type={src_type}; destination {args.dst} type={dst_type}")
    if args.roster:
        moves = roster_moves(nd, args)
        pairs = vpc_pairs(nd, args.src)
        serials = {m["serial"] for m in moves}
        return {"src": args.src, "dst": args.dst, "src_type": src_type, "dst_type": dst_type, "moves": moves,
                "vpc_pairs": [p for p in pairs if {p.get("switchId"), p.get("peerSwitchId")} & serials]}
    src_sw = fabric_switches(nd, args.src)
    dst_names = {s.get("hostname") for s in fabric_switches(nd, args.dst)}
    wanted = set(args.switches.split(",")) if args.switches else None
    moves = []
    for sw in src_sw:
        v = sw_view(sw)
        if wanted is None or v["name"] in wanted or v["ip"] in wanted or v["serial"] in wanted:
            moves.append(v)
    if wanted:
        found = {m["name"] for m in moves} | {m["ip"] for m in moves} | {m["serial"] for m in moves}
        missing = wanted - found - dst_names
        if missing:
            raise SystemExit(f"requested switches not in {args.src}: {sorted(missing)}")
    pairs = vpc_pairs(nd, args.src)
    serials = {m["serial"] for m in moves}
    for m in moves:
        for p in pairs:
            if m["serial"] in (p.get("switchId"), p.get("peerSwitchId")):
                m["vpc_peer"] = p["peerSwitchId"] if p["switchId"] == m["serial"] else p["switchId"]
    return {"src": args.src, "dst": args.dst, "src_type": src_type, "dst_type": dst_type,
            "moves": moves, "vpc_pairs": [p for p in pairs if {p.get("switchId"), p.get("peerSwitchId")} & serials]}


# ----------------------------------------------------------------- phases
def phase_audit(nd: ND, state: dict) -> None:
    for fab in (state["src"], state["dst"]):
        sws = [sw_view(s) for s in fabric_switches(nd, fab)]
        log(f"{fab}: {len(sws)} switch(es)")
        for s in sws:
            log(f"   {s['name']:<16} {s['serial']:<12} {s['ip']:<15} role={s['role']:<7} sync={s['sync']} mode={s['mode']} disc={s['discovery']}")
        for p in vpc_pairs(nd, fab):
            log(f"   vPC {p.get('switchName')} <-> {p.get('peerSwitchName')} ({p.get('type')})")
        for a in leaf_tor_anomalies(nd, fab):
            log(f"   LEAF-TOR anomaly ack={a.get('acknowledged')} {a.get('startDate', '')[:10]} {a.get('anomalyString')}")
    for m in state["moves"]:
        if m["role"] == "leaf":
            assoc = tor_associations(nd, state["src"], m["serial"])
            if assoc:
                log(f"   ToR associations on {m['name']}: {len(assoc)}")
    log("plan: " + ", ".join(f"{m['name']}({m['role']})" for m in state["moves"]) + f"  {state['src']} -> {state['dst']}")


def phase_unpair(nd: ND, state: dict) -> None:
    pairs = [p for p in vpc_pairs(nd, state["src"]) if {p.get("switchId"), p.get("peerSwitchId")} & {m["serial"] for m in state["moves"]}]
    if not pairs:
        log("unpair: no vPC pair holds a moving switch")
        return
    for p in pairs:
        body = {"vpcAction": "unPair", "switchId": p["switchId"], "peerSwitchId": p["peerSwitchId"]}
        status, data = nd.call("PUT", f"{MANAGE}/fabrics/{q(state['src'])}/switches/{p['switchId']}/vpcPair", body)
        log(f"unpair {p.get('switchName')}-{p.get('peerSwitchName')}: HTTP {status} {short(data)}")
        if status not in (200, 201, 202, 204, 207):
            raise SystemExit("vPC unpair refused; no switch removed")
    recalc_deploy(nd, state["src"])
    wait_until(lambda: not [p for p in vpc_pairs(nd, state["src"]) if {p.get("switchId"), p.get("peerSwitchId")} & {m["serial"] for m in state["moves"]}],
               "vPC pairs gone from source", 600, 20)


def recalculate(nd: ND, fabric: str) -> bool:
    status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(fabric)}/actions/configSave", {})
    log(f"Recalculate {fabric}: HTTP {status} {short(data)}")
    return status in (200, 201, 202, 204)


def recalc_deploy(nd: ND, fabric: str, serials: list[str] | None = None) -> None:
    recalculate(nd, fabric)
    if serials:
        status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(fabric)}/switchActions/deploy", {"switchIds": serials})
        log(f"Deploy {fabric} switches={len(serials)}: HTTP {status} {short(data)}")
    else:
        status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(fabric)}/actions/deploy", {})
        log(f"Deploy {fabric}: HTTP {status} {short(data)}")
    if status not in (200, 201, 202, 204, 207):
        log(f"WARNING: deploy of {fabric} not accepted (HTTP {status})")


def phase_predeploy(nd: ND, state: dict) -> None:
    serials = [m["serial"] for m in present(nd, state["src"], state)]
    if not serials:
        log("predeploy: no moving switch left in source")
        return
    status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(state['src'])}/actions/copyRunStart", {"switchIds": serials})
    log(f"copyRunStart {len(serials)} switch(es): HTTP {status} {short(data)}")
    recalc_deploy(nd, state["src"])
    wait_insync(nd, state["src"], serials, 1200)


def present(nd: ND, fabric: str, state: dict) -> list[dict]:
    serials = {m["serial"] for m in state["moves"]}
    return [sw_view(s) for s in fabric_switches(nd, fabric) if s.get("switchId") in serials]


def wait_insync(nd: ND, fabric: str, serials: list[str], timeout: int) -> bool:
    def ok():
        sws = {s["serial"]: s for s in (sw_view(x) for x in fabric_switches(nd, fabric))}
        bad = [f"{sws[s]['name']}:{sws[s]['sync']}/{sws[s]['mode']}" for s in serials if s in sws and not (sws[s]["sync"] == "inSync" and sws[s]["mode"] == "normal")]
        absent = [s for s in serials if s not in sws]
        if bad or absent:
            log(f"   waiting: {bad} absent={len(absent)}")
        return not bad and not absent
    return wait_until(ok, f"inSync/normal in {fabric}", timeout, 30)


def remove(nd: ND, fabric: str, serials: list[str], force: bool) -> dict[str, tuple[str, str]]:
    path = f"{MANAGE}/fabrics/{q(fabric)}/switchActions/remove" + ("?force=true" if force else "")
    status, data = nd.call("POST", path, {"switchIds": serials}, retries=0 if force else 3)
    log(f"remove{' (force)' if force else ''} {len(serials)} switch(es): HTTP {status}")
    result = {}
    items = data.get("items") if isinstance(data, dict) else None
    if isinstance(items, list) and items:
        for it in items:
            result[it.get("switchId")] = (str(it.get("status", "")).lower(), str(it.get("message", it.get("reason", "")))[:240])
    elif status in (200, 201, 202, 204):
        result = {s: ("success", "") for s in serials}
    else:
        result = {s: ("failed", f"HTTP {status} {short(data)}") for s in serials}
    for sid, (st, msg) in result.items():
        log(f"   {name_of(sid)}: {st} {msg}")
    return result


_NAMES: dict[str, str] = {}


def name_of(serial: str) -> str:
    return _NAMES.get(serial, serial)


def phase_remove(nd: ND, state: dict, allow_force: bool) -> None:
    src = state["src"]
    pending = [m["serial"] for m in present(nd, src, state)]
    if not pending:
        log("remove: no moving switch left in source")
        return
    res = remove(nd, src, pending, force=False)
    refused = [s for s in pending if res.get(s, ("failed", ""))[0] != "success"]
    if not refused:
        return

    # Remediation ladder, one rung at a time; each rung retries only the still-refused switches.
    log(f"REMEDIATE: {len(refused)} refused: {[name_of(s) for s in refused]}")
    for a in leaf_tor_anomalies(nd, src):
        log(f"   Leaf-ToR anomaly ack={a.get('acknowledged')} {a.get('anomalyString')}")

    rungs = [
        ("disassociate ToR", lambda r: disassociate_tor(nd, src, r)),
        ("fabric Recalculate & Deploy", lambda r: (recalc_deploy(nd, src), wait_insync(nd, src, r, 900))),
        ("per-switch Deploy", lambda r: (recalc_deploy(nd, src, r), wait_insync(nd, src, r, 900))),
    ]
    for label, action in rungs:
        log(f"REMEDIATE rung: {label}")
        action(refused)
        still = [s for s in refused if s in {m["serial"] for m in present(nd, src, state)}]
        if not still:
            refused = []
            break
        res = remove(nd, src, still, force=False)
        refused = [s for s in still if res.get(s, ("failed", ""))[0] != "success"]
        if not refused:
            break

    if refused:
        refused = leaf_tor_role_bypass(nd, src, state, refused)

    if refused:
        if not allow_force:
            raise SystemExit(f"NDP_SWITCH_REMOVE_REJECTED {[name_of(s) for s in refused]}; force disabled (--no-force)")
        log(f"REMEDIATE rung: one force=true retry for {[name_of(s) for s in refused]}")
        res = remove(nd, src, refused, force=True)
        refused = [s for s in refused if res.get(s, ("failed", ""))[0] != "success"]
        if refused:
            raise SystemExit(f"NDP_SWITCH_REMOVE_REJECTED even with force: {[name_of(s) for s in refused]}")


def change_roles(nd: ND, fabric: str, roles: dict[str, str]) -> bool:
    body = {"switchRoles": [{"switchId": s, "role": r} for s, r in roles.items()]}
    status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(fabric)}/switchActions/changeRoles", body)
    items = data.get("items") if isinstance(data, dict) else None
    ok = status in (200, 207) and (not items or all(str(i.get("status", "")).lower() == "success" for i in items))
    log(f"   changeRoles {[(name_of(s), r) for s, r in roles.items()]}: HTTP {status} {short(data)}")
    return ok


def leaf_tor_role_bypass(nd: ND, fabric: str, state: dict, refused: list[str]) -> list[str]:
    """Remove leaves blocked by an orphaned markDeleted Leaf-ToR pair record.

    The Easy_Fabric preSwitchDelete hook runs ToRWrapper.getMarkDeletedPairs()
    only when switchRole == "leaf" and refuses the delete (even with force=true)
    while such a record exists. Recalculate cannot complete the unpairing once
    the ToR has left the fabric, so the record never clears. A temporary role
    change takes the switch out of that check; the destination add uses the
    planned role, so the leaf comes back as a leaf.
    """
    current = {s["serial"]: s for s in (sw_view(x) for x in fabric_switches(nd, fabric))}
    blocked_serials = {s for a in leaf_tor_anomalies(nd, fabric) for s in refused if s in json.dumps(a)}
    targets = [s for s in refused if s in blocked_serials and current.get(s, {}).get("role") == "leaf"]
    if not targets:
        return refused
    log(f"REMEDIATE rung: Leaf-ToR role bypass (leaf -> border, normal remove) for {[name_of(s) for s in targets]}")
    if not change_roles(nd, fabric, {s: "border" for s in targets}):
        change_roles(nd, fabric, {s: "leaf" for s in targets})
        return refused
    res = remove(nd, fabric, targets, force=False)
    failed = [s for s in targets if res.get(s, ("failed", ""))[0] != "success"]
    if failed:
        change_roles(nd, fabric, {s: "leaf" for s in failed})
    return [s for s in refused if s not in targets or s in failed]


def disassociate_tor(nd: ND, fabric: str, serials: list[str]) -> None:
    for s in serials:
        for a in tor_associations(nd, fabric, s):
            body = {k: a[k] for k in ("accessOrTorSwitchId", "aggregationOrLeafSwitchId", "accessOrTorPeerSwitchId", "aggregationOrLeafPeerSwitchId") if a.get(k)}
            status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(fabric)}/accessAssociationActions/disassociate", [body])
            log(f"   disassociate ToR on {name_of(s)}: HTTP {status} {short(data)}")
    log("   ToR associations checked")


def phase_absence(nd: ND, state: dict) -> None:
    wait_until(lambda: not present(nd, state["src"], state), f"moving switches absent from {state['src']}", 600, 15)


def phase_add(nd: ND, state: dict, sw_user: str, sw_pass: str, preserve: bool) -> None:
    dst = state["dst"]
    have = {s.get("switchId") for s in fabric_switches(nd, dst)}
    todo = [m for m in state["moves"] if m["serial"] not in have]
    if not todo:
        log("add: every switch is already in the destination")
        return
    still_src = present(nd, state["src"], state)
    if still_src:
        raise SystemExit(f"refusing to add: still in source {[s['name'] for s in still_src]}")

    def discovered():
        status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(dst)}/actions/shallowDiscovery",
                               {"seedIpCollection": [m["ip"] for m in todo], "maxHop": 0, "platformType": "nx-os",
                                "snmpV3AuthProtocol": "md5", "username": sw_user, "password": sw_pass})
        sws = (data or {}).get("switches", []) if isinstance(data, dict) else []
        by_ip = {s.get("ip"): s for s in sws}
        states = {m["name"]: (by_ip.get(m["ip"]) or {}).get("status", "missing") for m in todo}
        log(f"   discovery HTTP {status}: {states}")
        for m in todo:
            d = by_ip.get(m["ip"]) or {}
            if d.get("serialNumber") and d["serialNumber"] != m["serial"]:
                raise SystemExit(f"serial drift on {m['name']}: expected {m['serial']} got {d['serialNumber']}")
            if d.get("statusReason") and d.get("status", "").lower() not in ("manageable", "ok"):
                log(f"     {m['name']}: {d.get('statusReason')}")
            # A switch planned from the roster while in no fabric has no model/version yet.
            m["model"] = m.get("model") or d.get("model")
            m["version"] = m.get("version") or d.get("softwareVersion") or d.get("version")
        return all(states[m["name"]].lower() in ("manageable", "ok") for m in todo)

    if not wait_until(discovered, "switches discoverable for the destination", 900, 30):
        raise SystemExit("discovery did not confirm every switch; nothing added")

    body = {
        "switches": [{"hostname": m["name"], "ip": m["ip"], "serialNumber": m["serial"], "model": m["model"],
                      "softwareVersion": m["version"], "switchRole": m["role"]} for m in todo],
        "platformType": "nx-os", "preserveConfig": preserve, "snmpV3AuthProtocol": "md5",
        "username": sw_user, "password": sw_pass,
    }
    status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(dst)}/switches", body, retries=0)
    log(f"add {len(todo)} switch(es) to {dst} preserveConfig={preserve}: HTTP {status} {short(data, 600)}")
    if status not in (200, 201, 202, 207):
        raise SystemExit("add request not accepted")


def phase_converge(nd: ND, state: dict, timeout: int) -> None:
    dst = state["dst"]
    serials = [m["serial"] for m in state["moves"]]

    def discovered_ok():
        sws = {s["serial"]: s for s in (sw_view(x) for x in fabric_switches(nd, dst))}
        info = {name_of(s): (sws[s]["discovery"], sws[s]["mode"], sws[s]["sync"]) if s in sws else "absent" for s in serials}
        log(f"   {info}")
        return all(s in sws and str(sws[s]["discovery"]).lower() == "ok" for s in serials)

    if not wait_until(discovered_ok, f"discovery ok in {dst}", timeout, 60):
        raise SystemExit("switches did not finish discovery/reload in the destination")
    fix_roles(nd, state)
    # Greenfield add reloads the switches; ND refuses Recalculate (HTTP 500 "Switch(es) are
    # reloading") until they are reachable again, so wait for an accepted Recalculate first.
    if not wait_until(lambda: recalculate(nd, dst), f"Recalculate accepted for {dst}", timeout, 60):
        raise SystemExit("Recalculate was never accepted; switches did not come back from reload")
    for attempt in range(1, 4):
        # Right after the greenfield reload, the fabric-wide deploy returned "completed"
        # without pushing anything. An explicit switch-scoped deploy pushed the config.
        sws = {s["serial"]: s for s in (sw_view(x) for x in fabric_switches(nd, dst))}
        pending = [s for s in serials if not (s in sws and sws[s]["sync"] == "inSync")] or serials
        recalc_deploy(nd, dst, pending)
        if wait_insync(nd, dst, serials, 900):
            log(f"CONVERGED: all {len(serials)} switches inSync/normal in {dst}")
            return
        log(f"converge attempt {attempt} incomplete; retrying Recalculate & Deploy")
    raise SystemExit("destination did not converge")


def fix_roles(nd: ND, state: dict) -> None:
    sws = {s["serial"]: s for s in (sw_view(x) for x in fabric_switches(nd, state["dst"]))}
    changes = [{"switchId": m["serial"], "role": m["role"]} for m in state["moves"] if m["serial"] in sws and sws[m["serial"]]["role"] != m["role"]]
    if changes:
        status, data = nd.call("POST", f"{MANAGE}/fabrics/{q(state['dst'])}/switchActions/changeRoles", {"switchRoles": changes})
        log(f"changeRoles {changes}: HTTP {status} {short(data)}")


def phase_repair_vpc(nd: ND, state: dict) -> None:
    for p in state.get("vpc_pairs", []):
        body = {"vpcAction": "pair", "switchId": p["switchId"], "peerSwitchId": p["peerSwitchId"], "useVirtualPeerLink": True}
        status, data = nd.call("PUT", f"{MANAGE}/fabrics/{q(state['dst'])}/switches/{p['switchId']}/vpcPair", body)
        log(f"pair {p.get('switchName')}-{p.get('peerSwitchName')} in {state['dst']}: HTTP {status} {short(data)}")
    if state.get("vpc_pairs"):
        recalc_deploy(nd, state["dst"])
        wait_insync(nd, state["dst"], [m["serial"] for m in state["moves"]], 1200)


# ----------------------------------------------------------------- helpers
def wait_until(pred, what: str, timeout: int, interval: int) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if pred():
                log(f"OK: {what}")
                return True
        except RuntimeError as err:
            log(f"   read error: {err}")
        if time.monotonic() >= deadline:
            log(f"TIMEOUT after {timeout}s: {what}")
            return False
        time.sleep(interval)


def short(data, limit: int = 300) -> str:
    text = data if isinstance(data, str) else json.dumps(data)
    return (text or "")[:limit]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("phase", choices=["audit", "move", "unpair", "predeploy", "remove", "absence", "add", "converge", "repair-vpc"])
    ap.add_argument("--src", default="VXLAN_EVPN_Fabric")
    ap.add_argument("--dst", default="VXLAN_EVPN_Fabric_eBGP")
    ap.add_argument("--switches", default="", help="comma list of names/IPs/serials; default = every switch in --src")
    ap.add_argument("--roster", default="", help="plan from nd_test_fabric_switches in this YAML (roster roles) instead of --src membership")
    ap.add_argument("--state", default="nd_switch_fabric_move_state.json")
    ap.add_argument("--no-force", action="store_true", help="never send switchActions/remove?force=true")
    ap.add_argument("--preserve-config", action="store_true", help="brownfield add (pipeline default is greenfield)")
    ap.add_argument("--repair-vpc", action="store_true", help="re-create the source vPC pair(s) in the destination after convergence")
    ap.add_argument("--converge-timeout", type=int, default=3600)
    args = ap.parse_args()

    nd_pass = os.environ.get("ND_PASSWORD")
    if not nd_pass:
        raise SystemExit("set ND_PASSWORD in the environment")
    nd = ND(os.environ.get("ND_HOST", "192.0.2.117"), os.environ.get("ND_USERNAME", "admin"), nd_pass, os.environ.get("ND_DOMAIN", "local"))
    sw_user = os.environ.get("SWITCH_USERNAME") or "admin"
    sw_pass = os.environ.get("SWITCH_PASSWORD") or nd_pass

    if os.path.exists(args.state) and args.phase not in ("audit", "move"):
        state = load_state(args.state)
    else:
        state = build_plan(nd, args)
        if os.path.exists(args.state) and not state["moves"]:
            state = load_state(args.state)
        elif state["moves"]:
            save_state(args.state, state)
    _NAMES.update({m["serial"]: m["name"] for m in state["moves"]})
    if not state["moves"]:
        raise SystemExit("nothing to move (no matching switches in the source and no saved state)")
    if args.phase in ("move", "add") and state.get("dst_type") == state.get("src_type") == "":
        raise SystemExit("unknown fabric types")

    phases = {
        "audit": lambda: phase_audit(nd, state),
        "unpair": lambda: phase_unpair(nd, state),
        "predeploy": lambda: phase_predeploy(nd, state),
        "remove": lambda: phase_remove(nd, state, not args.no_force),
        "absence": lambda: phase_absence(nd, state),
        "add": lambda: phase_add(nd, state, sw_user, sw_pass, args.preserve_config),
        "converge": lambda: phase_converge(nd, state, args.converge_timeout),
        "repair-vpc": lambda: phase_repair_vpc(nd, state),
    }
    order = ["audit", "unpair", "predeploy", "remove", "absence", "add", "converge"] + (["repair-vpc"] if args.repair_vpc else [])
    for name in (order if args.phase == "move" else [args.phase]):
        log(f"===== phase {name} =====")
        phases[name]()
    if args.phase == "move":
        log("===== final audit =====")
        phase_audit(nd, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
