#!/usr/bin/env python3
"""consul_sync.py - sync local nd_pipeline sources <-> Consul KV (ansible-nd/).

Compares md5 checksum AND byte size between each local (OneDrive) source file
and its Consul key. On `push`, every locally-changed file is staged into a
throwaway temp directory, PUT to Consul, roundtrip-verified (re-GET + md5),
then the temp copy is deleted.

  status              read-only: md5+size compare of all keys  (DEFAULT)
  push --yes          stage->PUT->verify->clean the changed files
  push                dry-run of push (prints the plan, writes nothing)

  --only a,b,c        restrict to keys/basenames matching any token

The key<->file map is driven by the LIVE Consul key list, so files that are not
Consul keys (nd_25aug/, nd_30aug/, _deleted/, temp _*.yaml probes, local-only
tests) are never touched. Stdlib only; runs on /usr/bin/python3.
"""
import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

CONSUL = os.environ.get(
    "ND_CONSUL_BASE", "http://198.51.100.155:8500/v1/kv/ansible-nd"
)
WORKSPACE = "/Users/sivakasi/Library/CloudStorage/OneDrive-Cisco/2/Ansible work/NX_ansible/jenkins/jenkins_nd"
ROOT = os.environ.get("ND_LOCAL_ROOT", WORKSPACE)
READ_TIMEOUT = int(os.environ.get("ND_READ_TIMEOUT", "12"))  # per-file hydrate cap
NET_TIMEOUT = int(os.environ.get("ND_NET_TIMEOUT", "20"))
WORKERS = int(os.environ.get("ND_WORKERS", "8"))

# Keys whose local source lives outside nd_pipeline/playbooks/ (see consul-sync.md).
CONFIG_KEYS = {
    "ansible.cfg", "inventory.yaml", "requirements.txt",
    "requirements.yaml", "reset_fabric.yaml",
}
TESTS_KEYS = {
    "integration_config.yml", "run_integration_module.yaml",
    "nd_prerequisite_profiles.yaml", "nd_prerequisite_orchestrator.py",
    "validate_nd_prerequisites.py", "test_validate_nd_prerequisites.py",
}


def key_to_local(key):
    """Map a Consul key (base already stripped) to its canonical local path."""
    if key.startswith("nd_prerequisite/"):
        return os.path.join(ROOT, "nd_pipeline", "playbooks", key)
    if key.startswith("fixtures/nd_prerequisite/"):
        return os.path.join(ROOT, "nd_pipeline", "tests", key)
    if key == "webex-notification-jenkins.py":
        return os.path.join(ROOT, key)
    if key in CONFIG_KEYS:
        return os.path.join(ROOT, "nd_pipeline", "consul", key)
    if key in TESTS_KEYS:
        return os.path.join(ROOT, "nd_pipeline", "tests", key)
    return os.path.join(ROOT, "nd_pipeline", "playbooks", key)


def md5(b):
    return hashlib.md5(b).hexdigest()


def list_keys():
    with urllib.request.urlopen(CONSUL + "?keys", timeout=NET_TIMEOUT) as r:
        keys = json.load(r)
    prefix = CONSUL.rsplit("/", 1)[-1] + "/"  # "ansible-nd/"
    out = []
    for k in keys:
        if k.startswith(prefix):
            k = k[len(prefix):]
        if k and not k.endswith("/"):
            out.append(k)
    return sorted(out)


def consul_get(key):
    try:
        with urllib.request.urlopen(
            "%s/%s?raw" % (CONSUL, key), timeout=NET_TIMEOUT
        ) as r:
            return r.read(), None
    except urllib.error.HTTPError as e:
        return None, "404" if e.code == 404 else "http%s" % e.code
    except Exception as e:  # noqa: BLE001 - report any transport error
        return None, str(e)


def consul_put(key, data):
    req = urllib.request.Request("%s/%s" % (CONSUL, key), data=data, method="PUT")
    with urllib.request.urlopen(req, timeout=NET_TIMEOUT) as r:
        return r.read().decode().strip() == "true"


def read_local(path, timeout=READ_TIMEOUT):
    """Read a (possibly dataless OneDrive) file, bounded so a stall can't hang."""
    if not os.path.exists(path):
        return None, "missing"
    try:
        p = subprocess.run(["cat", path], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout>%ss (dataless/stall)" % timeout
    if p.returncode != 0:
        return None, (p.stderr.decode("utf-8", "replace").strip() or "cat-error")
    return p.stdout, None


def evaluate(key):
    local = key_to_local(key)
    cbytes, cerr = consul_get(key)
    row = {
        "key": key, "local": local,
        "csize": len(cbytes) if cbytes is not None else None,
        "cmd5": md5(cbytes) if cbytes else None,
        "lsize": os.path.getsize(local) if os.path.exists(local) else None,
        "lmd5": None, "lbytes": None, "lerr": None,
    }
    if row["lsize"] is None:
        row["status"] = "LOCAL-MISSING"
        return row
    lbytes, lerr = read_local(local)
    if lbytes is None:
        row["lerr"] = lerr
        if cbytes is None:
            row["status"] = "CONSUL-MISSING"
        elif row["lsize"] == row["csize"]:
            row["status"] = "SIZE-MATCH?"      # readable failed; sizes equal
        else:
            row["status"] = "DIFF?(unread)"
        return row
    row["lmd5"] = md5(lbytes)
    row["lbytes"] = lbytes
    if cbytes is None:
        row["status"] = "CONSUL-MISSING"
    elif row["lmd5"] == row["cmd5"]:
        row["status"] = "SAME"
    else:
        row["status"] = "DIFF"
    return row


def gather(keys):
    rows = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        rows = list(ex.map(evaluate, keys))
    return sorted(rows, key=lambda r: r["key"])


def _short(h):
    return h[:8] if h else "-"


def print_table(rows):
    print("%-42s %-13s %8s  %-13s %8s  %s" % (
        "KEY", "CONSUL md5", "size", "LOCAL md5", "size", "STATUS"))
    print("-" * 104)
    for r in rows:
        print("%-42s %-13s %8s  %-13s %8s  %s" % (
            r["key"][:42], _short(r["cmd5"]),
            r["csize"] if r["csize"] is not None else "-",
            _short(r["lmd5"]), r["lsize"] if r["lsize"] is not None else "-",
            r["status"] + (" (%s)" % r["lerr"] if r["lerr"] else "")))
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("-" * 104)
    print("summary:", ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts)))


def do_push(rows, execute):
    changed = [r for r in rows
               if r["status"] in ("DIFF", "CONSUL-MISSING")
               and r["lbytes"] is not None]
    unread = [r for r in rows if r["status"] in ("SIZE-MATCH?", "DIFF?(unread)")]
    if unread:
        print("\nNOTE: %d file(s) could not be read (OneDrive dataless/stall) and "
              "are SKIPPED - not pushed:" % len(unread))
        for r in unread:
            print("  - %s (%s)" % (r["key"], r["lerr"]))
    if not changed:
        print("\nNothing to push (no readable DIFF/CONSUL-MISSING files).")
        return 0
    print("\n%s %d changed file(s):" % (
        "PUSHING" if execute else "WOULD PUSH", len(changed)))
    for r in changed:
        print("  %-42s %s  local=%s consul=%s" % (
            r["key"], r["status"], _short(r["lmd5"]), _short(r["cmd5"])))
    if not execute:
        print("\nDry-run only. Re-run with:  push --yes   to apply.")
        return 0

    tmp = tempfile.mkdtemp(prefix="consul_sync_")
    ok = fail = 0
    try:
        for r in changed:
            staged = os.path.join(tmp, r["key"].replace("/", "_"))
            with open(staged, "wb") as f:
                f.write(r["lbytes"])
            put_ok = False
            try:
                put_ok = consul_put(r["key"], r["lbytes"])
            except Exception as e:  # noqa: BLE001
                print("  FAIL %s: PUT error %s" % (r["key"], e))
            vb, verr = consul_get(r["key"])
            verified = vb is not None and md5(vb) == r["lmd5"]
            os.remove(staged)  # delete temp content, per file
            if put_ok and verified:
                ok += 1
                print("  OK   %s  -> md5 %s verified (%d B)" % (
                    r["key"], _short(r["lmd5"]), r["lsize"]))
            else:
                fail += 1
                print("  FAIL %s  put=%s verified=%s%s" % (
                    r["key"], put_ok, verified,
                    "" if vb is not None else " (GET %s)" % verr))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\npush complete: %d ok, %d failed. temp dir removed: %s" % (ok, fail, tmp))
    return 1 if fail else 0


def filter_rows(keys, only):
    if not only:
        return keys
    tokens = [t.strip() for t in only.split(",") if t.strip()]
    sel = []
    for k in keys:
        base = os.path.basename(k)
        if any(t == k or t == base or t in k for t in tokens):
            sel.append(k)
    return sel


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    for name in ("status", "push"):
        sp = sub.add_parser(name)
        sp.add_argument("--only", help="comma-separated keys/basenames to include")
        if name == "push":
            sp.add_argument("--yes", action="store_true",
                            help="actually PUT to Consul (default is dry-run)")
    args = ap.parse_args(argv)
    cmd = args.cmd or "status"

    print("Consul : %s" % CONSUL)
    print("Local  : %s" % ROOT)
    keys = list_keys()
    keys = filter_rows(keys, getattr(args, "only", None))
    print("Keys   : %d\n" % len(keys))
    rows = gather(keys)
    print_table(rows)
    if cmd == "push":
        return do_push(rows, execute=getattr(args, "yes", False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
