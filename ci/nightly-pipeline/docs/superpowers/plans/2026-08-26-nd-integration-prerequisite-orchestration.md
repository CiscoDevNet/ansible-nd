# ND Per-Target Prerequisite Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, validate, and publish a per-target Jenkins/Ansible lifecycle that safely prepares and restores the retained Siva virtual lab topology so every configured cisco.nd target reaches its module tests without topology, switch, role, vPC, or interface prerequisite failures.

**Architecture:** A versioned YAML registry is the single topology contract. A phase-driven Ansible wrapper performs read-only preflight, validated snapshot capture, bounded reconciliation/polling, runtime-variable emission, and dependency-aware restoration; Jenkins invokes every smoke, role, and standalone target through one Groovy `try/finally` boundary while holding a Consul CAS lab lock. A Python validator and CAS publisher hydrate the current Consul values, validate a complete release, keep restricted before-images, publish content keys first and the hash-locked manifest last, and roll back partial writes without deleting newly created keys.

**Tech Stack:** Jenkins Pipeline Groovy, Bash, Ansible/YAML, cisco.nd modules and `cisco.nd.nd_rest`, Python 3 standard library plus PyYAML, HashiCorp Consul KV HTTP API, SHA-256.

**Spec:** `docs/superpowers/specs/2026-08-26-nd-integration-prerequisite-orchestration-design.md`

## Global Constraints

- Retain `Siva_Fabric_Adv` (`vxlanIbgp`) and `Siva_External_Fabric` (`externalConnectivity`); no automatic path may delete either fabric or evict its captured baseline switches.
- Treat all links as already physically wired virtual links. The wrapper may set `adminState=true` only on profile-allowlisted Ethernet interfaces and performs no cabling or hypervisor action.
- Use four distinct lab identities exactly as declared: `adv_1=99WMIU1JLQ3/10.122.84.203`, `adv_2=9484O9IOVJK/10.122.84.204`, `ext_1=94HIZLNUVCI/10.122.84.55`, and `ext_2=90SRMMW6APK/10.122.84.56`.
- Obtain switch onboarding credentials only from Jenkins credential `ANSIBLE_NXOS_SWITCH_CREDENTIALS`; never put controller or switch credentials in Consul, YAML, snapshots, manifests, logs, or artifacts.
- Require a validated before-image for every managed domain before mutation. Store snapshots outside the collection at `${BASE_DIRECTORY}/.nd-prerequisite-recovery/<run-id>` with directory mode `0700` and file mode `0600`.
- Fail closed on unknown schema, missing fabric, duplicate or missing switch, missing credential, unsupported role, unavailable required interface, API error, HTTP 207, deployment timeout, stale runtime variables, lock conflict, restore mismatch, or CAS mismatch.
- Poll every 15 seconds, with a 5-minute normal timeout, a 10-minute vPC/switch timeout, and no more than 3 consecutive API errors. A fixed sleep is never convergence proof.
- Preserve a target failure after successful restoration. If restoration or normalized comparison fails, keep the snapshot, set `ND_LAB_QUARANTINED=true`, and stop later targets.
- All 19 Consul playbooks receive structured `nd_prerequisite` metadata, but dormant smoke playbooks remain disabled in `PLAYBOOK_FILES`.
- `nd_manage_vrfs` and `nd_manage_networks` use only the `standalone` topology on `Siva_Fabric_Adv`; MSD/MCFG suites are out of scope.
- Publish Consul keys with revision-aware CAS, verify each written byte sequence, roll back partial writes, and publish `ansible-nd/nd_prerequisite_release_manifest.json` last. Delete no Consul key.
- Do not edit or commit the dirty cisco.nd source checkout at `/Users/sivakasi/ansible/collections/ansible_collections/cisco/nd`.
- Preserve the Jenkinsfile's existing safe repository synchronization: validated remote ref, commit/tree/branch/origin/tracked-state checks, staged clone, timestamped backup/rollback, and no `rm -rf nd` fallback.
- The Jenkins target workspace is not a Git repository. Replace per-task Git commits with restricted before-images plus SHA-256 checkpoint reports; never initialize Git there.
- Task 1's restricted Consul snapshot is its checkpoint. After the passing verification step of Tasks 2-11, run `python3 tests/validate_nd_prerequisites.py checkpoint --root . --label task-N --output ../.nd-consul-release-backups/checkpoints/task-N.json`; do not check off the task until that mode-`0600` report exists.
- Do not overwrite a OneDrive dataless playbook without first hydrating and hashing its current Consul source.
- Do not use `ignore_errors` in prerequisite preparation, restoration, release validation, or publication. Diagnostic failures may be recorded but cannot become success.

## File Structure

### Create

- `tests/nd_prerequisite_profiles.yaml` — schema-versioned lab registry and every `smoke.*` / `integration.*` topology contract.
- `tests/nd_prerequisite_wrapper.yaml` — stable phase entry point and phase/profile/run validation.
- `tests/nd_prerequisite_capture.yaml` — live read-only discovery, normalized before-image construction, and restricted snapshot persistence.
- `tests/nd_prerequisite_reconcile.yaml` — membership, role, vPC, interface, resource, save, and deploy reconciliation.
- `tests/nd_prerequisite_wait.yaml` — bounded polling and HTTP/API failure accounting.
- `tests/nd_prerequisite_verify.yaml` — explicit fabric/switch/interface/vPC/resource assertions and runtime-variable emission.
- `tests/nd_prerequisite_restore.yaml` — dependency-ordered removal, normalized reconstruction, comparison, and quarantine reporting.
- `tests/validate_nd_prerequisites.py` — registry/playbook/Jenkins/release validation and manifest generation.
- `tests/publish_nd_prerequisites.py` — Consul snapshot, CAS publication, verification, and rollback CLI.
- `tests/nd_prerequisite_release_manifest.json` — manifest schema, release ID, key paths, lengths, and SHA-256 values.
- `tests/test_validate_nd_prerequisites.py` — unit tests for registry, target coverage, playbook summaries, sanitization, and normalized comparison.
- `tests/test_publish_nd_prerequisites.py` — in-memory Consul tests for snapshot, CAS conflict, rollback, and manifest-last behavior.
- `tests/test_jenkins_nd_prerequisites.py` — structural Jenkins tests and extracted Bash syntax checks.
- `tests/fixtures/nd_prerequisite/inventory.yaml` — non-secret localhost inventory used only for parsing and fixture execution.
- `tests/fixtures/nd_prerequisite/consul_records.json` — non-secret fake Consul revisions and values used by unit tests.
- `tests/fixtures/nd_prerequisite/valid_state.yaml` — controller fixture with retained fabrics, four switches, virtual vPC, and interface/API responses.
- `tests/fixtures/nd_prerequisite/transitions.yaml` — convergence, 207, timeout, link-down, lock, restore, and resource-manager failure sequences.

### Modify

- `Jenkinsfile_nd_jenkins_script` — verified Consul release install, cross-job lock, common target lifecycle, credentials, target-loop refactor, quarantine handling, and result preservation.
- `tests/run_integration_module.yaml` — consume generated runtime variables, remove generic pre-clean, and make optional target cleanup visible.
- `playbooks/*.yaml` (all 19 named in the spec) — embedded prerequisite summaries and retained/disposable fabric safety corrections.
- `consul/reset_fabric.yaml` — manual emergency cleanup limited to namespaced disposable state.
- `docs/superpowers/specs/2026-08-26-nd-integration-prerequisite-orchestration-design.md` — implementation-status update only.

### Stable Interfaces

```text
validate_nd_prerequisites.py validate --root PATH --jenkinsfile PATH [--secret-scan]
validate_nd_prerequisites.py manifest --root PATH --output PATH --release-id ID
validate_nd_prerequisites.py checkpoint --root PATH --label LABEL --output PATH
publish_nd_prerequisites.py snapshot [--allow-absent] --address URL --prefix ansible-nd --keys-file MANIFEST --output DIR
publish_nd_prerequisites.py publish --address URL --prefix ansible-nd --manifest MANIFEST --backup-dir DIR
publish_nd_prerequisites.py verify --address URL --prefix ansible-nd --manifest MANIFEST

ansible-playbook -i INVENTORY nd_prerequisite_wrapper.yaml \
  -e nd_prerequisite_phase=preflight|prepare|restore|verify-restored \
  -e nd_prerequisite_profile=PROFILE_ID \
  -e nd_prerequisite_run_id=RUN_ID \
  -e nd_prerequisite_state_dir=ABSOLUTE_DIR
```

The wrapper writes `${nd_prerequisite_state_dir}/runtime-vars.yaml` only after successful prepare and includes `nd_prerequisite_run_id`, `nd_prerequisite_profile`, `nd_prerequisite_prepared: true`, and the target-specific extra variables. Jenkins passes it as `--extra-vars @<absolute-path>` and rejects any mismatched marker.

---

### Task 1: Add Safe Consul Source Snapshotting

**Files:**

- Create: `tests/publish_nd_prerequisites.py`
- Create: `tests/test_publish_nd_prerequisites.py`
- Create: `tests/fixtures/nd_prerequisite/consul_records.json`

**Interfaces:**

- Consumes: Consul KV JSON response fields `Key`, `Value`, `ModifyIndex`, and optional `Flags`.
- Produces: immutable `KVRecord(key: str, value: bytes | None, modify_index: int, exists: bool)`, `ConsulKV.read(key, allow_absent=False)`, and `snapshot_keys(client, keys, output_dir, allow_absent=False) -> dict[str, KVRecord]` for later publication tasks.

- [ ] **Step 1: Write the failing snapshot tests**

```python
def test_snapshot_decodes_bytes_and_records_revision(tmp_path):
    client = FakeConsul({"ansible-nd/nd_manage_acl.yaml": (41, b"---\n- hosts: nd\n")})
    records = snapshot_keys(client, ["ansible-nd/nd_manage_acl.yaml"], tmp_path)
    record = records["ansible-nd/nd_manage_acl.yaml"]
    assert record.modify_index == 41
    assert record.value == b"---\n- hosts: nd\n"
    assert (tmp_path / "ansible-nd" / "nd_manage_acl.yaml").read_bytes() == record.value
    assert (tmp_path.stat().st_mode & 0o777) == 0o700
    assert ((tmp_path / "ansible-nd" / "nd_manage_acl.yaml").stat().st_mode & 0o777) == 0o600


def test_snapshot_rejects_empty_or_missing_key(tmp_path):
    client = FakeConsul({"ansible-nd/empty.yaml": (9, b"")})
    with pytest.raises(ReleaseError, match="empty"):
        snapshot_keys(client, ["ansible-nd/empty.yaml"], tmp_path)


def test_publication_snapshot_records_absent_new_key_without_creating_it(tmp_path):
    client = FakeConsul({})
    records = snapshot_keys(client, ["ansible-nd/nd_prerequisite_wrapper.yaml"], tmp_path, allow_absent=True)
    assert records["ansible-nd/nd_prerequisite_wrapper.yaml"] == KVRecord(
        key="ansible-nd/nd_prerequisite_wrapper.yaml", value=None,
        modify_index=0, exists=False,
    )
    assert client.put_order == []
```

Define the unit-test fake in the same test module so no network call is possible:

```python
class FakeConsul:
    def __init__(self, records):
        self.records = {
            key: KVRecord(key, value, revision, True)
            for key, (revision, value) in records.items()
        }
        self.put_order = []

    def read(self, key, allow_absent=False):
        if key in self.records:
            return self.records[key]
        if allow_absent:
            return KVRecord(key, None, 0, False)
        raise ReleaseError(f"missing Consul value: {key}")
```

- [ ] **Step 2: Run the focused tests and confirm the missing implementation failure**

Run: `python3 -m pytest tests/test_publish_nd_prerequisites.py -q`

Expected: collection fails because `publish_nd_prerequisites` and `snapshot_keys` do not exist.

- [ ] **Step 3: Implement the byte-safe Consul client and snapshot primitive**

```python
@dataclasses.dataclass(frozen=True)
class KVRecord:
    key: str
    value: bytes | None
    modify_index: int
    exists: bool = True


class ReleaseError(RuntimeError):
    pass


class ConsulKV:
    def __init__(self, address: str, timeout: int = 30):
        self.address = address.rstrip("/")
        self.timeout = timeout

    def read(self, key: str, allow_absent: bool = False) -> KVRecord:
        url = f"{self.address}/v1/kv/{urllib.parse.quote(key, safe='/')}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and allow_absent:
                return KVRecord(key, None, 0, False)
            raise
        if len(payload) != 1 or payload[0].get("Value") is None:
            raise ReleaseError(f"missing Consul value: {key}")
        value = base64.b64decode(payload[0]["Value"], validate=True)
        if not value:
            raise ReleaseError(f"empty Consul value: {key}")
        return KVRecord(key, value, int(payload[0]["ModifyIndex"]), True)


def snapshot_keys(client, keys, output_dir, allow_absent=False):
    output_dir = pathlib.Path(output_dir)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    records = {}
    for key in keys:
        record = client.read(key, allow_absent=allow_absent)
        if record.exists:
            path = output_dir / pathlib.PurePosixPath(key)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(record.value)
            path.chmod(0o600)
        records[key] = record
    return records
```

The CLI `snapshot` subcommand must read the exact key list from a JSON manifest, refuse symlink destinations, write `records.json` containing revisions and SHA-256 hashes but no values, and never print content.

- [ ] **Step 4: Run snapshot tests and CLI help**

Run: `python3 -m pytest tests/test_publish_nd_prerequisites.py -q && python3 tests/publish_nd_prerequisites.py --help`

Expected: snapshot tests pass; help lists `snapshot` and exits 0.

- [ ] **Step 5: Capture a restricted before-image checkpoint before hydrating OneDrive playbooks**

Run from `nd/` with a unique sibling directory: `umask 077 && python3 tests/publish_nd_prerequisites.py snapshot --address http://10.78.210.155:8500 --prefix ansible-nd --keys-file tests/nd_prerequisite_release_manifest.json --output ../.nd-consul-release-backups/consul-before-20260826`

Expected: every requested existing key has nonzero bytes, a revision, and a SHA-256 entry; no credential-bearing inventory or generated output is included. If the final manifest does not exist yet, use a temporary JSON key list containing the 19 playbooks plus `run_integration_module.yaml` and `reset_fabric.yaml`, then delete only that temporary list after recording its hash in the execution log.

### Task 2: Build the Authoritative Registry and Static Validator

**Files:**

- Create: `tests/nd_prerequisite_profiles.yaml`
- Create: `tests/validate_nd_prerequisites.py`
- Create: `tests/test_validate_nd_prerequisites.py`

**Interfaces:**

- Consumes: the exact target arrays in `Jenkinsfile_nd_jenkins_script` and `nd_prerequisite` summaries in all playbooks.
- Produces: `load_registry(path) -> dict`, `validate_registry(registry) -> list[str]`, `jenkins_targets(text) -> dict[str, list[str]]`, `validate_playbook_summary(path, profile) -> list[str]`, `validate_fabric_delete_guards(paths) -> list[str]`, `sanitize_interface_payload(payload, switch_id, admin_state) -> dict`, and `normalized_equal(domain, before, after) -> bool`.

- [ ] **Step 1: Write failing registry coverage and invariant tests**

```python
EXPECTED_INTEGRATION = {
    "nd_manage_policy", "nd_manage_policy_group", "nd_manage_vrfs",
    "nd_manage_networks", "nd_manage_route_map", "nd_manage_acl",
    "nd_manage_l3out", "nd_interface_vpc_access",
    "nd_interface_vpc_trunk_host", "nd_manage_switches",
    "nd_manage_fabric", "nd_resource_manager", "nd_vpc_pair",
}
EXPECTED_SMOKE = {
    "nd_manage_acl", "nd_manage_prefix_list", "nd_manage_route_map",
    "nd_manage_vrfs", "nd_manage_networks", "nd_manage_policy",
    "nd_manage_policy_group", "nd_manage_switches", "nd_manage_vpc_pair",
    "nd_interface_vpc_access", "nd_interface_vpc_trunk_host",
    "nd_manage_vrf_lite", "nd_manage_l3out", "nd_manage_resource_manager",
    "nd_manage_fabric_ibgp_vxlan", "nd_manage_fabric_ebgp_vxlan",
    "nd_manage_fabric_ai_ibgp_vxlan", "nd_manage_fabric_ai_ebgp_vxlan",
    "nd_manage_fabric_external",
}

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def registry():
    return load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")


@pytest.fixture
def playbook_dir():
    return ROOT / "playbooks"


@pytest.fixture
def wrapper_yaml():
    return ROOT / "tests/nd_prerequisite_wrapper.yaml"


@pytest.fixture
def runner_text():
    return (ROOT / "tests/run_integration_module.yaml").read_text(encoding="utf-8")


@pytest.fixture
def runner_yaml():
    return yaml.safe_load((ROOT / "tests/run_integration_module.yaml").read_text(encoding="utf-8"))


def test_registry_has_every_profile_and_distinct_lab_switches(registry):
    assert set(registry["lab"]["switches"]) == {"adv_1", "adv_2", "ext_1", "ext_2"}
    serials = [v["serial"] for v in registry["lab"]["switches"].values()]
    assert len(serials) == len(set(serials)) == 4
    ids = set(registry["profiles"])
    assert {f"integration.{name}" for name in EXPECTED_INTEGRATION} <= ids
    assert {f"smoke.{name}" for name in EXPECTED_SMOKE} == {i for i in ids if i.startswith("smoke.")}


def test_retained_fabrics_cannot_be_declared_disposable(registry):
    for profile in registry["profiles"].values():
        for fabric in profile["fabrics"]:
            if fabric["name"] in {"Siva_Fabric_Adv", "Siva_External_Fabric"}:
                assert fabric["lifecycle"] == "retained"
```

- [ ] **Step 2: Run validator tests and confirm they fail before the registry exists**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -q`

Expected: failure names `tests/nd_prerequisite_profiles.yaml` or missing validator functions.

- [ ] **Step 3: Write the schema-versioned lab registry and exact profile contracts**

Start the file with this exact registry contract:

```yaml
schema_version: 1
lab:
  retained_fabrics:
    advanced: {name: Siva_Fabric_Adv, type: vxlanIbgp}
    external: {name: Siva_External_Fabric, type: externalConnectivity}
  switches:
    adv_1: {baseline_fabric_ref: advanced, serial: 99WMIU1JLQ3, seed_ip: 10.122.84.203}
    adv_2: {baseline_fabric_ref: advanced, serial: 9484O9IOVJK, seed_ip: 10.122.84.204}
    ext_1: {baseline_fabric_ref: external, serial: 94HIZLNUVCI, seed_ip: 10.122.84.55}
    ext_2: {baseline_fabric_ref: external, serial: 90SRMMW6APK, seed_ip: 10.122.84.56}
  retained_fabric_names: [Siva_Fabric_Adv, Siva_External_Fabric]
  interface_allowlist:
    adv_1: [Ethernet1/1, Ethernet1/2, Ethernet1/5, Ethernet1/6, Ethernet1/7, Ethernet1/8, Ethernet1/9, Ethernet1/10, Ethernet1/20]
    adv_2: [Ethernet1/1, Ethernet1/2, Ethernet1/5, Ethernet1/6, Ethernet1/7, Ethernet1/8, Ethernet1/9, Ethernet1/10]
    ext_1: [Ethernet1/1, Ethernet1/2]
    ext_2: []
profiles: {}
```

Populate `profiles` with each contract below. A switch tuple is `(logical_ref, desired_role)`; a link mapping names every administrative interface the wrapper may touch; `virtual_vpc=true` requires peers `adv_1/adv_2` with no physical peer-link ports.

```python
PROFILE_EXPECTATIONS = {
    "smoke.nd_manage_acl": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_prefix_list": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_route_map": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_vrfs": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_networks": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_policy": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf")], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_policy_group": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_switches": {"fabrics": ["advanced"], "switches": [("adv_1", "preserve"), ("adv_2", "preserve")], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_vpc_pair": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {}, "virtual_vpc": True},
    "smoke.nd_interface_vpc_access": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {"adv_1": ["Ethernet1/5", "Ethernet1/6", "Ethernet1/7"], "adv_2": ["Ethernet1/5", "Ethernet1/6", "Ethernet1/7"]}, "virtual_vpc": True},
    "smoke.nd_interface_vpc_trunk_host": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {"adv_1": ["Ethernet1/8", "Ethernet1/9", "Ethernet1/10"], "adv_2": ["Ethernet1/8", "Ethernet1/9", "Ethernet1/10"]}, "virtual_vpc": True},
    "smoke.nd_manage_vrf_lite": {"fabrics": ["advanced"], "switches": [("adv_1", "border")], "links": {"adv_1": ["Ethernet1/20"]}, "virtual_vpc": False},
    "smoke.nd_manage_l3out": {"fabrics": ["advanced", "external"], "switches": [("adv_1", "border"), ("ext_1", "edge_router")], "links": {"adv_1": ["Ethernet1/1"], "ext_1": ["Ethernet1/1"]}, "virtual_vpc": False},
    "smoke.nd_manage_resource_manager": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_fabric_ibgp_vxlan": {"fabrics": ["disposable_ibgp"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_fabric_ebgp_vxlan": {"fabrics": ["disposable_ebgp"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_fabric_ai_ibgp_vxlan": {"fabrics": ["disposable_ai_ibgp"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_fabric_ai_ebgp_vxlan": {"fabrics": ["disposable_ai_ebgp"], "switches": [], "links": {}, "virtual_vpc": False},
    "smoke.nd_manage_fabric_external": {"fabrics": ["disposable_external"], "switches": [], "links": {}, "virtual_vpc": False},
    "integration.nd_manage_policy": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {}, "virtual_vpc": False},
    "integration.nd_manage_policy_group": {"fabrics": ["advanced"], "switches": [("adv_1", "preserve"), ("adv_2", "preserve"), ("ext_1", "leaf")], "links": {}, "virtual_vpc": False},
    "integration.nd_manage_vrfs": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf")], "links": {}, "virtual_vpc": False},
    "integration.nd_manage_networks": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf")], "links": {"adv_1": ["Ethernet1/20"]}, "virtual_vpc": False},
    "integration.nd_manage_route_map": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "integration.nd_manage_acl": {"fabrics": ["advanced"], "switches": [], "links": {}, "virtual_vpc": False},
    "integration.nd_manage_l3out": {"fabrics": ["advanced", "external"], "switches": [("adv_1", "border"), ("ext_1", "edge_router")], "links": {"adv_1": ["Ethernet1/1", "Ethernet1/2"], "ext_1": ["Ethernet1/1", "Ethernet1/2"]}, "virtual_vpc": False},
    "integration.nd_interface_vpc_access": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {"adv_1": ["Ethernet1/5", "Ethernet1/6", "Ethernet1/7"], "adv_2": ["Ethernet1/5", "Ethernet1/6", "Ethernet1/7"]}, "virtual_vpc": True},
    "integration.nd_interface_vpc_trunk_host": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {"adv_1": ["Ethernet1/8", "Ethernet1/9", "Ethernet1/10"], "adv_2": ["Ethernet1/8", "Ethernet1/9", "Ethernet1/10"]}, "virtual_vpc": True},
    "integration.nd_manage_switches": {"fabrics": ["advanced", "external"], "switches": [("adv_1", "leaf"), ("adv_2", "spine"), ("ext_1", "border")], "links": {}, "virtual_vpc": False},
    "integration.nd_manage_fabric": {"fabrics": [], "switches": [], "links": {}, "virtual_vpc": False},
    "integration.nd_resource_manager": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {}, "virtual_vpc": True},
    "integration.nd_vpc_pair": {"fabrics": ["advanced"], "switches": [("adv_1", "leaf"), ("adv_2", "leaf")], "links": {}, "virtual_vpc": False},
}
```

Resolve fabric refs exactly as follows: `advanced=Siva_Fabric_Adv/vxlanIbgp/retained`, `external=Siva_External_Fabric/externalConnectivity/retained`, `disposable_ibgp=ANSIBLE_NIGHTLY_IBGP/vxlanIbgp/disposable`, `disposable_ebgp=ANSIBLE_NIGHTLY_EBGP/vxlanEbgp/disposable`, `disposable_ai_ibgp=ANSIBLE_NIGHTLY_AI_IBGP/aimlVxlanIbgp/disposable`, `disposable_ai_ebgp=ANSIBLE_NIGHTLY_AI_EBGP/aimlVxlanEbgp/disposable`, and `disposable_external=ANSIBLE_NIGHTLY_EXTERNAL/externalConnectivity/disposable`.

Each YAML profile has `profile_id`, `execution_style`, `fabrics`, `switches.required_count`, `switches.members`, `vpc_pairs`, `links`, `resources`, `managed_domains`, `runtime_vars`, `timeouts`, and `restore: verified_normalized_snapshot`. Every declared link uses `admin_state: true` and `operational_state: when_reported_up`. `smoke.nd_manage_resource_manager` requires existing `L3_VNI` and `ID` pools; `integration.nd_resource_manager` requires the existing virtual pair no-create path. `integration.nd_manage_switches` adds `snapshot_switch_refs: [adv_1, adv_2, ext_1, ext_2]`. Managed domains use the exact mutation families defined in the spec; composite network, L3Out, vPC-interface, resource-manager, and switch profiles include every listed dependency domain.

- [ ] **Step 4: Implement the static validation API**

```python
ALLOWED_ROLES = {"leaf", "spine", "border", "edge_router", "preserve"}
RETAINED = {"Siva_Fabric_Adv", "Siva_External_Fabric"}


class ValidationError(ValueError):
    pass


def validate_registry(registry):
    errors = []
    if registry.get("schema_version") != 1:
        errors.append("schema_version must equal 1")
    switches = registry.get("lab", {}).get("switches", {})
    serials = [item.get("serial") for item in switches.values()]
    if len(serials) != len(set(serials)):
        errors.append("lab switch serials must be distinct")
    for profile_id, profile in registry.get("profiles", {}).items():
        if profile.get("profile_id") != profile_id:
            errors.append(f"{profile_id}: profile_id mismatch")
        members = profile.get("switches", {}).get("members", [])
        refs = [item.get("ref") for item in members]
        if len(refs) != len(set(refs)) or len(refs) != profile.get("switches", {}).get("required_count"):
            errors.append(f"{profile_id}: switch identities/count are invalid")
        for member in members:
            if member.get("desired_role") not in ALLOWED_ROLES:
                errors.append(f"{profile_id}: unsupported role {member.get('desired_role')}")
        for fabric in profile.get("fabrics", []):
            if fabric.get("name") in RETAINED and fabric.get("lifecycle") != "retained":
                errors.append(f"{profile_id}: retained fabric marked disposable")
    return errors


def load_registry(path):
    data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValidationError("profile registry must be a mapping")
    return data


def jenkins_targets(text):
    result = {}
    for name in ("PLAYBOOK_FILES", "INTEGRATION_MODULES", "STANDALONE_INTEGRATION_MODULES"):
        match = re.search(rf"def\s+{name}\s*=\s*\[(.*?)\]", text, re.S)
        if not match:
            raise ValidationError(f"missing Jenkins target array: {name}")
        active = []
        for raw_line in match.group(1).splitlines():
            line = raw_line.split("//", 1)[0]
            active.extend(re.findall(r"'([A-Za-z0-9_.-]+)'", line))
        result[name] = active
    return result


def validate_playbook_summary(path, profile):
    plays = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    actual = plays[0].get("vars", {}).get("nd_prerequisite") if isinstance(plays, list) and plays else None
    wanted = {
        "profile": profile["profile_id"],
        "fabric_types": [item["type"] for item in profile["fabrics"]],
        "switch_count": profile["switches"]["required_count"],
        "switch_roles": [item["desired_role"] for item in profile["switches"]["members"]],
    }
    return [] if actual == wanted else [f"{path}: nd_prerequisite summary mismatch"]


FABRIC_MODULES = {
    "cisco.nd.nd_manage_fabric_external", "cisco.nd.nd_manage_fabric_ibgp_vxlan",
    "cisco.nd.nd_manage_fabric_ebgp_vxlan", "cisco.nd.nd_manage_fabric_ai_ibgp_vxlan",
    "cisco.nd.nd_manage_fabric_ai_ebgp_vxlan",
}


def _task_lists(value):
    if isinstance(value, list):
        yield value
        for item in value:
            if isinstance(item, dict):
                for key in ("block", "rescue", "always"):
                    yield from _task_lists(item.get(key, []))


def validate_fabric_delete_guards(paths):
    errors = []
    for path in paths:
        plays = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for tasks in _task_lists([task for play in plays for task in play.get("tasks", [])]):
            for index, task in enumerate(tasks):
                module = next((key for key in FABRIC_MODULES if key in task), None)
                if not module or task[module].get("state") != "deleted":
                    continue
                serialized = json.dumps(task[module], sort_keys=True)
                if "Siva_Fabric_Adv" in serialized or "Siva_External_Fabric" in serialized:
                    errors.append(f"{path}: retained fabric in delete config")
                guard = json.dumps(tasks[index - 1], sort_keys=True) if index else ""
                if "^ANSIBLE_NIGHTLY_" not in guard or "Siva_External_Fabric" not in guard or "Siva_Fabric_Adv" not in guard:
                    errors.append(f"{path}: fabric delete lacks namespace/retained guard")
    return errors


READ_ONLY_INTERFACE_KEYS = {
    "operData", "status", "metadata", "createdOn", "lastModified",
    "uuid", "deploymentStatus", "configSyncStatus",
}


def _strip_read_only(value):
    if isinstance(value, dict):
        return {key: _strip_read_only(item) for key, item in value.items() if key not in READ_ONLY_INTERFACE_KEYS}
    if isinstance(value, list):
        return [_strip_read_only(item) for item in value]
    return value


def sanitize_interface_payload(payload, switch_id, admin_state):
    current = payload.get("current", payload)
    interface_name = current.get("interfaceName")
    policy = copy.deepcopy(current["configData"]["networkOS"]["policy"])
    policy = _strip_read_only(policy)
    if not interface_name or not re.fullmatch(r"Ethernet\d+/\d+", interface_name):
        raise ValidationError("physical interface name is absent or invalid")
    policy["adminState"] = bool(admin_state)
    return {
        "interfaceName": interface_name,
        "switchId": switch_id,
        "configData": {"networkOS": {"policy": policy}},
    }


SERVER_MANAGED_FIELDS = {"createdOn", "lastModified", "status", "metadata", "uuid"}


def _normalize(value):
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in sorted(value.items()) if key not in SERVER_MANAGED_FIELDS}
    if isinstance(value, list):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def normalized_equal(domain, before, after):
    if domain not in {
        "fabrics", "switches", "vpc_pairs", "physical_interfaces", "vpc_interfaces",
        "resource_allocations", "policies", "policy_groups", "vrfs", "networks",
        "l3outs", "acls", "prefix_lists", "route_maps", "vrf_lite",
    }:
        raise ValidationError(f"unsupported normalized domain: {domain}")
    return _normalize(before) == _normalize(after)


def write_checkpoint(root, label, output):
    root = pathlib.Path(root).resolve()
    paths = [root / "Jenkinsfile_nd_jenkins_script"]
    for folder in ("tests", "playbooks", "consul", "docs/superpowers"):
        paths.extend(path for path in (root / folder).rglob("*") if path.is_file() and not path.is_symlink())
    report = {
        "label": label,
        "files": {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(paths)) if path.exists()
        },
    }
    output = pathlib.Path(output)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)
```

The validator additionally walks each fabric-module delete task and requires an immediately preceding assertion proving both the `^ANSIBLE_NIGHTLY_` name and retained-name exclusion; literal retained names in a fabric delete config are always errors. It also rejects fixture-mode variables in Jenkins and verifies every manifest source is regular, non-symlinked, and nonempty.

- [ ] **Step 5: Run the focused registry, sanitizer, and target-coverage tests**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -q`

Expected: all tests pass, all 32 profile IDs resolve, and the duplicate third-switch regression is covered.

- [ ] **Step 6: Run the validator CLI against the current tree and record the expected metadata failures**

Run: `python3 tests/validate_nd_prerequisites.py validate --root . --jenkinsfile Jenkinsfile_nd_jenkins_script`

Expected: nonzero only because the 19 playbook summaries and remaining wrapper/release files are not implemented yet; the output lists every missing file/profile association without a Python traceback.

### Task 3: Implement Phase Dispatch, Read-Only Preflight, and Snapshot Capture

**Files:**

- Create: `tests/nd_prerequisite_wrapper.yaml`
- Create: `tests/nd_prerequisite_capture.yaml`
- Create: `tests/fixtures/nd_prerequisite/inventory.yaml`
- Create: `tests/fixtures/nd_prerequisite/valid_state.yaml`
- Modify: `tests/test_validate_nd_prerequisites.py`

**Interfaces:**

- Consumes: a validated profile from `nd_prerequisite_profiles.yaml`, phase/profile/run/state-dir variables, ND inventory credentials, and optional test-only fixture responses.
- Produces: `${state_dir}/snapshot.yaml`, `${state_dir}/snapshot.sha256`, `${state_dir}/preflight-report.json`, and in-memory facts `nd_profile`, `nd_snapshot`, and `nd_discovered`.

- [ ] **Step 1: Write failing wrapper-contract and no-mutation preflight tests**

```python
def test_wrapper_accepts_only_four_phases(wrapper_yaml):
    text = wrapper_yaml.read_text()
    assert "['preflight', 'prepare', 'restore', 'verify-restored']" in text
    assert "nd_prerequisite_run_id" in text
    assert "nd_prerequisite_state_dir" in text


def test_preflight_fixture_contains_no_mutating_methods(run_wrapper):
    result = run_wrapper("preflight", "integration.nd_manage_l3out", "valid_state.yaml")
    assert result.returncode == 0
    report = json.loads(result.state_dir.joinpath("preflight-report.json").read_text())
    assert set(report["http_methods"]) <= {"GET"}
    assert report["validated_fabrics"] == ["Siva_Fabric_Adv", "Siva_External_Fabric"]
```

Use this exact subprocess fixture for offline wrapper cases:

```python
@pytest.fixture
def run_wrapper(tmp_path):
    def _run(phase, profile, fixture_name, case="default", state_dir=None):
        state_dir = state_dir or (tmp_path / ".nd-prerequisite-recovery" / f"fixture-{phase}-{case}")
        command = [
            "ansible-playbook", "-i", "tests/fixtures/nd_prerequisite/inventory.yaml",
            "tests/nd_prerequisite_wrapper.yaml",
            "-e", f"nd_prerequisite_phase={phase}",
            "-e", f"nd_prerequisite_profile={profile}",
            "-e", f"nd_prerequisite_run_id=fixture-{phase}-{case}",
            "-e", f"nd_prerequisite_state_dir={state_dir}",
            "-e", "nd_prerequisite_fixture_mode=true",
            "-e", "nd_prerequisite_fixture_guard=offline-fixture-only",
            "-e", f"nd_prerequisite_fixture_file=tests/fixtures/nd_prerequisite/{fixture_name}",
            "-e", f"nd_prerequisite_fixture_case={case}",
        ]
        completed = subprocess.run(command, text=True, capture_output=True)
        completed.state_dir = state_dir
        return completed
    return _run
```

- [ ] **Step 2: Run the two wrapper tests and confirm the wrapper is missing**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k 'wrapper or preflight' -q`

Expected: failure identifies `nd_prerequisite_wrapper.yaml` as absent.

- [ ] **Step 3: Implement strict wrapper phase dispatch**

```yaml
---
- name: cisco.nd per-target prerequisite lifecycle
  hosts: nd
  gather_facts: false
  vars_files:
    - nd_prerequisite_profiles.yaml
  pre_tasks:
    - name: Validate lifecycle arguments
      ansible.builtin.assert:
        that:
          - nd_prerequisite_phase in ['preflight', 'prepare', 'restore', 'verify-restored']
          - nd_prerequisite_profile in profiles
          - nd_prerequisite_run_id is match('^[A-Za-z0-9_.-]+$')
          - nd_prerequisite_state_dir | length > 1
          - nd_prerequisite_state_dir is match('^/.+/.nd-prerequisite-recovery/.+$')
        fail_msg: Invalid prerequisite lifecycle arguments
    - name: Resolve selected profile
      ansible.builtin.set_fact:
        nd_profile: "{{ profiles[nd_prerequisite_profile] }}"
    - name: Restrict fixture mode to the isolated localhost fixture inventory
      ansible.builtin.assert:
        that:
          - inventory_hostname == 'fixture-nd'
          - ansible_connection == 'local'
          - nd_prerequisite_fixture_guard | default('') == 'offline-fixture-only'
        fail_msg: Fixture mode is permitted only in the isolated offline fixture inventory
      when: nd_prerequisite_fixture_mode | default(false) | bool
  tasks:
    - name: Discover and validate current prerequisite state
      ansible.builtin.include_tasks: nd_prerequisite_capture.yaml
      when: nd_prerequisite_phase in ['preflight', 'prepare']
    - name: Reconcile declared prerequisite state
      ansible.builtin.include_tasks: nd_prerequisite_reconcile.yaml
      when: nd_prerequisite_phase == 'prepare'
    - name: Verify prepared or preflight state
      ansible.builtin.include_tasks: nd_prerequisite_verify.yaml
      vars:
        nd_verify_mode: "{{ 'prepared' if nd_prerequisite_phase == 'prepare' else 'preflight' }}"
      when: nd_prerequisite_phase in ['preflight', 'prepare']
    - name: Restore captured state
      ansible.builtin.include_tasks: nd_prerequisite_restore.yaml
      when: nd_prerequisite_phase == 'restore'
    - name: Verify restored state
      ansible.builtin.include_tasks: nd_prerequisite_verify.yaml
      vars:
        nd_verify_mode: restored
      when: nd_prerequisite_phase == 'verify-restored'
```

- [ ] **Step 4: Implement discovery and validated snapshot persistence**

For live mode, gather exactly these endpoints with `cisco.nd.nd_rest` and `method: get`: `/api/v1/manage/fabrics/{fabric}`, `/api/v1/manage/fabrics/{fabric}/switches`, each declared physical interface, `vpcPairOverview?componentType=full`, `vpcPairConsistency`, and every profile-managed domain. For fixture mode, load `valid_state.yaml` locally and record GET operations without making network calls.

`nd_verify_mode: preflight` validates identity, supported fabric type, discoverability, credentials, allowlists, capture capability, and dependency safety while reporting desired-state drift; it must not require roles, vPC state, or admin state to already match. `nd_verify_mode: prepared` enforces the complete desired topology after reconciliation.

Persist this exact top-level shape only during `prepare`:

```yaml
schema_version: 1
run_id: "{{ nd_prerequisite_run_id }}"
profile_id: "{{ nd_prerequisite_profile }}"
captured_at_utc: "{{ now(utc=true, fmt='%Y-%m-%dT%H:%M:%SZ') }}"
fabrics: {}
switches: {}
vpc_pairs: {}
interfaces: {}
managed_domains: {}
intended_system_modes: {}
created_by_prepare: {fabrics: [], vpc_pairs: [], interfaces: [], resources: [], domain_objects: []}
```

Use delegated local `ansible.builtin.file` tasks to create the directory with `mode: '0700'`, `ansible.builtin.copy` with `mode: '0600'` for `snapshot.yaml`, and `ansible.builtin.stat(checksum_algorithm=sha256)` for `snapshot.sha256`. Assert that serialized content does not contain the environment values used for controller or switch usernames/passwords before writing.

The valid fixture uses the same response paths as live ND and contains no credentials:

```yaml
---
default:
  fabrics:
    Siva_Fabric_Adv: {current: {management: {type: vxlanIbgp}}}
    Siva_External_Fabric: {current: {management: {type: externalConnectivity}}}
  switches:
    Siva_Fabric_Adv:
      current:
        switches:
          - {switchId: 99WMIU1JLQ3, fabricManagementIp: 10.122.84.203, role: leaf, additionalData: {configSyncStatus: inSync, intendedSystemMode: normal}}
          - {switchId: 9484O9IOVJK, fabricManagementIp: 10.122.84.204, role: leaf, additionalData: {configSyncStatus: inSync, intendedSystemMode: normal}}
    Siva_External_Fabric:
      current:
        switches:
          - {switchId: 94HIZLNUVCI, fabricManagementIp: 10.122.84.55, role: edgeRouter, additionalData: {configSyncStatus: inSync, intendedSystemMode: normal}}
          - {switchId: 90SRMMW6APK, fabricManagementIp: 10.122.84.56, role: edgeRouter, additionalData: {configSyncStatus: inSync, intendedSystemMode: maintenance}}
  interfaces:
    default_response:
      current:
        interfaceName: Ethernet1/1
        configData: {networkOS: {policy: {adminState: true, policyType: routed}}}
        operData: {operationalStatus: up}
  vpc:
    overview: {inventory: {syncStatus: inSync}, networks: {pending: 0, outOfSync: 0, inProgress: 0}, vrfs: {pending: 0, outOfSync: 0, inProgress: 0}}
    consistency: {type2Consistency: true}
  resources: {pools: [{type: L3_VNI}, {type: ID}]}
  managed_domains: {}
```

- [ ] **Step 5: Add identity, credential, dependency, and interface preflight assertions**

```yaml
- name: Validate distinct discovered switches and required credentials
  ansible.builtin.assert:
    that:
      - nd_required_serials | length == (nd_required_serials | unique | length)
      - nd_required_serials | difference(nd_discovered_serials) | length == 0
      - not nd_requires_switch_movement or
        ((lookup('env', 'ANSIBLE_NXOS_SWITCH_USERNAME') | length > 0) and
         (lookup('env', 'ANSIBLE_NXOS_SWITCH_PASSWORD') | length > 0))
    fail_msg: Switch identity or onboarding credential preflight failed

- name: Reject undeclared physical interfaces
  ansible.builtin.assert:
    that:
      - item.1 in lab.interface_allowlist[item.0.switch_ref]
      - item.1 is match('^Ethernet[0-9]+/[0-9]+$')
    fail_msg: "Interface is not allowlisted: {{ item.0.switch_ref }}/{{ item.1 }}"
  loop: "{{ query('subelements', nd_profile.links | default([]), 'interfaces') }}"
```

Before allowing vPC deletion, assert that the overview shows zero existing vPC-interface, network, and VRF dependencies unless each dependency is listed in `created_by_prepare`. Before allowing any mutation, assert every `managed_domains` value was captured successfully and normalized.

- [ ] **Step 6: Run wrapper fixture tests and validate file modes**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k 'wrapper or preflight or snapshot' -q`

Expected: valid preflight passes, duplicate identity/missing credential/unexpected vPC dependency fixtures fail before mutation, snapshot mode checks pass, and no fixture record contains a non-GET operation.

### Task 4: Implement Reconciliation, Polling, Verification, and Runtime Variables

**Files:**

- Create: `tests/nd_prerequisite_reconcile.yaml`
- Create: `tests/nd_prerequisite_wait.yaml`
- Create: `tests/nd_prerequisite_verify.yaml`
- Create: `tests/fixtures/nd_prerequisite/transitions.yaml`
- Modify: `tests/test_validate_nd_prerequisites.py`

**Interfaces:**

- Consumes: `nd_profile`, `nd_snapshot`, Jenkins switch-credential environment variables, fixture/live API results, and sanitizer behavior from Task 2.
- Produces: converged declared topology plus a mode-`0600` `${state_dir}/runtime-vars.yaml` whose fresh run/profile markers Jenkins can verify.

- [ ] **Step 1: Write failing transition and runtime-variable tests**

```python
@pytest.mark.parametrize("case,expected", [
    ("already_up", 0),
    ("admin_down_then_up", 0),
    ("oper_down_after_deploy", 1),
    ("vpc_timeout", 1),
    ("http_207", 1),
])
def test_prepare_transition_outcomes(run_wrapper, case, expected):
    result = run_wrapper("prepare", "integration.nd_interface_vpc_access", "transitions.yaml", case=case)
    assert (result.returncode != 0) == bool(expected)


def test_runtime_vars_are_target_specific_and_fresh(run_wrapper):
    result = run_wrapper("prepare", "integration.nd_manage_l3out", "valid_state.yaml")
    data = yaml.safe_load(result.state_dir.joinpath("runtime-vars.yaml").read_text())
    assert data["nd_prerequisite_prepared"] is True
    assert data["nd_prerequisite_profile"] == "integration.nd_manage_l3out"
    assert data["nd_test_switch1_id"] == "99WMIU1JLQ3"
    assert data["nd_test_switch2_id"] == "94HIZLNUVCI"
    assert data["nd_test_switch1_interface"] == "Ethernet1/1"
```

- [ ] **Step 2: Run transition tests and confirm missing task-file failures**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k 'transition or runtime_vars' -q`

Expected: failure identifies reconcile/wait/verify files or missing runtime output.

The transition fixture is deterministic and uses this exact case contract:

```yaml
---
cases:
  already_up:
    interface_admin_sequence: [true]
    interface_oper_sequence: [up]
    switch_sync_sequence: [inSync]
    api_status_sequence: [200]
  admin_down_then_up:
    interface_admin_sequence: [false, true]
    interface_oper_sequence: [down, up]
    switch_sync_sequence: [outOfSync, inSync]
    api_status_sequence: [200, 200]
  oper_down_after_deploy:
    interface_admin_sequence: [false, true]
    interface_oper_sequence: [down, down, down, down]
    switch_sync_sequence: [outOfSync, inSync]
    api_status_sequence: [200, 200, 200, 200]
  vpc_timeout:
    vpc_sync_sequence: [outOfSync, outOfSync, outOfSync, outOfSync]
    api_status_sequence: [200, 200, 200, 200]
  http_207:
    api_status_sequence: [207]
    object_failures: [{switchId: 9484O9IOVJK, message: simulated-partial-failure}]
  restore_success:
    restore_match: true
    captured_system_modes: {99WMIU1JLQ3: normal, 9484O9IOVJK: maintenance}
  restore_mismatch:
    restore_match: false
    mismatched_domains: [switches]
  existing_virtual_pair:
    pair_present: true
    use_virtual_peer_link: true
    dependencies: {vpc_interfaces: 0, networks: 0, vrfs: 0}
```

The fixture adapter consumes one sequence element per poll and repeats the last element when a sequence is exhausted. It records every simulated method, path, and redacted payload in the phase report so tests can prove no physical-peer-link creation and no undeclared mutation occurred.

- [ ] **Step 3: Implement membership and role reconciliation without replaced-state churn**

For a borrowed switch, use its captured source fabric—not the static baseline table—as the removal source: enter captured maintenance mode when required, remove exactly that seed IP from the captured source with `cisco.nd.nd_manage_switches state=deleted`, save/deploy, and poll until absent. Then use `cisco.nd.nd_manage_switches state=merged` on the desired fabric with masked environment lookups and switch-scoped save/deploy. Never use `replaced` or `overridden` for prerequisite membership. For role-only changes on an existing member, call `changeRoles` directly:

```yaml
- name: Remove borrowed switch from its captured source fabric
  cisco.nd.nd_manage_switches:
    fabric: "{{ item.captured_fabric }}"
    state: deleted
    config:
      - seed_ip: "{{ item.seed_ip }}"
    config_actions: {save: true, deploy: true, type: switch}
  loop: "{{ nd_membership_moves }}"
  no_log: true

- name: Onboard borrowed switch into the declared destination
  cisco.nd.nd_manage_switches:
    fabric: "{{ item.desired_fabric }}"
    state: merged
    config:
      - seed_ip: "{{ item.seed_ip }}"
        username: "{{ lookup('env', 'ANSIBLE_NXOS_SWITCH_USERNAME') }}"
        password: "{{ lookup('env', 'ANSIBLE_NXOS_SWITCH_PASSWORD') }}"
        role: "{{ item.desired_role }}"
        preserve_config: true
    config_actions: {save: true, deploy: true, type: switch}
  loop: "{{ nd_membership_moves }}"
  no_log: true
```

The capture must prove that each borrowed switch has exactly one source membership and must store the complete source-fabric configuration needed to reverse the move. Poll source absence before onboarding and destination `inSync` after onboarding. For role-only changes on an existing member, call `changeRoles` directly:

```yaml
- name: Change roles for existing members only
  cisco.nd.nd_rest:
    path: "/api/v1/manage/fabrics/{{ item.fabric }}/switchActions/changeRoles"
    method: post
    content:
      switchRoles:
        - switchId: "{{ item.serial }}"
          role: "{{ nd_api_role_map[item.desired_role] }}"
  loop: "{{ nd_role_changes }}"
  register: nd_role_change_results

- name: Reject partial role-change responses
  ansible.builtin.assert:
    that:
      - item.status | default(200) | int != 207
      - not (item.failed | default(false))
  loop: "{{ nd_role_change_results.results | default([]) }}"
```

Map `edge_router` to ND wire value `edgeRouter`; leave `preserve` out of the mutation list. Capture each affected switch's `additionalData.intendedSystemMode`, use `cisco.nd.nd_maintenance_mode` only for disruptive membership/role work, and do not force all switches into maintenance.

- [ ] **Step 4: Implement vPC, physical-interface, save, and targeted-deploy reconciliation**

Create an absent declared pair with `cisco.nd.nd_manage_vpc_pair state=merged` and `use_virtual_peer_link: true`. Never specify physical peer-link interfaces. For a raw physical-interface update, construct a sanitized request and PUT only the allowlisted endpoint, then deploy exact pairs:

```yaml
- name: Deploy allowlisted physical interfaces
  cisco.nd.nd_rest:
    path: "/api/v1/manage/fabrics/{{ nd_fabric_name }}/interfaceActions/deploy"
    method: post
    content:
      interfaces: "{{ nd_interface_deploy_pairs }}"
  when: nd_interface_deploy_pairs | length > 0

- name: Save recalculated fabric configuration
  cisco.nd.nd_rest:
    path: "/api/v1/manage/fabrics/{{ nd_fabric_name }}/actions/configSave"
    method: post
    content: {}
```

Each deploy pair is exactly `{interfaceName: EthernetX/Y, switchId: SERIAL}`. Physical Ethernet interfaces are PUT/normalized only; they are never deleted.

- [ ] **Step 5: Implement bounded polling with explicit failure counters**

```yaml
- name: Poll affected switches until configuration is synchronized
  cisco.nd.nd_rest:
    path: "/api/v1/manage/fabrics/{{ nd_poll_fabric }}/switches"
    method: get
  register: nd_poll_result
  until:
    - not (nd_poll_result.failed | default(false))
    - nd_poll_result.current.switches
      | selectattr('switchId', 'in', nd_poll_switch_ids)
      | map(attribute='additionalData.configSyncStatus')
      | map('lower') | unique | list == ['insync']
  retries: "{{ 40 if nd_poll_kind in ['vpc', 'switch'] else 20 }}"
  delay: 15
```

Wrap individual GET failures with a counter fact and abort after the third consecutive error. Reset the counter only after a successful GET. Treat HTTP 207 as failure and include per-object response details in the redacted report.

- [ ] **Step 6: Implement explicit prepared-state verification and runtime mapping**

Assert the exact response paths from the spec: fabric `current.management.type`; switch `current.switches[]` identity, management IP, role, `configSyncStatus`, and `intendedSystemMode`; interface `current.configData.networkOS.policy.adminState` plus optional normalized operational status; vPC overview zero `pending`, `outOfSync`, and `inProgress`; consistency not `type2Consistency: false`; resource pool existence.

Write runtime variables by profile. The required mappings are:

```yaml
integration.nd_manage_policy:
  fabric_name: Siva_Fabric_Adv
  switch_serial_1: 99WMIU1JLQ3
  switch_serial_2: 9484O9IOVJK
integration.nd_manage_policy_group:
  fabric_name: Siva_Fabric_Adv
  switch_serial_1: 99WMIU1JLQ3
  switch_serial_2: 9484O9IOVJK
  switch_serial_3: 94HIZLNUVCI
integration.nd_manage_vrfs:
  nd_vrf_test_topology: standalone
  ansible_it_fabric: Siva_Fabric_Adv
  ansible_switch1: 10.122.84.203
integration.nd_manage_networks:
  nd_network_test_topology: standalone
  ansible_it_fabric: Siva_Fabric_Adv
  ansible_switch1: 10.122.84.203
  ansible_network_interface1: Ethernet1/20
integration.nd_manage_route_map:
  nd_test_fabric_name: Siva_Fabric_Adv
integration.nd_manage_acl:
  acl_test_fabric: Siva_Fabric_Adv
integration.nd_manage_l3out:
  nd_test_fabric_name: Siva_Fabric_Adv
  nd_test_fabric1_name: Siva_Fabric_Adv
  nd_test_fabric2_name: Siva_External_Fabric
  nd_test_switch1_id: 99WMIU1JLQ3
  nd_test_switch2_id: 94HIZLNUVCI
  nd_test_switch1_mgmt_ip: 10.122.84.203
  nd_test_switch2_mgmt_ip: 10.122.84.55
  nd_test_switch1_interface: Ethernet1/1
  nd_test_switch2_interface: Ethernet1/1
  nd_test_switch1_subif: Ethernet1/2
  nd_test_switch2_subif: Ethernet1/2
integration.nd_interface_vpc_access:
  nd_test_fabric_name: Siva_Fabric_Adv
  nd_test_vpc_access_fabric_name: Siva_Fabric_Adv
  nd_test_vpc_peer1_ip: 10.122.84.203
  nd_test_vpc_peer2_ip: 10.122.84.204
integration.nd_interface_vpc_trunk_host:
  nd_test_fabric_name: Siva_Fabric_Adv
  nd_test_vpc_trunk_host_fabric_name: Siva_Fabric_Adv
  nd_test_vpc_peer1_ip: 10.122.84.203
  nd_test_vpc_peer2_ip: 10.122.84.204
integration.nd_manage_switches:
  ansible_it_fabric: Siva_Fabric_Adv
  ansible_switch1: 10.122.84.203
  ansible_switch2: 10.122.84.204
  ansible_switch3: 10.122.84.55
integration.nd_manage_fabric: {}
integration.nd_resource_manager:
  ansible_it_fabric: Siva_Fabric_Adv
  ansible_switch1: 10.122.84.203
  ansible_switch2: 10.122.84.204
  ansible_sno_1: 99WMIU1JLQ3
  ansible_sno_2: 9484O9IOVJK
  intf_1_2: Ethernet1/2
  intf_1_3: Ethernet1/3
  intf_1_10: Ethernet1/10
integration.nd_vpc_pair:
  fabric_name: Siva_Fabric_Adv
  switch1_serial: 99WMIU1JLQ3
  switch2_serial: 9484O9IOVJK
  fabric_type: vxlanIbgp
```

Smoke profiles write only the variables their playbook already consumes plus the three fresh lifecycle markers. No runtime file contains `switch_username`, `switch_password`, controller credentials, or their environment values.

- [ ] **Step 7: Run transition, sanitizer, convergence, and runtime mapping tests**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k 'transition or sanitizer or convergence or runtime' -q`

Expected: already-up and admin-down-then-up converge; oper-down, 207, timeout, and fourth consecutive API-error paths fail; every target gets a fresh matching runtime file.

### Task 5: Implement Dependency-Aware Restoration and Quarantine

**Files:**

- Create: `tests/nd_prerequisite_restore.yaml`
- Modify: `tests/nd_prerequisite_verify.yaml`
- Modify: `tests/fixtures/nd_prerequisite/transitions.yaml`
- Modify: `tests/test_validate_nd_prerequisites.py`

**Interfaces:**

- Consumes: validated snapshot plus `created_by_prepare`, the selected profile's managed domains, and live/fixture current state.
- Produces: restored normalized state or retained recovery material plus `${state_dir}/recovery-report.json` and `${state_dir}/QUARANTINED`.

- [ ] **Step 1: Write failing restoration-order and failure-injection tests**

```python
def test_restore_order_is_dependency_safe(run_wrapper):
    prepared = run_wrapper("prepare", "integration.nd_interface_vpc_access", "transitions.yaml", case="restore_success")
    assert prepared.returncode == 0
    result = run_wrapper("restore", "integration.nd_interface_vpc_access", "transitions.yaml", case="restore_success", state_dir=prepared.state_dir)
    assert result.returncode == 0
    report = json.loads(result.state_dir.joinpath("restore-report.json").read_text())
    assert report["steps"] == [
        "remove-target-created", "restore-fabric-for-membership",
        "restore-switch-membership-and-roles", "restore-dependent-domains",
        "restore-managed-domains", "restore-vpc-pairs",
        "restore-physical-interfaces", "restore-virtual-interfaces",
        "delete-disposable-fabrics", "restore-system-modes", "compare-normalized",
    ]
    verified = run_wrapper("verify-restored", "integration.nd_interface_vpc_access", "transitions.yaml", case="restore_success", state_dir=prepared.state_dir)
    assert verified.returncode == 0
    assert not prepared.state_dir.joinpath("snapshot.yaml").exists()


def test_restore_mismatch_quarantines_and_keeps_snapshot(run_wrapper):
    prepared = run_wrapper("prepare", "integration.nd_manage_switches", "transitions.yaml", case="restore_mismatch")
    assert prepared.returncode == 0
    result = run_wrapper("restore", "integration.nd_manage_switches", "transitions.yaml", case="restore_mismatch", state_dir=prepared.state_dir)
    assert result.returncode != 0
    assert result.state_dir.joinpath("QUARANTINED").exists()
    assert result.state_dir.joinpath("snapshot.yaml").exists()
```

- [ ] **Step 2: Run restoration tests and confirm the restore implementation is absent**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k restore -q`

Expected: failure identifies missing restoration output/order/quarantine behavior.

- [ ] **Step 3: Implement the exact normalized restoration sequence**

```yaml
- name: Initialize restoration audit trail
  ansible.builtin.set_fact:
    nd_restore_steps: []
    nd_restore_operations:
      - remove-target-created
      - restore-fabric-for-membership
      - restore-switch-membership-and-roles
      - restore-dependent-domains
      - restore-managed-domains
      - restore-vpc-pairs
      - restore-physical-interfaces
      - restore-virtual-interfaces
      - delete-disposable-fabrics
      - restore-system-modes

- name: Execute each restoration layer in dependency order
  ansible.builtin.include_tasks: nd_prerequisite_reconcile.yaml
  loop: "{{ nd_restore_operations }}"
  loop_control:
    loop_var: nd_reconcile_operation
  vars:
    nd_reconcile_direction: restore

- name: Append normalized comparison step after all layers succeed
  ansible.builtin.set_fact:
    nd_restore_steps: "{{ nd_restore_steps + ['compare-normalized'] }}"
```

Each reconcile operation appends its own name to `nd_restore_steps` only after its mutation and polling succeed. Each destructive removal must intersect its requested objects with `snapshot.created_by_prepare`; baseline vPC deletion additionally requires a dependency-free snapshot. Each disposable-fabric delete must first assert `fabric_name is match('^ANSIBLE_NIGHTLY_')` and `fabric_name not in lab.retained_fabric_names`.

- [ ] **Step 4: Add normalized comparison, quarantine, and snapshot-retention logic**

Run the restored verifier after every layer and once for all captured domains. On mismatch, write a redacted report and marker locally with mode `0600`, set a failed fact, and finish with an assertion failure:

```yaml
- name: Quarantine lab after restoration mismatch
  ansible.builtin.copy:
    dest: "{{ nd_prerequisite_state_dir }}/QUARANTINED"
    content: "run_id={{ nd_prerequisite_run_id }} profile={{ nd_prerequisite_profile }}\n"
    mode: '0600'
  delegate_to: localhost
  when: nd_restore_mismatches | length > 0

- name: Fail closed when normalized restoration did not match
  ansible.builtin.assert:
    that: nd_restore_mismatches | length == 0
    fail_msg: "Lab quarantined; recovery snapshot retained at {{ nd_prerequisite_state_dir }}"
```

The `restore` phase keeps the snapshot after its zero-mismatch result so the separate `verify-restored` phase can independently re-gather and compare. Only `verify-restored` deletes the snapshot after its own zero-mismatch result. Restore each captured `intendedSystemMode` value, including maintenance, rather than unconditionally selecting normal.

- [ ] **Step 5: Run success, target-failure, partial-prepare, maintenance, and mismatch fixtures**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k 'restore or quarantine or maintenance' -q`

Expected: successful restoration removes its snapshot; target and partial-prepare failures still restore; captured normal and maintenance modes both return correctly; mismatch retains snapshot and quarantines.

### Task 6: Make the Common Integration Runner Consume Prepared Runtime State

**Files:**

- Modify: `tests/run_integration_module.yaml`
- Modify: `tests/test_validate_nd_prerequisites.py`

**Interfaces:**

- Consumes: `test_module` and the `runtime-vars.yaml` values passed by Jenkins with `--extra-vars @FILE`.
- Produces: one full `testcase: "*"` role execution, optional target cleanup in `always`, and a failing recap when either the target or its cleanup fails.

- [ ] **Step 1: Write failing runner-safety tests**

```python
def test_runner_has_no_hardcoded_lab_identity_or_best_effort_preclean(runner_text):
    assert "99WMIU1JLQ3" not in runner_text
    assert "9484O9IOVJK" not in runner_text
    assert "pre-clean" not in runner_text.lower()
    assert "ignore_errors" not in runner_text


def test_runner_requires_fresh_prepared_marker(runner_yaml):
    rendered = json.dumps(runner_yaml)
    for token in ("nd_prerequisite_prepared", "nd_prerequisite_run_id", "nd_prerequisite_profile"):
        assert token in rendered
```

- [ ] **Step 2: Run runner tests and observe failures from hardcoded/ignored cleanup behavior**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k runner -q`

Expected: failures identify hardcoded serials, generic pre-clean, and `ignore_errors`.

- [ ] **Step 3: Replace hardcoded setup with fail-closed prepared-state assertions**

```yaml
---
- name: "cisco.nd - integration suite for {{ test_module }}"
  hosts: nd
  gather_facts: false
  vars:
    testcase: "*"
    switch_username: "{{ lookup('env', 'ANSIBLE_NXOS_SWITCH_USERNAME') }}"
    switch_password: "{{ lookup('env', 'ANSIBLE_NXOS_SWITCH_PASSWORD') }}"
  pre_tasks:
    - name: Require fresh target-specific prerequisite output
      ansible.builtin.assert:
        that:
          - nd_prerequisite_prepared | default(false) | bool
          - nd_prerequisite_run_id == nd_expected_run_id
          - nd_prerequisite_profile == ('integration.' ~ test_module)
        fail_msg: Runtime prerequisite variables are absent, stale, or for another target
    - name: Discover optional target cleanup
      ansible.builtin.stat:
        path: "{{ playbook_dir }}/tests/integration/targets/{{ test_module }}/tasks/cleanup.yaml"
      register: cleanup_file
      delegate_to: localhost
  tasks:
    - name: Run full target and expose cleanup failures
      block:
        - name: Include collection target with every testcase
          ansible.builtin.include_role:
            name: "{{ test_module }}"
          vars:
            testcase: "*"
      always:
        - name: Run target-provided cleanup when present
          ansible.builtin.include_role:
            name: "{{ test_module }}"
            tasks_from: cleanup.yaml
          when: cleanup_file.stat.exists
```

- [ ] **Step 4: Run runner tests and syntax-check the runner with fixture inventory**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k runner -q && ansible-playbook --syntax-check -i tests/fixtures/nd_prerequisite/inventory.yaml tests/run_integration_module.yaml -e test_module=nd_manage_acl -e nd_prerequisite_prepared=true -e nd_prerequisite_run_id=fixture -e nd_expected_run_id=fixture -e nd_prerequisite_profile=integration.nd_manage_acl`

Expected: tests pass and Ansible reports the runner playbook without syntax errors.

### Task 7: Add Metadata to All 19 Playbooks and Remove Retained-Fabric Hazards

**Files:**

- Modify: all 19 `playbooks/*.yaml` files listed in the spec
- Modify: `consul/reset_fabric.yaml`
- Modify: `tests/test_validate_nd_prerequisites.py`

**Interfaces:**

- Consumes: exact `smoke.*` profile summaries and restricted current-Consul before-images.
- Produces: self-documenting playbooks whose summary matches the registry, disposable-fabric deletes are guarded, retained external fabrics survive L3Out/external smoke tests, and emergency reset has a narrow namespace-only surface.

- [ ] **Step 1: Write failing exact-summary and delete-safety tests**

```python
PLAYBOOK_SUMMARIES = {
    "nd_manage_acl": (["vxlanIbgp"], 0, []),
    "nd_manage_prefix_list": (["vxlanIbgp"], 0, []),
    "nd_manage_route_map": (["vxlanIbgp"], 0, []),
    "nd_manage_vrfs": (["vxlanIbgp"], 0, []),
    "nd_manage_networks": (["vxlanIbgp"], 0, []),
    "nd_manage_policy": (["vxlanIbgp"], 1, ["leaf"]),
    "nd_manage_policy_group": (["vxlanIbgp"], 2, ["leaf", "leaf"]),
    "nd_manage_switches": (["vxlanIbgp"], 2, ["preserve", "preserve"]),
    "nd_manage_vpc_pair": (["vxlanIbgp"], 2, ["leaf", "leaf"]),
    "nd_interface_vpc_access": (["vxlanIbgp"], 2, ["leaf", "leaf"]),
    "nd_interface_vpc_trunk_host": (["vxlanIbgp"], 2, ["leaf", "leaf"]),
    "nd_manage_vrf_lite": (["vxlanIbgp"], 1, ["border"]),
    "nd_manage_l3out": (["vxlanIbgp", "externalConnectivity"], 2, ["border", "edge_router"]),
    "nd_manage_resource_manager": (["vxlanIbgp"], 0, []),
    "nd_manage_fabric_ibgp_vxlan": (["vxlanIbgp"], 0, []),
    "nd_manage_fabric_ebgp_vxlan": (["vxlanEbgp"], 0, []),
    "nd_manage_fabric_ai_ibgp_vxlan": (["aimlVxlanIbgp"], 0, []),
    "nd_manage_fabric_ai_ebgp_vxlan": (["aimlVxlanEbgp"], 0, []),
    "nd_manage_fabric_external": (["externalConnectivity"], 0, []),
}


def test_every_playbook_summary_is_exact(playbook_dir):
    for name, (fabric_types, count, roles) in PLAYBOOK_SUMMARIES.items():
        data = yaml.safe_load((playbook_dir / f"{name}.yaml").read_text())
        summary = data[0]["vars"]["nd_prerequisite"]
        assert summary == {
            "profile": f"smoke.{name}", "fabric_types": fabric_types,
            "switch_count": count, "switch_roles": roles,
        }


def test_retained_fabrics_never_appear_in_fabric_delete_configs(playbook_dir):
    paths = sorted(playbook_dir.glob("*.yaml")) + [ROOT / "consul/reset_fabric.yaml"]
    assert validate_fabric_delete_guards(paths) == []
```

- [ ] **Step 2: Run playbook tests and confirm metadata and retained-delete failures**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k 'playbook or retained_fabric' -q`

Expected: all 19 metadata checks fail initially; external and L3Out/reset deletion checks identify current unsafe tasks.

- [ ] **Step 3: Hydrate each dataless playbook from its verified Consul before-image and insert exact metadata**

For each playbook, verify the restricted before-image hash still equals a fresh read of its Consul key. Use `apply_patch` to materialize/update the canonical local file, preserving all unrelated current playbook content. Insert the exact summary from `PLAYBOOK_SUMMARIES` beneath the play's existing `vars:` key; create `vars:` immediately after `gather_facts` if absent. Do not add any dormant playbook to `PLAYBOOK_FILES`.

The resulting structure is exact:

```yaml
  vars:
    nd_prerequisite:
      profile: smoke.nd_manage_acl
      fabric_types: [vxlanIbgp]
      switch_count: 0
      switch_roles: []
```

- [ ] **Step 4: Correct external and L3Out smoke lifecycle behavior**

In `nd_manage_fabric_external.yaml`, set the test fabric to `ANSIBLE_NIGHTLY_EXTERNAL`. In `nd_manage_l3out.yaml`, remove retained-external pre-delete/create/final-delete tasks and replace them with an exact read-only API check plus assertions:

```yaml
- name: Read retained external fabric
  cisco.nd.nd_rest:
    path: /api/v1/manage/fabrics/Siva_External_Fabric
    method: get
  register: retained_external

- name: Require retained external fabric with correct type
  ansible.builtin.assert:
    that:
      - retained_external.current is mapping
      - retained_external.current.management.type == 'externalConnectivity'
```

Every fabric deletion task must precede its module call with:

```yaml
- name: Validate disposable fabric deletion target
  ansible.builtin.assert:
    that:
      - fabric_name is match('^ANSIBLE_NIGHTLY_')
      - fabric_name not in ['Siva_Fabric_Adv', 'Siva_External_Fabric']
```

- [ ] **Step 5: Convert reset into a manual namespaced emergency cleanup**

Change the play name and comments to state that it is manual recovery only. Remove all delete-all VRF/network operations, all vPC-pair deletion on retained fabrics, all retained external-fabric deletion, all switch eviction, and all suppressed errors. Keep only documented named objects beginning `ANSIBLE_NIGHTLY_` and disposable fabrics whose names pass the two assertions above. Gather first and delete only exact matches; do not automatically invoke reset after a restore mismatch.

- [ ] **Step 6: Run metadata/delete-safety tests and syntax-check every playbook**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py -k 'playbook or retained_fabric or reset' -q && for file in playbooks/*.yaml consul/reset_fabric.yaml; do ansible-playbook --syntax-check -i tests/fixtures/nd_prerequisite/inventory.yaml "$file" || exit 1; done`

Expected: 19 exact summaries pass; no retained-fabric delete path exists; every disposable deletion has both guards; every YAML file passes syntax check.

### Task 8: Refactor Jenkins Around One Verified Target Lifecycle

**Files:**

- Modify: `Jenkinsfile_nd_jenkins_script`
- Create: `tests/test_jenkins_nd_prerequisites.py`

**Interfaces:**

- Consumes: release manifest, all release files, controller inventory, `ANSIBLE_NXOS_SWITCH_CREDENTIALS`, target lists, and wrapper stable CLI.
- Produces: `downloadVerifiedConsulRelease()`, `acquireNdLabLock()`, `refreshNdLabLock()`, `releaseNdLabLock()`, and `runPrerequisiteWrappedTarget(Map target)`; one output file and preserved status per target.

- [ ] **Step 1: Write failing Jenkins structural and extracted-shell tests**

```python
ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def jenkins_path():
    return ROOT / "Jenkinsfile_nd_jenkins_script"


@pytest.fixture
def jenkins_text(jenkins_path):
    return jenkins_path.read_text(encoding="utf-8")


def extract_method(text, name):
    start = text.index(f"def {name}(")
    opening = text.index("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError(f"unbalanced Groovy method: {name}")


def extract_shell_bodies(text):
    pattern = re.compile(r"\bsh\s*(?:\(\s*script\s*:\s*)?(?P<q>'''|\"\"\")(?P<body>.*?)(?P=q)", re.S)
    return [match.group("body") for match in pattern.finditer(text)]


def neutralize_groovy_interpolation(shell):
    return re.sub(r"\$\{(?=[^}]*[.() ])[^}]+\}", "GROOVY_VALUE", shell).replace("\\$", "$")


def test_common_lifecycle_has_try_finally_and_all_target_kinds(jenkins_text):
    body = extract_method(jenkins_text, "runPrerequisiteWrappedTarget")
    assert "try {" in body and "finally {" in body
    assert "nd_prerequisite_phase=preflight" in body
    assert "nd_prerequisite_phase=prepare" in body
    assert "nd_prerequisite_phase=restore" in body
    assert "nd_prerequisite_phase=verify-restored" in body
    assert all(kind in jenkins_text for kind in ("smoke", "role", "standalone"))


def test_release_is_hash_verified_and_manifest_is_first(jenkins_text):
    body = extract_method(jenkins_text, "downloadVerifiedConsulRelease")
    assert body.index("nd_prerequisite_release_manifest.json") < body.index("manifest.files.each")
    assert "SHA-256" in body or "SHA-256" in jenkins_text
    assert "isSymbolicLink" in body


def test_run_modes_are_explicit_and_default_to_full(jenkins_text):
    assert "ND_PREREQUISITE_RUN_MODE" in jenkins_text
    assert all(mode in jenkins_text for mode in (
        "full", "preflight-only", "canary-fabric", "canary-policy", "canary-vpc",
    ))


def test_repository_safety_patch_is_not_regressed(jenkins_text):
    assert "LOCAL_TREE" in jenkins_text and "REMOTE_TREE" in jenkins_text
    assert "git ls-remote" in jenkins_text
    assert "rm -rf nd" not in jenkins_text


def test_every_embedded_shell_body_parses(jenkins_path, tmp_path):
    for index, shell in enumerate(extract_shell_bodies(jenkins_path.read_text())):
        fixture = neutralize_groovy_interpolation(shell)
        path = tmp_path / f"shell-{index}.bash"
        path.write_text(fixture)
        subprocess.run(["bash", "-n", str(path)], check=True)
```

- [ ] **Step 2: Run Jenkins tests and confirm missing lifecycle/hash/lock failures**

Run: `python3 -m pytest tests/test_jenkins_nd_prerequisites.py -q`

Expected: failures name the missing verified downloader, common lifecycle, and lock methods; all pre-existing shell syntax results remain visible separately.

- [ ] **Step 3: Define the complete release file list and verify the manifest before installation**

Define `CONSUL_RELEASE_FILES` as the 19 playbooks plus `run_integration_module.yaml`, `reset_fabric.yaml`, `nd_prerequisite_profiles.yaml`, `nd_prerequisite_wrapper.yaml`, and the five task files. Download `nd_prerequisite_release_manifest.json` first, parse it, require `schema_version == 1`, require its key set to equal `CONSUL_RELEASE_FILES`, reject absolute/parent-traversal names and symlinks, then verify byte length and SHA-256 before atomically installing each file.

```groovy
def downloadVerifiedConsulRelease() {
    def manifestResponse = httpRequest(
        url: "${CONSUL_URL}/v1/kv/ansible-nd/nd_prerequisite_release_manifest.json?raw",
        validResponseCodes: '200')
    def manifest = new groovy.json.JsonSlurperClassic().parseText(manifestResponse.content)
    if (manifest.schema_version != 1) {
        error('Unsupported prerequisite release manifest schema')
    }
    if (!(manifest.release_id ==~ /^[A-Za-z0-9_.-]+$/)) {
        error('Unsafe prerequisite release ID')
    }
    def expected = CONSUL_RELEASE_FILES as Set
    def actual = manifest.files.collect { it.key.tokenize('/').last() } as Set
    if (actual != expected || manifest.files.size() != expected.size()) {
        error('Consul prerequisite release set does not match the Jenkins allowlist')
    }
    def staged = []
    manifest.files.each { entry ->
        def localName = entry.key.tokenize('/').last()
        if (!(localName ==~ /^[A-Za-z0-9_.-]+$/) || localName != entry.source.tokenize('/').last()) {
            error("Unsafe release entry: ${entry.key}")
        }
        def response = httpRequest(url: "${CONSUL_URL}/v1/kv/${entry.key}?raw", validResponseCodes: '200')
        byte[] content = response.content.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        verifyReleaseEntry(entry, content)
        def stagingName = ".nd-release-${manifest.release_id}-${localName}"
        if (isSymbolicLink(stagingName)) {
            error("Release staging path is a symlink: ${stagingName}")
        }
        writeFile(file: stagingName, text: response.content, encoding: 'UTF-8')
        def destination = "${COLLECTIONS_DIRECTORY}/${localName}"
        if (isSymbolicLink(stagingName) || isSymbolicLink(destination)) {
            error("Release source or destination is a symlink: ${localName}")
        }
        staged << [source: stagingName, destination: destination, entry: entry]
    }
    staged.each { item ->
        def newPath = item.destination + '.new'
        if (isSymbolicLink(newPath)) {
            error("Release temporary destination is a symlink: ${newPath}")
        }
        sh "install -m 0600 -- ${shellQuote(item.source)} ${shellQuote(newPath)}"
        sh "mv -f -- ${shellQuote(newPath)} ${shellQuote(item.destination)}"
        byte[] installed = readFile(file: item.destination, encoding: 'UTF-8')
            .getBytes(java.nio.charset.StandardCharsets.UTF_8)
        verifyReleaseEntry(item.entry, installed)
    }
    return manifest.release_id
}

def sha256Hex(byte[] bytes) {
    java.security.MessageDigest.getInstance('SHA-256')
        .digest(bytes).collect { String.format('%02x', it) }.join()
}

def verifyReleaseEntry(Map entry, byte[] content) {
    if (content.length != (entry.bytes as Integer)) {
        error("Consul release length mismatch for ${entry.key}")
    }
    if (sha256Hex(content) != entry.sha256) {
        error("Consul release SHA-256 mismatch for ${entry.key}")
    }
}

def isSymbolicLink(String path) {
    def leaf = path.tokenize('/').last()
    if (!(leaf ==~ /^[A-Za-z0-9_.-]+$/)) {
        error("Unsafe release filename: ${leaf}")
    }
    return sh(script: "test -L -- ${shellQuote(path)}", returnStatus: true) == 0
}
```

Keep `requirements.txt`, `requirements.yaml`, `inventory.yaml`, and `ansible.cfg` on their existing required-download path. Do not use the embedded runner fallback.

- [ ] **Step 4: Add cross-job Consul CAS lock functions**

Use key `ansible-nd/runtime/locks/nd42-siva-lab`. Acquisition PUTs a redacted JSON value with `?cas=0` and requires response `true`; refresh PUTs with the captured ModifyIndex; release DELETEs with that latest index. Set expiry later than the Jenkins ten-hour timeout, refresh between targets, and fail on any existing lock even if its value appears stale.

```groovy
def acquireNdLabLock(String buildIdentity) {
    def payload = groovy.json.JsonOutput.toJson([
        build: buildIdentity,
        job_url: env.BUILD_URL,
        acquired_at: new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX"),
        expires_at_epoch: (System.currentTimeMillis() / 1000L) + 39600L,
    ])
    def response = httpRequest(httpMode: 'PUT',
        url: "${CONSUL_URL}/v1/kv/ansible-nd/runtime/locks/nd42-siva-lab?cas=0",
        requestBody: payload, validResponseCodes: '200')
    if (response.content.trim() != 'true') {
        error('ND lab is locked; automatic stale-lock takeover is prohibited')
    }
    return readConsulModifyIndex('ansible-nd/runtime/locks/nd42-siva-lab')
}

def readConsulModifyIndex(String key) {
    def response = httpRequest(url: "${CONSUL_URL}/v1/kv/${key}", validResponseCodes: '200')
    def rows = new groovy.json.JsonSlurperClassic().parseText(response.content)
    if (!(rows instanceof List) || rows.size() != 1) {
        error("Unexpected Consul lock response for ${key}")
    }
    return rows[0].ModifyIndex as Long
}

def refreshNdLabLock(Long modifyIndex) {
    def payload = groovy.json.JsonOutput.toJson([
        build: env.BUILD_TAG, job_url: env.BUILD_URL,
        refreshed_at: new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX"),
        expires_at_epoch: (System.currentTimeMillis() / 1000L) + 39600L,
    ])
    def response = httpRequest(httpMode: 'PUT',
        url: "${CONSUL_URL}/v1/kv/ansible-nd/runtime/locks/nd42-siva-lab?cas=${modifyIndex}",
        requestBody: payload, validResponseCodes: '200')
    if (response.content.trim() != 'true') {
        error('ND lab lock refresh lost its CAS revision')
    }
    return readConsulModifyIndex('ansible-nd/runtime/locks/nd42-siva-lab')
}

def releaseNdLabLock(Long modifyIndex) {
    def response = httpRequest(httpMode: 'DELETE',
        url: "${CONSUL_URL}/v1/kv/ansible-nd/runtime/locks/nd42-siva-lab?cas=${modifyIndex}",
        validResponseCodes: '200')
    if (response.content.trim() != 'true') {
        error('ND lab lock release lost its CAS revision')
    }
}
```

- [ ] **Step 5: Implement the one-target `try/finally` lifecycle**

Validate `target.token` with `^[A-Za-z0-9_.-]+$`, derive `profile` as `smoke.<basename>` or `integration.<target>`, build a unique run ID from `BUILD_TAG`, ND version, target, and UTC timestamp, and place recovery state under `${BASE_DIRECTORY}/.nd-prerequisite-recovery/${runId}`.

Use one quoted wrapper command builder and parse the runtime marker as YAML rather than grepping it:

```groovy
def runWrapperStatus(String phase, String profile, String runId, String stateDir, String inventoryFile) {
    if (!(phase in ['preflight', 'prepare', 'restore', 'verify-restored'])) {
        error("Invalid prerequisite phase: ${phase}")
    }
    return sh(returnStatus: true, script: """#!/bin/bash
        set -euo pipefail
        ansible-playbook -i '${inventoryFile}' '${COLLECTIONS_DIRECTORY}/nd_prerequisite_wrapper.yaml' \\
          -e 'nd_prerequisite_phase=${phase}' \\
          -e 'nd_prerequisite_profile=${profile}' \\
          -e 'nd_prerequisite_run_id=${runId}' \\
          -e 'nd_prerequisite_state_dir=${stateDir}'
    """)
}

def runWrapper(String phase, String profile, String runId, String stateDir, String inventoryFile) {
    int status = runWrapperStatus(phase, profile, runId, stateDir, inventoryFile)
    if (status != 0) {
        error("Prerequisite ${phase} failed for ${profile}")
    }
}

def verifyRuntimeMarker(Map target) {
    def values = readYaml(file: "${target.stateDir}/runtime-vars.yaml")
    if (values.nd_prerequisite_prepared != true ||
        values.nd_prerequisite_run_id != target.runId ||
        values.nd_prerequisite_profile != target.profile) {
        error("Stale or mismatched runtime variables for ${target.token}")
    }
}

def shellQuote(String value) {
    return "'" + value.replace("'", "'\"'\"'") + "'"
}

def runTargetCommand(Map target, Map ndfcConfig, String inventoryFile) {
    String runtimeFile = "${target.stateDir}/runtime-vars.yaml"
    List<String> command = ['ansible-playbook', '-i', inventoryFile]
    if (target.kind == 'role') {
        command += ["${COLLECTIONS_DIRECTORY}/run_integration_module.yaml",
                    '-e', "test_module=${target.token}",
                    '-e', "nd_expected_run_id=${target.runId}"]
    } else if (target.kind == 'standalone') {
        command += ["${COLLECTIONS_DIRECTORY}/tests/integration/targets/${target.token}/tasks/main.yaml"]
    } else if (target.kind == 'smoke') {
        command += ["${COLLECTIONS_DIRECTORY}/${target.token}"]
    } else {
        error("Unsupported target kind: ${target.kind}")
    }
    command += ['--extra-vars', "@${runtimeFile}"]
    String outputFile = "${COLLECTIONS_DIRECTORY}/test_output_${ndfcConfig.fabric_name}_${ndfcConfig.versionId}_${target.token}.txt"
    withEnv(["ND_TARGET_COMMAND=${command.collect { shellQuote(it) }.join(' ')}",
             "ND_TARGET_OUTPUT=${outputFile}", "ND_TARGET_TOKEN=${target.token}",
             "ND_TARGET_RUN_ID=${target.runId}",
             "ND_TARGET_LABEL=${target.kind == 'smoke' ? 'PLAYBOOK' : 'MODULE'}"]) {
        return sh(returnStatus: true, script: '''#!/bin/bash
            set -uo pipefail
            start_time=$(date +%s)
            set +e
            bash -c "${ND_TARGET_COMMAND}" 2>&1 | tee -a "${ND_TARGET_OUTPUT}"
            target_status=${PIPESTATUS[0]}
            set -e
            end_time=$(date +%s)
            printf '[ANSIBLE_EXIT_STATUS: %s]\n' "${target_status}" | tee -a "${ND_TARGET_OUTPUT}"
            printf '[TIMESTAMP_END: %s]\n' "${end_time}" | tee -a "${ND_TARGET_OUTPUT}"
            printf '[DURATION_SECONDS: %s]\n' "$((end_time - start_time))" | tee -a "${ND_TARGET_OUTPUT}"
            printf '[%s: %s] Execution completed.\n' "${ND_TARGET_LABEL}" "${ND_TARGET_TOKEN}" | tee -a "${ND_TARGET_OUTPUT}"
            exit "${target_status}"
        ''')
    }
}

def targetOutputFile(Map target, Map ndfcConfig) {
    return "${COLLECTIONS_DIRECTORY}/test_output_${ndfcConfig.fabric_name}_${ndfcConfig.versionId}_${target.token}.txt"
}

def initializeTargetOutput(Map target, Map ndfcConfig) {
    String label = target.kind == 'smoke' ? 'PLAYBOOK' : 'MODULE'
    writeFile(file: targetOutputFile(target, ndfcConfig), text:
        "[${label}: ${target.token}] Starting execution...\n" +
        "[RUN_MARKER: ${target.runId}]\n" +
        "[TIMESTAMP_START: ${System.currentTimeMillis().intdiv(1000)}]\n")
}

def appendPrerequisiteFailure(Map target, Map ndfcConfig, Throwable failure) {
    String path = targetOutputFile(target, ndfcConfig)
    String current = readFile(path)
    writeFile(file: path, text: current +
        "[PREREQUISITE_STATUS: FAILED]\n" +
        "[PREREQUISITE_FAILURE_CLASS: ${failure.getClass().getSimpleName()}]\n")
}
```

```groovy
def runPrerequisiteWrappedTarget(Map target, Map ndfcConfig, String inventoryFile) {
    int targetStatus = 1
    int restoreStatus = 0
    boolean snapshotExists = false
    Throwable lifecycleFailure = null
    initializeTargetOutput(target, ndfcConfig)
    try {
        runWrapper('preflight', target.profile, target.runId, target.stateDir, inventoryFile)
        runWrapper('prepare', target.profile, target.runId, target.stateDir, inventoryFile)
        snapshotExists = fileExists("${target.stateDir}/snapshot.yaml")
        verifyRuntimeMarker(target)
        targetStatus = runTargetCommand(target, ndfcConfig, inventoryFile)
    } catch (Throwable failure) {
        lifecycleFailure = failure
        appendPrerequisiteFailure(target, ndfcConfig, failure)
    } finally {
        if (snapshotExists || fileExists("${target.stateDir}/snapshot.yaml")) {
            restoreStatus = runWrapperStatus('restore', target.profile, target.runId, target.stateDir, inventoryFile)
            if (restoreStatus == 0) {
                restoreStatus = runWrapperStatus('verify-restored', target.profile, target.runId, target.stateDir, inventoryFile)
            }
        }
    }
    if (restoreStatus != 0) {
        env.ND_LAB_QUARANTINED = 'true'
        error("Restoration failed for ${target.token}; later targets are prohibited")
    }
    return [
        token: target.token,
        target_status: targetStatus,
        lifecycle_failure_class: lifecycleFailure?.getClass()?.getSimpleName(),
        failed: lifecycleFailure != null || targetStatus != 0,
    ]
}
```

Initialize the exact output file with a fresh run marker before preflight. If preflight or prepare fails, append `[PREREQUISITE_STATUS: FAILED]` plus a redacted message so result parsing never falls back to an old or missing file. `runTargetCommand` appends timestamp, `ANSIBLE_EXIT_STATUS`, duration, and recap. Role targets call the common runner with `-e test_module=<name> -e nd_expected_run_id=<id> --extra-vars @runtime-vars.yaml`; standalone `nd_vpc_pair` and smoke playbooks also receive that runtime file.

- [ ] **Step 6: Add safe validation modes, move all three target loops into Groovy, and bind switch credentials only around lifecycle calls**

Add a declarative choice parameter whose first/default value is `full` and whose remaining values are `preflight-only`, `canary-fabric`, `canary-policy`, and `canary-vpc`. Map canaries exactly to `nd_manage_prefix_list.yaml`, `nd_manage_policy`, and `nd_interface_vpc_access`. `preflight-only` calls only the wrapper's read-only preflight for every active profile and never calls prepare, target, restore, or reset.

Create ordered target maps for standalone first, role targets second, and smoke playbooks third. For each selected map, refresh the Consul lock, check `ND_LAB_QUARANTINED != 'true'`, and call the same helper inside:

```groovy
withCredentials([usernamePassword(
    credentialsId: 'ANSIBLE_NXOS_SWITCH_CREDENTIALS',
    usernameVariable: 'ANSIBLE_NXOS_SWITCH_USERNAME',
    passwordVariable: 'ANSIBLE_NXOS_SWITCH_PASSWORD'
)]) {
    boolean anyTargetFailed = false
    orderedTargets.each { target ->
        lockIndex = refreshNdLabLock(lockIndex)
        def outcome = runPrerequisiteWrappedTarget(target, ndfcConfig, inventory_file)
        anyTargetFailed = anyTargetFailed || outcome.failed
    }
    if (anyTargetFailed) {
        error('One or more targets failed after all restoration-safe targets were attempted')
    }
}
```

Acquire the lock before the first target and release it in the outermost `finally`. Remove the monolithic shell loops and the duplicate third-serial fallback. Keep independent result parsing, but missing/mismatched fresh output remains fatal. A target/preflight failure continues to the next target only after restoration verifies; a restore failure throws immediately and quarantines the lab.

- [ ] **Step 7: Run Python/Bash/Groovy syntax gates**

Run: `python3 -m pytest tests/test_jenkins_nd_prerequisites.py -q && groovy -e 'new GroovyShell().parse(new File(args[0]))' Jenkinsfile_nd_jenkins_script`

Expected: all structural and extracted Bash tests pass and Groovy parses the Jenkinsfile without executing it. If the `groovy` executable is unavailable, record that gate as unavailable and use the authenticated Jenkins Pipeline Linter in Task 11; do not describe structural tests as Groovy compilation.

### Task 9: Build the Complete Release Manifest and Transactional CAS Publisher

**Files:**

- Modify: `tests/validate_nd_prerequisites.py`
- Modify: `tests/publish_nd_prerequisites.py`
- Modify: `tests/test_publish_nd_prerequisites.py`
- Create: `tests/nd_prerequisite_release_manifest.json`

**Interfaces:**

- Consumes: locally validated release sources and live pre-write Consul revisions.
- Produces: deterministic release manifest plus `publish_release(client, manifest, root, backup_dir) -> PublishReport` with manifest-last ordering and guarded rollback.

- [ ] **Step 1: Write failing manifest, CAS-conflict, rollback, and hash-mismatch tests**

```python
@pytest.fixture
def tmp_release(tmp_path):
    root = pathlib.Path(__file__).resolve().parents[1]
    manifest = build_manifest(root, release_id="fixture-release")
    before_manifest = b'{"schema_version":1,"release_id":"before","prefix":"ansible-nd","files":[]}'
    before = {
        entry["key"]: f"before:{entry['key']}\n".encode()
        for entry in manifest["files"]
    }
    before["ansible-nd/nd_prerequisite_release_manifest.json"] = before_manifest
    return types.SimpleNamespace(
        root=root, manifest=manifest, before=before,
        before_manifest=before_manifest, backup=tmp_path / "backup",
    )


def test_manifest_lists_every_content_key_once(tmp_release):
    manifest = build_manifest(tmp_release.root, release_id="fixture-release")
    keys = [entry["key"] for entry in manifest["files"]]
    assert len(keys) == len(set(keys)) == 28
    assert "ansible-nd/nd_prerequisite_release_manifest.json" not in keys
    assert all(len(entry["sha256"]) == 64 and entry["bytes"] > 0 for entry in manifest["files"])


def test_publish_writes_manifest_last_and_verifies_each_value(tmp_release):
    client = FakeConsul.from_release(tmp_release.before)
    report = publish_release(client, tmp_release.manifest, tmp_release.root, tmp_release.backup)
    assert report.ok
    assert client.put_order[-1] == "ansible-nd/nd_prerequisite_release_manifest.json"
    assert client.read_count >= len(tmp_release.manifest["files"]) * 2


def test_partial_publish_conflict_rolls_back_only_our_values(tmp_release):
    client = FakeConsul.from_release(tmp_release.before, fail_put_number=4)
    with pytest.raises(ReleaseError, match="rolled back"):
        publish_release(client, tmp_release.manifest, tmp_release.root, tmp_release.backup)
    assert client.values == tmp_release.before


def test_rollback_refuses_to_overwrite_concurrent_post_write_change(tmp_release):
    client = FakeConsul.from_release(tmp_release.before, mutate_after_put_number=2, fail_put_number=3)
    with pytest.raises(ReleaseError, match="manual recovery"):
        publish_release(client, tmp_release.manifest, tmp_release.root, tmp_release.backup)
    assert client.concurrent_value_was_preserved


def test_failed_release_leaves_new_key_unreferenced_instead_of_deleting(tmp_release):
    new_key = tmp_release.manifest["files"][0]["key"]
    client = FakeConsul.from_release(tmp_release.before, absent_keys={new_key}, fail_put_number=3)
    with pytest.raises(ReleaseError, match="unreferenced new keys"):
        publish_release(client, tmp_release.manifest, tmp_release.root, tmp_release.backup)
    assert new_key in client.values
    assert client.delete_order == []
    assert client.values.get("ansible-nd/nd_prerequisite_release_manifest.json") == tmp_release.before_manifest
```

Extend the Task 1 fake with revision-aware writes and deterministic failure injection:

```python
def __init__(self, records, fail_put_number=None, mutate_after_put_number=None):
    self.records = {
        key: KVRecord(key, value, revision, True)
        for key, (revision, value) in records.items()
    }
    self.values = {key: record.value for key, record in self.records.items()}
    self.put_order = []
    self.delete_order = []
    self.fail_put_number = fail_put_number
    self.mutate_after_put_number = mutate_after_put_number
    self.concurrent_value_was_preserved = False
    self.next_index = max([record.modify_index for record in self.records.values()] + [0])


@classmethod
def from_release(cls, before, absent_keys=frozenset(), **kwargs):
    records = {
        key: (index + 1, value)
        for index, (key, value) in enumerate(sorted(before.items()))
        if key not in absent_keys
    }
    return cls(records, **kwargs)


def cas_put(self, key, value, modify_index):
    self.put_order.append(key)
    if self.fail_put_number and len(self.put_order) == self.fail_put_number:
        return False
    current = self.records.get(key)
    current_index = current.modify_index if current else 0
    if current_index != modify_index:
        return False
    self.next_index += 1
    self.records[key] = KVRecord(key, bytes(value), self.next_index, True)
    self.values[key] = bytes(value)
    if self.mutate_after_put_number == len(self.put_order):
        self.next_index += 1
        self.records[key] = KVRecord(key, b"concurrent", self.next_index, True)
        self.values[key] = b"concurrent"
        self.concurrent_value_was_preserved = True
    return True
```

- [ ] **Step 2: Run publication tests and confirm manifest/publish functions are absent**

Run: `python3 -m pytest tests/test_publish_nd_prerequisites.py -q`

Expected: failures identify `build_manifest`, `publish_release`, and missing manifest.

- [ ] **Step 3: Implement deterministic source-to-key manifest generation**

Use this exact mapping rule: `playbooks/<name>` maps to `ansible-nd/<name>`; `consul/reset_fabric.yaml` maps to `ansible-nd/reset_fabric.yaml`; each listed `tests/nd_prerequisite_*.yaml`, runner, and task file maps to `ansible-nd/<basename>`. Sort entries by key and calculate entries directly from bytes:

```python
PLAYBOOK_NAMES = [
    "nd_interface_vpc_access.yaml", "nd_interface_vpc_trunk_host.yaml",
    "nd_manage_acl.yaml", "nd_manage_fabric_ai_ebgp_vxlan.yaml",
    "nd_manage_fabric_ai_ibgp_vxlan.yaml", "nd_manage_fabric_ebgp_vxlan.yaml",
    "nd_manage_fabric_external.yaml", "nd_manage_fabric_ibgp_vxlan.yaml",
    "nd_manage_l3out.yaml", "nd_manage_networks.yaml", "nd_manage_policy.yaml",
    "nd_manage_policy_group.yaml", "nd_manage_prefix_list.yaml",
    "nd_manage_resource_manager.yaml", "nd_manage_route_map.yaml",
    "nd_manage_switches.yaml", "nd_manage_vpc_pair.yaml",
    "nd_manage_vrf_lite.yaml", "nd_manage_vrfs.yaml",
]
SUPPORT_SOURCES = [
    "tests/run_integration_module.yaml", "consul/reset_fabric.yaml",
    "tests/nd_prerequisite_profiles.yaml", "tests/nd_prerequisite_wrapper.yaml",
    "tests/nd_prerequisite_capture.yaml", "tests/nd_prerequisite_reconcile.yaml",
    "tests/nd_prerequisite_wait.yaml", "tests/nd_prerequisite_verify.yaml",
    "tests/nd_prerequisite_restore.yaml",
]
RELEASE_SOURCES = [f"playbooks/{name}" for name in PLAYBOOK_NAMES] + SUPPORT_SOURCES


def build_manifest(root, release_id):
    root = pathlib.Path(root).resolve()
    entries = []
    for source in RELEASE_SOURCES:
        source_path = root / source
        if not source_path.is_file() or source_path.is_symlink():
            raise ValidationError(f"unsafe or missing release source: {source}")
        data = source_path.read_bytes()
        if not data:
            raise ValidationError(f"empty release source: {source}")
        entries.append({
            "key": f"ansible-nd/{source_path.name}",
            "source": source,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return {
        "schema_version": 1,
        "release_id": release_id,
        "prefix": "ansible-nd",
        "files": sorted(entries, key=lambda item: item["key"]),
    }


def manifest_bytes(manifest):
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
```

Reject empty files and non-lowercase 64-character hashes. Do not include volatile timestamps, filesystem paths outside `nd/`, credentials, or the manifest's own hash.

- [ ] **Step 4: Implement Consul CAS PUT, read-back verification, and guarded rollback**

```python
def cas_put(self, key: str, value: bytes, modify_index: int) -> bool:
    quoted = urllib.parse.quote(key, safe="/")
    request = urllib.request.Request(
        f"{self.address}/v1/kv/{quoted}?cas={modify_index}",
        data=value,
        method="PUT",
        headers={"Content-Type": "application/octet-stream"},
    )
    with urllib.request.urlopen(request, timeout=self.timeout) as response:
        return response.read().strip() == b"true"


def verify_record(client, key, wanted):
    current = client.read(key)
    if hashlib.sha256(current.value).hexdigest() != wanted["sha256"]:
        raise ReleaseError(f"post-write SHA-256 mismatch: {key}")
    if len(current.value) != wanted["bytes"]:
        raise ReleaseError(f"post-write length mismatch: {key}")
    return current


def verify_release(client, local_manifest_bytes):
    remote_manifest = client.read("ansible-nd/nd_prerequisite_release_manifest.json")
    if remote_manifest.value != local_manifest_bytes:
        raise ReleaseError("remote manifest bytes differ from local candidate")
    manifest = json.loads(local_manifest_bytes)
    for entry in manifest["files"]:
        verify_record(client, entry["key"], entry)
    return True


@dataclasses.dataclass
class PublishReport:
    ok: bool
    written: list[str]
    rolled_back: list[str]
    unreferenced_new_keys: list[str]


def publish_release(client, manifest, root, backup_dir):
    root = pathlib.Path(root)
    entries = list(manifest["files"])
    manifest_key = "ansible-nd/nd_prerequisite_release_manifest.json"
    before = snapshot_keys(
        client, [entry["key"] for entry in entries] + [manifest_key],
        pathlib.Path(backup_dir) / "publication-before", allow_absent=True,
    )
    journal = []
    rolled_back = []
    unreferenced = []
    try:
        candidates = [(entry, (root / entry["source"]).read_bytes()) for entry in entries]
        candidates.append(({
            "key": manifest_key,
            "bytes": len(manifest_bytes(manifest)),
            "sha256": hashlib.sha256(manifest_bytes(manifest)).hexdigest(),
        }, manifest_bytes(manifest)))
        for entry, candidate in candidates:
            record = before[entry["key"]]
            if not client.cas_put(entry["key"], candidate, record.modify_index):
                raise ReleaseError(f"Consul CAS conflict: {entry['key']}")
            current = verify_record(client, entry["key"], entry)
            journal.append((entry["key"], candidate, record, current.modify_index))
        return PublishReport(True, [item[0] for item in journal], [], [])
    except Exception as publish_error:
        manual = []
        for key, candidate, old, _written_index in reversed(journal):
            current = client.read(key)
            if current.value != candidate:
                manual.append(key)
                continue
            if not old.exists:
                unreferenced.append(key)
                continue
            if not client.cas_put(key, old.value, current.modify_index):
                manual.append(key)
                continue
            restored = client.read(key)
            if restored.value != old.value:
                manual.append(key)
                continue
            rolled_back.append(key)
        if manual:
            raise ReleaseError(
                f"publication failed; manual recovery required for {sorted(manual)}; "
                f"unreferenced new keys {sorted(unreferenced)}"
            ) from publish_error
        suffix = f"; unreferenced new keys {sorted(unreferenced)}" if unreferenced else ""
        raise ReleaseError(f"publication failed and existing keys were rolled back{suffix}") from publish_error
```

Before the first write, snapshot every content key and the current manifest key with modes `0700/0600`. Record an absent key as `exists=false, ModifyIndex=0`, then create it only with `cas=0`. CAS each content key against its freshly captured ModifyIndex, read it back, and append its verified revision to the rollback journal. Publish serialized manifest bytes last. On failure, traverse the journal in reverse and restore an existing key's before-image only when the current value still hashes to this publisher's candidate; use the current revision for rollback CAS. If another writer changed the value, preserve it, retain all before-images, and report manual recovery. If this release created a previously absent key, leave it unreferenced and report it rather than deleting it; the unchanged manifest prevents Jenkins from consuming it.

- [ ] **Step 5: Generate the real manifest and run the complete publisher unit suite**

Run: `python3 tests/validate_nd_prerequisites.py manifest --root . --output tests/nd_prerequisite_release_manifest.json --release-id nd-prereq-20260826 && python3 -m pytest tests/test_publish_nd_prerequisites.py -q`

Expected: manifest contains 28 unique nonempty content keys with correct hashes; success, conflict, partial rollback, concurrent-change, and read-back mismatch tests all pass.

### Task 10: Run the Complete Local Release Gate and Record SHA-256 Checkpoints

**Files:**

- Create: `tests/fixtures/nd_prerequisite/inventory.yaml`
- Modify: `tests/test_validate_nd_prerequisites.py`
- Modify: `tests/nd_prerequisite_release_manifest.json`

**Interfaces:**

- Consumes: every implementation artifact from Tasks 1-9.
- Produces: a locally validated candidate release, a redacted validation report, and exact SHA-256 values ready for CAS publication.

- [ ] **Step 1: Add a non-secret syntax-only inventory fixture and high-risk profile tests**

```yaml
---
all:
  children:
    nd:
      hosts:
        fixture-nd:
          ansible_host: 127.0.0.1
          ansible_connection: local
```

```python
def test_switch_target_captures_both_fabrics_and_all_four_switches(registry):
    profile = registry["profiles"]["integration.nd_manage_switches"]
    assert {f["name"] for f in profile["fabrics"]} == {"Siva_Fabric_Adv", "Siva_External_Fabric"}
    assert set(profile["snapshot_switch_refs"]) == {"adv_1", "adv_2", "ext_1", "ext_2"}


def test_resource_manager_uses_existing_virtual_pair_without_physical_create(run_wrapper):
    result = run_wrapper("prepare", "integration.nd_resource_manager", "transitions.yaml", case="existing_virtual_pair")
    assert result.returncode == 0
    report = json.loads(result.state_dir.joinpath("prepare-report.json").read_text())
    assert report["vpc_pair_action"] == "existing-pair-no-create"
    assert report["physical_peer_link_interfaces"] == []
    gathered = [{"switchId": "99WMIU1JLQ3", "peerSwitchId": "9484O9IOVJK", "useVirtualPeerLink": True}]
    pair_exists = any(
        item.get("switchId") in {"99WMIU1JLQ3", "9484O9IOVJK"}
        and item.get("peerSwitchId") in {"99WMIU1JLQ3", "9484O9IOVJK"}
        for item in gathered
    )
    assert ("merged" if not pair_exists else "gathered") == "gathered"
    target = pathlib.Path(
        "/Users/sivakasi/ansible/collections/ansible_collections/cisco/nd/"
        "tests/integration/targets/nd_resource_manager/tasks/vpc_pair_once.yaml"
    ).read_text()
    assert "state: \"{{ 'merged' if rm_vpc_pair_needs_create else 'gathered' }}\"" in target
```

- [ ] **Step 2: Run Python unit and fixture suites from a clean process**

Run: `python3 -m pytest tests/test_validate_nd_prerequisites.py tests/test_publish_nd_prerequisites.py tests/test_jenkins_nd_prerequisites.py -q`

Expected: all tests pass with no skips for required behavior; any environment-only Groovy linter limitation remains separately reported.

- [ ] **Step 3: Parse all YAML/JSON and run the authoritative validator**

Run: `python3 -c 'import json,pathlib,yaml; [yaml.safe_load(p.read_text()) for p in pathlib.Path(".").glob("playbooks/*.yaml")]; [yaml.safe_load(pathlib.Path("tests", n).read_text()) for n in ["run_integration_module.yaml","nd_prerequisite_profiles.yaml","nd_prerequisite_wrapper.yaml","nd_prerequisite_capture.yaml","nd_prerequisite_reconcile.yaml","nd_prerequisite_wait.yaml","nd_prerequisite_verify.yaml","nd_prerequisite_restore.yaml"]]; json.loads(pathlib.Path("tests/nd_prerequisite_release_manifest.json").read_text())' && python3 tests/validate_nd_prerequisites.py validate --root . --jenkinsfile Jenkinsfile_nd_jenkins_script`

Expected: parse succeeds and validator reports zero errors across target coverage, summaries, schema, safety guards, runtime mappings, release contents, and hashes.

- [ ] **Step 4: Syntax-check all Ansible entry points**

Run: `for file in tests/nd_prerequisite_wrapper.yaml tests/run_integration_module.yaml consul/reset_fabric.yaml playbooks/*.yaml; do ansible-playbook --syntax-check -i tests/fixtures/nd_prerequisite/inventory.yaml "$file" || exit 1; done`

Expected: every file produces a playbook syntax success and the loop exits 0.

- [ ] **Step 5: Run lint, shell extraction, Groovy compilation or Jenkins-linter fallback, and secret scan**

Run: `ansible-lint tests/nd_prerequisite_*.yaml tests/run_integration_module.yaml consul/reset_fabric.yaml playbooks/*.yaml && python3 -m pytest tests/test_jenkins_nd_prerequisites.py -q && python3 tests/validate_nd_prerequisites.py validate --root . --jenkinsfile Jenkinsfile_nd_jenkins_script --secret-scan`

Expected: lint and Jenkins tests pass; the credential scan returns no hardcoded secret match. Run Groovy compilation from Task 8 when available, otherwise use the authenticated Pipeline Linter in Task 11 and mark local Groovy compilation unavailable.

- [ ] **Step 6: Regenerate the manifest after final formatting and prove determinism**

Run twice with the same release ID, comparing bytes: `python3 tests/validate_nd_prerequisites.py manifest --root . --output tests/nd_prerequisite_release_manifest.json --release-id nd-prereq-20260826 && shasum -a 256 tests/nd_prerequisite_release_manifest.json && python3 tests/validate_nd_prerequisites.py validate --root . --jenkinsfile Jenkinsfile_nd_jenkins_script`

Expected: the second generation is byte-identical, all manifest hashes match current files, and validation remains clean.

- [ ] **Step 7: Record the canonical local change checkpoint without touching the dirty collection checkout**

Run: `find Jenkinsfile_nd_jenkins_script tests playbooks consul docs/superpowers -type f -print | LC_ALL=C sort | while IFS= read -r file; do shasum -a 256 "$file"; done`

Expected: a complete hash report is saved with the restricted pre-change snapshot outside ordinary Jenkins artifacts; `git -C /Users/sivakasi/ansible/collections/ansible_collections/cisco/nd status --short` is byte-for-byte unchanged from its pre-implementation record.

### Task 11: Publish to Consul and Gather Staged Live Evidence

**Files:**

- Read: `tests/nd_prerequisite_release_manifest.json`
- Read: restricted before-images under sibling directory `../.nd-consul-release-backups/`
- Modify externally: only the 28 manifest-listed Consul content keys plus `ansible-nd/nd_prerequisite_release_manifest.json`

**Interfaces:**

- Consumes: locally passing candidate, current Consul revisions, and—only for Jenkins live validation—existing Jenkins/controller/switch credentials.
- Produces: verified Consul release, then separately labeled Pipeline Linter, preflight, canary, restoration, and full-suite evidence when the corresponding live access exists.

- [ ] **Step 1: Re-snapshot every target Consul key immediately before publication**

Run: `umask 077 && python3 tests/publish_nd_prerequisites.py snapshot --allow-absent --address http://10.78.210.155:8500 --prefix ansible-nd --keys-file tests/nd_prerequisite_release_manifest.json --output ../.nd-consul-release-backups/prepublish-20260826`

Expected: every existing key has its current ModifyIndex/hash captured and every new key is recorded as absent with revision 0; the operation performs GETs only and does not include inventory, credentials, generated outputs, or test artifacts.

- [ ] **Step 2: Publish with CAS and automatic guarded rollback**

Run: `python3 tests/publish_nd_prerequisites.py publish --address http://10.78.210.155:8500 --prefix ansible-nd --manifest tests/nd_prerequisite_release_manifest.json --backup-dir ../.nd-consul-release-backups/prepublish-20260826`

Expected: each content key CAS succeeds and verifies; manifest is written last; final report lists old/new revisions and hashes but no content. A conflict stops immediately and either restores this publisher's writes or preserves a concurrent value and reports manual recovery.

- [ ] **Step 3: Re-read the Consul release as a set**

Run: `python3 tests/publish_nd_prerequisites.py verify --address http://10.78.210.155:8500 --prefix ansible-nd --manifest tests/nd_prerequisite_release_manifest.json`

Expected: manifest bytes are current and every referenced key has the exact recorded nonzero length and SHA-256; no key was deleted.

- [ ] **Step 4: Validate the Jenkinsfile with the authenticated Pipeline Linter when access is available**

Submit the exact canonical `Jenkinsfile_nd_jenkins_script` bytes to the configured Jenkins `/pipeline-model-converter/validate` endpoint using existing masked Jenkins credentials. Expected: HTTP success and a validation result containing no Groovy or declarative-pipeline error. If the endpoint or credential is unavailable, report this evidence level as not run; do not substitute local structural tests for the live linter.

- [ ] **Step 5: Run the three ordered Jenkins canaries through the same production lifecycle**

Use the Jenkins run-mode parameter implemented in Task 8 in this order: `canary-fabric` runs `nd_manage_prefix_list.yaml`; `canary-policy` runs `nd_manage_policy`; `canary-vpc` runs `nd_interface_vpc_access`. Each build must acquire the Consul lab lock, prepare, run, restore, verify restored state, and release the lock. After each canary, compare both retained fabrics and all four switch records with the captured normalized snapshot.

Expected: no topology prerequisite failure, target command executes, restoration matches, retained fabrics remain present with correct types, and no quarantine marker exists. If Jenkins triggering authority is absent, stop at verified Consul publication and report all three canaries as not run.

- [ ] **Step 6: Run the full configured suite only after all canaries pass**

Trigger the existing Jenkins job with run mode `full`. Expected: all 13 integration profiles and active smoke profile run under the wrapper; no target reports missing topology/switch/role/link, no stale marker is parsed, and final normalized comparison shows both retained fabrics and four baseline switches restored.

- [ ] **Step 7: Produce the evidence-separated completion report**

Report five independent rows: local syntax/fixtures, Consul CAS/hash verification, live Jenkins Pipeline Linter, three canaries plus post-canary restoration, and full Jenkins suite plus final topology comparison. Mark each `passed`, `failed`, or `not run`; never infer a higher evidence level from a lower one.
