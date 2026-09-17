# ND Integration Prerequisite Orchestration Design

Date: 2026-08-26  
Status: Approved for implementation  
Canonical target workspace: `/Users/sivakasi/Library/CloudStorage/OneDrive-Cisco/2/Ansible work/NX_ansible/jenkins/jenkins_nd/nd`  
User-facing symlink: `/Users/sivakasi/OneDrive - Cisco/2/Ansible work/NX_ansible/jenkins/jenkins_nd/nd`

## Objective

Make every Jenkins-configured cisco.nd test target reach its module logic without failing because a required fabric, switch, role, vPC pair, or link on a virtual lab switch is missing. Before every target, a common Ansible wrapper captures the affected lab state, reconciles and verifies the target's declared prerequisites, and produces the target-specific variables. After the target finishes, whether it passes or fails, the wrapper removes test-created objects, attempts a normalized restoration of every successfully captured domain, and verifies the result. Any domain that cannot be captured or restored fails closed and quarantines the lab; the design does not claim that non-transactional controller operations are always recoverable.

The persistent lab fabrics are retained:

- `Siva_Fabric_Adv`, type `vxlanIbgp`
- `Siva_External_Fabric`, type `externalConnectivity`

They are never deleted as part of prerequisite preparation or cleanup. Fabric-module tests use uniquely named disposable fabrics.

## Success Criteria

1. Every target in `PLAYBOOK_FILES`, `INTEGRATION_MODULES`, and `STANDALONE_INTEGRATION_MODULES` has a valid prerequisite profile.
2. Every one of the 19 Consul playbooks contains structured prerequisite information naming its profile, fabric type or types, switch count, and switch roles.
3. Missing or invalid topology stops the selected target before its test logic starts; it cannot be reported as a module failure.
4. The wrapper may administratively enable only explicitly allowlisted Ethernet interfaces on the virtual lab switches. It never attempts cabling or changes an undeclared interface.
5. Reconciliation uses save/deploy actions and bounded polling. No fixed multi-minute sleep is used as proof of convergence.
6. Every attempted mutation has a successfully validated before-image and a defined normalized restore procedure. If either is unavailable, mutation is prohibited.
7. A target failure still runs cleanup and restoration. A restoration failure stops all later targets and marks the lab quarantined.
8. Consul publication is revision-aware, backed up, and verified byte-for-byte after each write.
9. No controller, switch, or Consul credential is stored in a playbook, profile, snapshot, manifest, console log, or artifact.
10. The final report distinguishes local syntax/fixture evidence, Consul verification, live preflight, canary execution, and full live-suite execution.

"All tests" means all Jenkins-configured target profiles and every test-case file selected by those profiles. For `nd_manage_vrfs` and `nd_manage_networks`, this design selects the `standalone` topology on `Siva_Fabric_Adv`; optional MSD and MCFG topology suites are not silently treated as provisioned. Adding those suites later requires separate profiles for real MSD/MCFG parents and children.

## Non-Goals

- Creating physical links or changing virtual-machine wiring.
- Weakening module assertions, deleting failing test cases, or converting failures into skips.
- Enabling dormant smoke playbooks that duplicate active integration targets.
- Editing the collection's upstream integration test implementation.
- Storing secrets in Consul.
- Treating a successful syntax check as proof of a live deployment.

## Existing State and Problems

The active Jenkins configuration currently runs:

- smoke: `nd_manage_prefix_list.yaml`
- role targets: `nd_manage_policy`, `nd_manage_policy_group`, `nd_manage_vrfs`, `nd_manage_networks`, `nd_manage_route_map`, `nd_manage_acl`, `nd_manage_l3out`, `nd_interface_vpc_access`, `nd_interface_vpc_trunk_host`, `nd_manage_switches`, `nd_manage_fabric`, and `nd_resource_manager`
- standalone target: `nd_vpc_pair`

The current common runner supplies only `fabric_name`, `ansible_it_fabric`, and `switch_serial_1..3`; the third serial duplicates the second. Several targets instead require `ansible_switch1..3`, `ansible_sno_1..2`, topology-specific fabric variables, management IPs, or interfaces. This variable-contract mismatch is a direct source of topology failures.

The current external-fabric smoke playbook deletes `Siva_External_Fabric`. The current L3Out smoke playbook also pre-deletes, recreates, and finally deletes that retained fabric. Both behaviors violate the approved persistent-fabric policy and must be removed.

The concrete correction is mandatory: `nd_manage_fabric_external.yaml` changes its default test fabric to `ANSIBLE_NIGHTLY_EXTERNAL`; `nd_manage_l3out.yaml` removes the retained-external-fabric pre-delete, create, and final-delete tasks and replaces them with fail-closed existence/type assertions. Every fabric deletion path asserts that the name begins with `ANSIBLE_NIGHTLY_` and is not either retained fabric.

The existing generic cleanup is best-effort and suppresses errors. Some upstream target setup is intentionally destructive: the switch target removes devices from its selected fabric, the vPC targets delete/recreate a pair, and the VRF target can delete the selected topology's VRFs. Therefore target cleanup alone cannot guarantee restoration.

## Architectural Decisions

### Declarative profiles

`nd_prerequisite_profiles.yaml` is the authoritative topology registry. Profile IDs are namespaced by execution style:

- `smoke.<playbook-basename>`
- `integration.<target-name>`

Each Consul playbook includes a structured summary under its play variables:

```yaml
nd_prerequisite:
  profile: smoke.nd_manage_acl
  fabric_types:
    - vxlanIbgp
  switch_count: 0
  switch_roles: []
```

The summary makes the playbook self-documenting. The release validator compares it with the authoritative profile and rejects drift before publication.

`switch_count` always means distinct switch identities. `switch_roles` may use a concrete ND role or `preserve`; `preserve` means the wrapper must not change that switch's captured role. `operational_state: when_reported_up` means admin-up and discovery are mandatory, and any operational status returned by ND must be up; absence of the optional field is recorded explicitly rather than treated as up.

Each authoritative profile contains:

```yaml
schema_version: 1
profile_id: integration.nd_interface_vpc_access
fabrics:
  - ref: advanced
    name: Siva_Fabric_Adv
    type: vxlanIbgp
    lifecycle: retained
switches:
  required_count: 2
  members:
    - ref: adv_1
      fabric_ref: advanced
      desired_role: leaf
    - ref: adv_2
      fabric_ref: advanced
      desired_role: leaf
vpc_pairs:
  - peers: [adv_1, adv_2]
    use_virtual_peer_link: true
links:
  - switch_ref: adv_1
    interfaces: [Ethernet1/5, Ethernet1/6, Ethernet1/7]
    admin_state: true
    operational_state: when_reported_up
  - switch_ref: adv_2
    interfaces: [Ethernet1/5, Ethernet1/6, Ethernet1/7]
    admin_state: true
    operational_state: when_reported_up
managed_domains:
  - vpc_pairs
  - vpc_interfaces
restore: verified_normalized_snapshot
```

Profiles reference logical switch identities. Serial numbers and seed IPs live once in the lab registry, not in every profile.

### Declared lab registry

The current checked-in reset configuration declares four virtual switches. The wrapper treats these as expected identities and verifies them live before mutation:

| Switch ref | Baseline fabric | Serial | Seed/management IP |
|---|---|---|---|
| `adv_1` | `Siva_Fabric_Adv` | `99WMIU1JLQ3` | `10.122.84.203` |
| `adv_2` | `Siva_Fabric_Adv` | `9484O9IOVJK` | `10.122.84.204` |
| `ext_1` | `Siva_External_Fabric` | `94HIZLNUVCI` | `10.122.84.55` |
| `ext_2` | `Siva_External_Fabric` | `90SRMMW6APK` | `10.122.84.56` |

Current live membership and roles are never assumed from this table; they are discovered into the per-target snapshot. A profile may temporarily move `ext_1` into `Siva_Fabric_Adv` when three distinct switches are required, but restoration must return it to its captured fabric and role before the next target.

Switch onboarding credentials are supplied through a Jenkins username/password credential named `ANSIBLE_NXOS_SWITCH_CREDENTIALS`. Jenkins exposes it only as masked environment variables for the wrapper and switch integration target. If this credential is absent, any profile requiring switch movement fails before mutation. It is not replaced with the ND controller credential by assumption.

### Common lifecycle wrapper

`nd_prerequisite_wrapper.yaml` accepts `nd_prerequisite_phase`, `nd_prerequisite_profile`, `nd_prerequisite_run_id`, and `nd_prerequisite_state_dir`.

Supported phases are:

- `preflight`: read-only schema, credential, fabric, switch, vPC, interface, and resource checks
- `prepare`: capture, reconcile, deploy, verify, and write target runtime variables
- `restore`: remove target-created substrate, restore the snapshot, deploy, and verify
- `verify-restored`: read-only confirmation used after restoration and by recovery runs

Internally, the wrapper keeps focused task files for capture, reconciliation, convergence polling, verification, and restoration. These files are implementation details behind the stable phase interface.

Jenkins moves the three target loops out of one monolithic shell and invokes every smoke, role, and standalone target through one Groovy orchestration function. That function wraps the complete target command in `try/finally`: `preflight` and `prepare` run before the target, while `restore` and `verify-restored` run in `finally`. A test cannot execute unless `prepare` returned success and produced a freshly marked runtime-variable file.

The role runner is itself the wrapped target command. Its generic best-effort pre-clean is removed because prerequisite preparation owns stale-state cleanup. Its optional target cleanup remains inside the runner's `always` block but no longer suppresses failure; the outer wrapper then performs normalized restoration. The standalone vPC command and every smoke command use the same outer lifecycle.

The standalone `nd_vpc_pair` target remains a complete playbook and is still invoked directly. It is no longer lifecycle-standalone: the same prerequisite wrapper runs before and after it.

## Per-Profile Topology Contract

### Consul smoke playbooks

All 19 playbooks receive metadata. Dormant playbooks remain dormant unless separately enabled, preventing duplicate coverage.

| Profile | Fabric requirement | Switch requirement | vPC/link requirement |
|---|---|---|---|
| `smoke.nd_manage_acl` | retained advanced, `vxlanIbgp` | 0 | none |
| `smoke.nd_manage_prefix_list` | retained advanced, `vxlanIbgp` | 0 | none |
| `smoke.nd_manage_route_map` | retained advanced, `vxlanIbgp` | 0 | none |
| `smoke.nd_manage_vrfs` | retained advanced, `vxlanIbgp` | 0 | none |
| `smoke.nd_manage_networks` | retained advanced, `vxlanIbgp` | 0 | definition-only; no attachment link |
| `smoke.nd_manage_policy` | retained advanced, `vxlanIbgp` | 1 distinct leaf (`adv_1`) | none |
| `smoke.nd_manage_policy_group` | retained advanced, `vxlanIbgp` | 2 distinct leaves (`adv_1`, `adv_2`) | none |
| `smoke.nd_manage_switches` | retained advanced, `vxlanIbgp` | 2 discovered members; captured roles | gather-only playbook; no mutation prerequisite |
| `smoke.nd_manage_vpc_pair` | retained advanced, `vxlanIbgp` | 2 distinct leaves | virtual peer link; no physical peer-link ports |
| `smoke.nd_interface_vpc_access` | retained advanced, `vxlanIbgp` | 2 distinct leaves | virtual vPC; Ethernet1/5-7 on both peers, admin up and oper up when ND reports it |
| `smoke.nd_interface_vpc_trunk_host` | retained advanced, `vxlanIbgp` | 2 distinct leaves | virtual vPC; Ethernet1/8-10 on both peers, admin up and oper up when ND reports it |
| `smoke.nd_manage_vrf_lite` | retained advanced, `vxlanIbgp` | 1 border (`adv_1`) | Ethernet1/20 admin up and oper up when ND reports it |
| `smoke.nd_manage_l3out` | retained advanced plus retained external | `adv_1` border; `ext_1` edge router | Ethernet1/1 routed link on both endpoints, admin up and oper up when ND reports it |
| `smoke.nd_manage_resource_manager` | retained advanced, `vxlanIbgp` | 0 for fabric-scoped gather | validated `L3_VNI`/`ID` pool; no resource replacement |
| `smoke.nd_manage_fabric_ibgp_vxlan` | disposable `vxlanIbgp` | 0 | create/verify/delete disposable fabric |
| `smoke.nd_manage_fabric_ebgp_vxlan` | disposable `vxlanEbgp` | 0 | create/verify/delete disposable fabric |
| `smoke.nd_manage_fabric_ai_ibgp_vxlan` | disposable `aimlVxlanIbgp` | 0 | create/verify/delete disposable fabric |
| `smoke.nd_manage_fabric_ai_ebgp_vxlan` | disposable `aimlVxlanEbgp` | 0 | create/verify/delete disposable fabric |
| `smoke.nd_manage_fabric_external` | disposable `externalConnectivity` | 0 | use `ANSIBLE_NIGHTLY_EXTERNAL`; never use/delete retained external fabric |

### Active role and standalone integration targets

| Profile | Fabric requirement | Switch/role requirement | Other prerequisite and injected variables |
|---|---|---|---|
| `integration.nd_manage_policy` | retained advanced | 2 distinct leaves | `fabric_name`, `switch_serial_1..2` |
| `integration.nd_manage_policy_group` | retained advanced | 3 distinct identities; preserve captured roles for `adv_1`/`adv_2`, borrow `ext_1` as leaf | `switch_serial_1..3`; no role change beyond what temporary onboarding requires |
| `integration.nd_manage_vrfs` | retained advanced | 1 leaf | select `nd_vrf_test_topology=standalone`; inject `ansible_it_fabric`, `ansible_switch1` |
| `integration.nd_manage_networks` | retained advanced | 1 leaf | select `nd_network_test_topology=standalone`; inject `ansible_it_fabric`, `ansible_switch1`, `ansible_network_interface1=Ethernet1/20`; enable and verify admin state, plus oper state when reported |
| `integration.nd_manage_route_map` | retained advanced | 0 | inject `nd_test_fabric_name`; destructive overridden case remains controlled by the target's existing opt-in flag |
| `integration.nd_manage_acl` | retained advanced | 0 | inject `acl_test_fabric` |
| `integration.nd_manage_l3out` | retained advanced plus retained external | `adv_1` border; `ext_1` edge router | inject real fabric names, serials/IPs, Ethernet1/1 and Ethernet1/2 mappings; both link pairs admin up and oper up when reported |
| `integration.nd_interface_vpc_access` | retained advanced | 2 leaves | virtual vPC; Ethernet1/5-7 admin up and oper up when reported; inject peer IPs |
| `integration.nd_interface_vpc_trunk_host` | retained advanced | 2 leaves | virtual vPC; Ethernet1/8-10 admin up and oper up when reported; inject peer IPs |
| `integration.nd_manage_switches` | retained advanced | 3 seed IPs with desired leaf, spine, border roles; temporarily borrow `ext_1` | requires switch credential; target is destructive, so capture both fabrics and all four switches |
| `integration.nd_manage_fabric` | controller only | 0 | target-created disposable fabrics only |
| `integration.nd_resource_manager` | retained advanced | 2 leaves | pre-create/verify virtual vPC, inject matching `ansible_sno_1..2`, and fixture-verify the target's existing-pair detector takes its no-create path; physical fallback is prohibited |
| `integration.nd_vpc_pair` | retained advanced | 2 leaves | direct full playbook; inject fabric, peer serials, and `vxlanIbgp` type |

The managed-domain declaration follows the target's mutation surface. Single-domain targets capture their corresponding complete fabric-scoped domain. Composite targets capture all dependencies: L3Out captures L3Outs plus its prerequisite VRFs and touched interfaces; vPC-interface targets capture vPC pairs, vPC interfaces, and physical member-interface payloads; resource manager captures allocations plus vPC state; switch integration captures complete switch membership and roles for both retained fabrics; fabric integration captures the exact set of disposable fabric names. VRF and network integration capture their complete selected standalone domains because their setup or overridden-state cases can be broad.

## Reconciliation Sequence

For each target, Jenkins performs the following sequence under the shared lab lock:

1. Generate a unique run ID from the Jenkins build tag, ND version, target, and timestamp.
2. Call wrapper `preflight` without mutation.
3. Call wrapper `prepare`.
4. Execute the target with the generated runtime-variable file.
5. Record the target's Ansible exit code without suppressing it.
6. Call wrapper `restore` regardless of the target exit code.
7. Call wrapper `verify-restored`.
8. Preserve the target failure result after successful restoration, or quarantine the lab if restoration failed.

Preparation order is:

1. Validate profile schema and distinct switch identities.
2. Acquire and validate the retained fabrics.
3. Capture fabric configuration, switch membership and roles, vPC state, resource allocations, every profile-declared managed domain, and exact configurations of every touched interface.
4. Capture `additionalData.intendedSystemMode`, then enter maintenance mode only for switches undergoing membership or disruptive role changes.
5. Remove only dependency objects that block the declared transition.
6. Move/re-onboard a switch only when the profile requires membership not currently present.
7. Change roles. Prefer the ND `changeRoles` action for an existing member rather than `nd_manage_switches replaced`, because the latter deletes and rediscovers the device on role mismatch.
8. Create or reconcile the declared vPC pair.
9. Reconcile allowlisted interface policy, setting `adminState=true` only when required.
10. Save/recalculate, deploy, and poll.
11. Put switches in the profile's required test mode, normally `normal`, without discarding the captured intended mode.
12. Verify the complete declared topology and emit runtime variables.

For an interface whose typed module cannot safely preserve the existing physical-interface policy, the wrapper uses `nd_rest` GET/PUT on that exact interface. It does not echo the raw GET response back to ND. An API-write sanitizer retains only the writable interface schema, strips operational/read-only fields, resolves and injects the path-matching `switchId`, applies the declared `adminState` change, and validates the resulting payload before PUT. It then deploys only `{interfaceName, switchId}` pairs for the allowlisted interfaces. Physical Ethernet interfaces are never deleted; restoration is a sanitized PUT or typed normalization.

vPC deletion is conditional, never forced. Before unpairing, the wrapper queries vPC interfaces, network/VRF counts, overview, and consistency. It removes only dependencies created by the current prerequisite run. If a baseline pair has unexpected dependencies, the profile fails before mutation. For a baseline pair that is absent, the snapshot records absence; for a dependency-free baseline pair that exists, the complete writable pair configuration is captured for restoration.

## Convergence and Verification

Polling is the authoritative convergence proof. Existing upstream 30-second vPC stabilization delays may remain, but they cannot replace the checks below; the unused three-minute reset delay is removed:

- interval: 15 seconds
- normal timeout: 5 minutes
- vPC or switch membership/role timeout: 10 minutes
- maximum consecutive API errors: 3

Preparation succeeds only when all applicable assertions pass:

- fabric exists and its reported type matches the profile
- every switch identity is distinct and belongs to the expected fabric
- every desired role is reported by ND
- every affected switch reports `additionalData.configSyncStatus == inSync`
- every required interface reports admin up and remains discoverable
- every link whose ND endpoint exposes operational state reports up; a missing operational field is reported as unverified rather than invented
- every required vPC pair exists, its overview is synchronized, and its consistency endpoint reports no failure
- resource pools referenced by the profile exist

Verification uses explicit ND response paths and accepted values:

- fabric: `GET /api/v1/manage/fabrics/{fabric}`; `current.management.type` must equal the profile type
- switch: `GET /api/v1/manage/fabrics/{fabric}/switches`; match `current.switches[]` by `switchId` and verify `fabricManagementIp`, `role`/`switchRole`, `additionalData.configSyncStatus`, and `additionalData.intendedSystemMode`
- interface: `GET /api/v1/manage/fabrics/{fabric}/switches/{switchId}/interfaces/{encodedInterface}`; `current.configData.networkOS.policy.adminState` must be true; when present, `current.operData.operationalStatus` must normalize to `up`
- vPC: `GET .../vpcPairOverview?componentType=full`; `inventory.syncStatus` and overlay network/VRF counters must have zero `pending`, `outOfSync`, and `inProgress`; `GET .../vpcPairConsistency` must not return `type2Consistency: false`

Unknown or missing mandatory fields fail closed. The physical Ethernet endpoint does not consistently expose operational status, so admin-up, interface discovery, successful targeted deployment, and switch `inSync` are mandatory there; operational-up is asserted only when ND reports it. vPC overview operational counters are used when available.

If an interface is reported operationally down, the wrapper first checks its captured and current administrative state. It may enable and deploy the interface only when the profile explicitly allows it. If ND continues to report it down, the wrapper reports the fabric, serial, interface, admin state, operational state, and last deployment status, then fails before the module test. It performs no cabling or hypervisor action.

## Snapshot and Restoration

Snapshots are stored outside the collection checkout under a restricted directory such as `${BASE_DIRECTORY}/.nd-prerequisite-recovery/<run-id>`, with directory mode `0700` and file mode `0600`. They are never archived or uploaded to Consul. Snapshots contain no passwords or tokens.

Every profile declares its `managed_domains`. These are the configuration families that the target may create, replace, override, or delete, such as ACLs, route maps, prefix lists, policies, policy groups, VRFs, networks, L3Outs, vPC pairs, interfaces, resource allocations, switches, or fabrics. The wrapper gathers the complete affected domain before the target runs, using the typed module's gathered state when available and a read-only `nd_rest` endpoint otherwise. This prevents a target's broad deleted/overridden setup from erasing pre-existing lab objects without a before-image.

Restoration is dependency-aware and separates removal of target-created state from re-creation of baseline state:

1. Remove target-created vPC interfaces, vPC pairs, resource allocations, and managed-domain objects, but only after dependency checks pass.
2. Restore retained-fabric configuration required for membership operations.
3. Restore switch membership and roles using explicit identities, then save/deploy and poll to `inSync`.
4. Restore fabric-scoped and switch-scoped resources only after every referenced switch is again a member.
5. Restore other profile-declared managed domains from their captured normalized state.
6. Restore the captured baseline vPC pair only after its switches and prerequisite domains exist.
7. Restore touched physical-interface policy with sanitized PUTs or typed modules, then restore virtual/vPC interfaces.
8. Delete only disposable fabrics created for the target.
9. Restore each switch's captured `additionalData.intendedSystemMode`; do not unconditionally force `normal`.
10. Re-gather and compare every declared domain with the normalized snapshot.

Successful restoration means every declared, captured domain passed the normalized comparison; only then is the target snapshot deleted. Because switch onboarding, resource replacement, and vPC deletion are non-transactional controller operations, restoration is not promised when ND loses state or a re-add fails. Such a failure retains the snapshot, writes a redacted recovery report, sets `ND_LAB_QUARANTINED=true`, and stops subsequent targets.

`reset_fabric.yaml` becomes a manually invoked emergency namespaced cleanup, not the primary lifecycle mechanism and never an automatic fallback after a restore mismatch. It must not delete `Siva_Fabric_Adv`, `Siva_External_Fabric`, or evict their switches. It may remove only documented `ANSIBLE_NIGHTLY_*` objects and disposable fabrics after confirming their identities.

## Cross-Job Lab Lock

`disableConcurrentBuilds()` protects only this Jenkins job. A Consul CAS lock under `ansible-nd/runtime/locks/nd42-siva-lab` protects the two fabrics across Jenkins jobs.

The lock value contains only build identity, job URL, acquisition time, and an expiry later than the Jenkins ten-hour timeout. Acquisition uses `cas=0`; an existing unexpired lock fails closed. Jenkins refreshes the lock between targets and releases it with the captured ModifyIndex. A stale lock is reported and requires explicit recovery rather than automatic takeover during a build.

## Jenkins and Consul Files

Local Jenkins workspace changes:

- `Jenkinsfile_nd_jenkins_script`
- `tests/run_integration_module.yaml`
- `tests/nd_prerequisite_profiles.yaml`
- `tests/nd_prerequisite_wrapper.yaml`
- `tests/nd_prerequisite_capture.yaml`
- `tests/nd_prerequisite_reconcile.yaml`
- `tests/nd_prerequisite_wait.yaml`
- `tests/nd_prerequisite_verify.yaml`
- `tests/nd_prerequisite_restore.yaml`
- `tests/validate_nd_prerequisites.py`
- `tests/publish_nd_prerequisites.py`
- `tests/nd_prerequisite_release_manifest.json`
- all 19 files under `playbooks/`
- `consul/reset_fabric.yaml`

Consul keys added or updated:

- `ansible-nd/nd_prerequisite_profiles.yaml`
- `ansible-nd/nd_prerequisite_wrapper.yaml`
- `ansible-nd/nd_prerequisite_capture.yaml`
- `ansible-nd/nd_prerequisite_reconcile.yaml`
- `ansible-nd/nd_prerequisite_wait.yaml`
- `ansible-nd/nd_prerequisite_verify.yaml`
- `ansible-nd/nd_prerequisite_restore.yaml`
- `ansible-nd/run_integration_module.yaml`
- `ansible-nd/reset_fabric.yaml`
- all 19 existing playbook keys
- `ansible-nd/nd_prerequisite_release_manifest.json`

The Jenkinsfile's required-download list is explicit. It downloads the release manifest and every prerequisite file fail-closed, rejects empty/symlinked files, verifies SHA-256 values, and installs the runner/wrapper/task files at the collection root so their relative includes remain stable. Only then does preflight start. Existing dormant playbooks are synchronized and documented but are not automatically added to `PLAYBOOK_FILES`.

## Consul Publication and Rollback

Publication is a separate operator action, not a Jenkins runtime upload:

1. Re-read every target key's current `ModifyIndex` and content hash.
2. Save restricted before-images locally, excluding credential-bearing inventory and generated outputs from ordinary backups.
3. Validate the complete candidate release and calculate SHA-256 values.
4. Write each key with Consul CAS against the captured `ModifyIndex`; a key that is absent is recorded explicitly and created only with `cas=0`.
5. Re-read and hash each written value.
6. If any CAS or verification fails, stop and restore already-written existing keys using their captured before-images and new revision indexes. A newly created key has no before-image and is left unreferenced rather than deleted; because the manifest is still old, Jenkins cannot consume it. Report such an inert key for operator review.
7. Publish the manifest last so Jenkins never observes an incomplete release as current.
8. Re-read the manifest and every referenced key and verify the final release as a set.

No Consul key is deleted by this release.

## Error Handling

- Schema error, missing fabric, duplicate/missing switch, missing switch credential, unsupported role, absent required interface, or failed read-only query: fail preflight; perform no mutation.
- Partial prepare failure after snapshot creation: immediately run restoration from the snapshot.
- Test failure: preserve the test exit status, restore, and continue only if restoration verifies.
- Cleanup failure: attempt normalized snapshot restoration; the cleanup failure remains visible.
- Restore or restore-verification failure: quarantine and stop all later targets.
- Consul CAS mismatch: publish nothing further; do not overwrite a concurrent change.
- Deployment timeout or HTTP 207 partial failure: report per-object failures, restore, and stop the target.
- Missing fresh output marker: do not parse an older test result.

Preparation, restoration, and release verification do not use `ignore_errors`. Diagnostic gathers may record an error but cannot convert a failed prerequisite into success.

## Validation Strategy

### Local, non-mutating validation

1. Parse all YAML files and the JSON manifest.
2. Validate every profile against the schema and confirm every Jenkins target resolves to exactly one profile.
3. Compare each playbook's embedded summary with its authoritative profile.
4. Run `ansible-playbook --syntax-check` for the wrapper, runner, reset playbook, and all 19 playbooks with a non-secret fixture inventory.
5. Run `ansible-lint` on changed YAML.
6. Extract Jenkins shell bodies, run `bash -n`, and run the existing disposable Jenkins fixture suite.
7. Test normalized snapshot comparisons and runtime-variable mappings.

### Failure-injection fixtures

Fixtures cover:

- missing/incorrect fabric type
- duplicate switch identity
- missing third switch credential
- unexpected dependency on a baseline vPC pair
- resource-manager existing-pair detection must take the no-create path
- raw interface GET sanitization, read-only-field removal, and `switchId` injection
- captured maintenance mode restored to maintenance as well as normal
- link already up
- link admin down then converged up
- link still operationally down after deployment
- vPC convergence timeout
- HTTP 207 partial switch failure
- test command failure followed by successful restoration
- partial prepare failure followed by restoration
- restoration mismatch and quarantine
- stale or conflicting Consul lock
- Consul CAS conflict, partial publication rollback, and hash mismatch

### Live staged validation

1. Run wrapper `preflight` for every active profile with mutation disabled.
2. Publish the Consul release with CAS and verify all hashes.
3. Run the fabric-only `nd_manage_prefix_list` canary.
4. Run a switch-scoped policy canary.
5. Run a vPC/interface canary to exercise role, pair, link, deploy, and restore logic.
6. Confirm both retained fabrics and all four switches match their pre-canary snapshots.
7. Run the complete Jenkins target list.
8. Confirm no topology failure, no stale runtime output, no retained test object, and no restoration mismatch.

A local pass, successful Consul write, or canary pass is reported only as that level of evidence; none is described as a complete live-suite success until the final run and post-run topology comparison pass.

## Implementation Boundary

Implementation changes only the Jenkins workspace and the explicitly enumerated Consul keys. It does not modify or commit the user's existing dirty changes in the cisco.nd source checkout. The target Jenkins workspace is not a Git repository, so local before-images and SHA-256 manifests provide change history there.
