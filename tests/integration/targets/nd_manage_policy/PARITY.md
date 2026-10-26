# `nd_manage_policy` Harness Parity

This document maps every original `nd_manage_policy` integration scenario to
the opt-in ND 4.x harness migration. The original files remain under `tests/`
and are the reference suite for the harness coverage.

The harness scenarios are target-local under `tasks/` and are selected with
`--tags nd4x_demo`. They are tagged `never` so the existing legacy suite keeps
its current default behavior until live parity results are recorded.

The policy REST API is fabric-scoped, so `nd4x_policy_check_mode_queries`
snapshots the complete `/policies?max=10000` collection. This is intentionally
wider than the requested entries and detects unintended predictive mutations
to any policy in the test fabric.

Preflight is selected by the full-suite tag and by every state-specific tag.
Single-switch scenarios require only the explicitly configured primary switch
(`test_switch_serial_1`). Fan-out and gathered multi-switch scenarios require
both explicitly configured switches. The fabric must also be explicitly
configured through `test_fabric_name` or its supported alias; there is no
implicit `test_fabric` fallback. This prevents a missing local variable from
silently targeting another fabric.

## Current live status

The harness implementation and legacy-to-harness scenario mapping are in
place. Live ND 4.x execution is in progress.

The first live merged-state run produced the following recap:

```text
nd : ok=35 changed=2 unreachable=0 failed=1 skipped=9 rescued=0 ignored=0
```

The failure occurred in `nd4x_demo_merged.yaml` at the task
`MERGED: Create clock_summertime, switch_freeform, and feature_enable`.
The captured check-mode result was:

```text
before_count: 0
after_count: 3
proposed_count: 3
changed: false
failed: false
```

The harness therefore stopped on its expected `changed: true` assertion.
This is the known `nd_manage_policy` check-mode reporting defect tracked in
[#630](https://github.com/CiscoDevNet/ansible-nd/issues/630), not a missing
harness scenario.

The live fan-out run produced:

```text
nd : ok=39 changed=2 unreachable=0 failed=1 skipped=5 rescued=0 ignored=0
```

It encountered the same check-mode `changed: false` defect tracked in
[#630](https://github.com/CiscoDevNet/ansible-nd/issues/630). The remaining
live state results and any controller-specific deviations will be recorded
here as testing continues.

A run reported as gathered produced the following recap:

```text
nd : ok=39 changed=2 unreachable=0 failed=1 skipped=5 rescued=0 ignored=0
```

However, the captured failure is again at
`nd4x_demo_merged.yaml:61` (`MERGED: Create clock_summertime,
switch_freeform, and feature_enable`). The run stopped on the same
check-mode `changed: false` defect before reaching the gathered scenario, so
this is not yet a gathered-scenario result. It remains tracked in
[#630](https://github.com/CiscoDevNet/ansible-nd/issues/630).

A run reported as deleted produced:

```text
nd : ok=35 changed=2 unreachable=0 failed=1 skipped=9 rescued=0 ignored=0
```

The log shows the same failure at
`nd4x_demo_merged.yaml:61` before the deleted scenario was reached. The
deleted-state live result is therefore still pending; this run was blocked by
the known check-mode defect in
[#630](https://github.com/CiscoDevNet/ansible-nd/issues/630).

A run reported as edge cases produced:

```text
nd : ok=35 changed=2 unreachable=0 failed=1 skipped=9 rescued=0 ignored=0
```

The log shows the same failure at
`nd4x_demo_merged.yaml:61` before the edge-case scenario was reached. The
edge-case live result is therefore still pending; this run was blocked by the
known check-mode defect in
[#630](https://github.com/CiscoDevNet/ansible-nd/issues/630).

A run reported as negative produced:

```text
nd : ok=35 changed=2 unreachable=0 failed=1 skipped=9 rescued=0 ignored=0
```

The log shows the same failure at
`nd4x_demo_merged.yaml:61` before the negative scenario was reached. The
negative-state live result is therefore still pending; this run was blocked
by the known check-mode defect in
[#630](https://github.com/CiscoDevNet/ansible-nd/issues/630).

## Harness coverage and safeguards

- Each migrated state is an opt-in `never`-tagged include with its own
  state-specific tag: `nd4x_demo_merged`, `nd4x_demo_fanout`,
  `nd4x_demo_modify`, `nd4x_demo_gathered`, `nd4x_demo_deleted`,
  `nd4x_demo_edge_cases`, and `nd4x_demo_negative`.
- The shared harness contract exercises check mode, apply, idempotency, and
  controller-state assertions. The policy snapshot protects the full fabric
  policy collection during predictive execution.
- Positive checks validate exact template names, priorities, template inputs,
  switch association, policy IDs, and owned-policy counts in the scenarios
  where duplicates or stale records would otherwise be possible. Template-key
  matching, gathered force-create, replacement, and multi-template flows
  explicitly preserve the original records and assert the expected number of
  resulting policies.
- The original multiline banner fixture and the legacy five-entry
  multi-template request shape are retained, including the legacy values and
  priorities.
- Cleanup runs from `always`, tracks policies created by the scenario, uses
  policy IDs where available, guards fallback matching against pre-existing
  records, and fails if owned records remain. Single-switch cleanup builds a
  one-switch list; multi-switch cleanup includes the second switch only when
  the selected scenario requires it.
- Expected validation failures remain direct module calls so their error
  wording, `changed: false`, and absence of proposed/after state can be
  asserted without weakening the shared harness contract.

## Scenario mapping

| Original scenario | Original file | Harness replacement | Coverage notes |
|---|---|---|---|
| Single-template merged creation and idempotency | `tests/merged.yaml` | `nd4x_demo_merged.yaml` | Harness predictive/apply/idempotency phases and REST validation cover clock timezone, summertime, freeform, feature enable, and the harness-owned BFD timer case. |
| Multiple policies in one merged task | `tests/merged.yaml` | `nd4x_demo_merged.yaml` | Preserved as separate harness calls so each module result is independently checked. |
| Multi-switch fan-out and idempotency | `tests/merged_multi_switch.yaml` | `nd4x_demo_fanout.yaml` | Covers shared global policies on both switches. |
| Per-switch policy override | `tests/merged_multi_switch.yaml` | `nd4x_demo_fanout.yaml` | Covers switch-specific policy data and a distinct override description. |
| Multiple templates in one task | `tests/merged_multi_template.yaml` | `nd4x_demo_fanout.yaml` | Preserves the exact five-entry request values (`Timezone CET`/101, `Summertime CEST`/102, `System vlan long-name`/110, `BFD timers`/115, and `as-format asdot`/120), with explicit-ID cleanup and exact gathered-state checks. |
| File-backed banner/syslog/spanning-tree/alias inputs | `tests/merged_with_vars.yaml` | `nd4x_demo_fanout.yaml` | File inputs are loaded from the existing `files/` fixtures and passed through the harness; the legacy multiline banner is preserved and asserted exactly. |
| Description-key priority and input updates | `tests/modify.yaml` | `nd4x_demo_modify.yaml` | Includes the BFD feature prerequisite, update, exact omitted-priority/template-input preservation, and harness idempotency. |
| Policy-ID update with omitted description | `tests/modify.yaml` | `nd4x_demo_modify.yaml` | Gathers the live ID, updates through the harness, and verifies the same ID, description, and priority remain correct. |
| Default template-name matching | `tests/template_key_matching.yaml` | `nd4x_demo_modify.yaml` | Verifies exact two-policy state, distinct IDs, preserved descriptions/priorities, and repeated multi-match no-op without a third policy. |
| Gather by switch and template filter | `tests/gathered.yaml` | `nd4x_demo_gathered.yaml` | Harness runs read-only gathered phases with expected `changed: false`. |
| Gather both switches and whole fabric | `tests/gathered.yaml` | `nd4x_demo_gathered.yaml` | Covers switch-scoped and config-omitted gather operations. |
| Gathered output policy-ID round trip | `tests/gathered.yaml` | `nd4x_demo_gathered.yaml` | Covers unchanged replay with a post-gather count check, same-ID update, and force-create after removing `policy_id`, verifying exactly two policies with distinct IDs and preserving the original. |
| Delete one and multiple policies | `tests/deleted.yaml` | `nd4x_demo_deleted.yaml` | Covers the legacy clock_timezone template-name delete followed immediately by a repeated delete asserting `changed: true`, plus description-key deletion, default template-name deletion, multiple template names, and post-delete absence checks. |
| Pending normal-template cleanup | `tests/deleted.yaml` | `nd4x_demo_deleted.yaml` | Harness runs the intentional `deploy: false` then `deploy: true` operations with idempotency disabled. |
| Pending PYTHON-content cleanup fallback | `tests/deleted.yaml` | `nd4x_demo_deleted.yaml` | Covers the direct-delete fallback and subsequent deploy. |
| Delete by description | `tests/deleted.yaml` | `nd4x_demo_deleted.yaml` | Harness coverage with exact description-key targeting. |
| Delete-and-create template replacement | `tests/delete_and_create.yaml` | `nd4x_demo_edge_cases.yaml` | Covers same description with a different template, exact old-policy absence, new policy ID, switch association, and automatic idempotency. |
| PYTHON delete-and-create fallback | `tests/delete_and_create.yaml` | `nd4x_demo_edge_cases.yaml` | Covers `switch_freeform` replacement with `feature_enable`, including direct-delete fallback and exact old-policy absence. |
| `create_additional_policy` duplicate creation | `tests/create_additional_policy.yaml` | `nd4x_demo_edge_cases.yaml` | Harness predictive/apply coverage uses `idempotency: false` because repeated creation is intentionally non-idempotent. |
| Policy-ID reapply with `create_additional_policy: true` | `tests/create_additional_policy.yaml` | `nd4x_demo_edge_cases.yaml` | Harness expects a no-op for the exact policy ID. |
| Missing args, bad templates, bad switches, shape validation | `tests/sanity.yaml` | `nd4x_demo_negative.yaml` | Kept as direct module calls with exact failure/no-op assertions; the harness contract advises direct tasks for negative tests. |
| Create/delete/recreate lifecycle | `tests/sanity.yaml` | `nd4x_demo_negative.yaml` | Harness creates, deletes by template name, verifies absence, recreates, and verifies the recreated policy's exact priority and template input. |
| Valid template-input validation | `tests/template_input_validation.yaml` | `nd4x_demo_negative.yaml` | Harness predictive/apply/idempotency coverage. |
| Unknown key, wrong type, check-mode validation | `tests/template_input_validation.yaml` | `nd4x_demo_negative.yaml` | Direct module calls assert the offending key/type wording, `changed: false`, empty `after`, and the proposed template entry because expected predictive failures should not proceed to apply. |
| Gathered-output validation round trip | `tests/template_input_validation.yaml` | `nd4x_demo_negative.yaml` | Gathered entry is replayed through the harness. |
| Same-template validation cache smoke test | `tests/template_input_validation.yaml` | `nd4x_demo_negative.yaml` | Three `feature_enable` entries are applied in one harness call. |

## Intentional exceptions

- Negative validation cases remain direct `cisco.nd.nd_manage_policy` tasks so
  the scenario can assert exact failure behavior without allowing the harness
  to continue from an expected predictive failure into a real apply.
- Duplicate creation and pending-delete deployment cases set
  `idempotency: false`; their purpose is to prove an intentional second
  mutation, which conflicts with the harness's mandatory idempotency contract.
- Cleanup failures are not ignored. Harness cleanup deletes by owned policy ID,
  uses the reserved `ND4X-` description prefix for harness-owned records,
  refuses to delete matching records found before the first harness scenario,
  and asserts that no owned records remain. Legacy-description fixtures are guarded against
  pre-existing records and are removed through captured policy IDs, with a
  guarded description fallback for partial setup failures. A
  pre-existing matching record must be removed manually or the harness must
  use a dedicated fabric.
- The BFD timer fixture uses the unique `ND4X-merged-bfd` description, is
  validated by its gathered controller policy ID, and is covered by the
  reserved-description cleanup regex.
- Legacy scenario files are not deleted. They remain the original-suite
  reference until live legacy-versus-harness results are recorded.
- Positive REST checks include the exact template name, priority, and key
  template inputs wherever the API exposes them; gathered assertions cover
  switch association and the complete returned policy shape.

## Running the harness suite

```text
ansible-test network-integration nd_manage_policy \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo -vv
```

Use `nd4x_demo_merged`, `nd4x_demo_gathered`, or another scenario tag in place
of `nd4x_demo` to run one migrated group; the preflight is tagged with each
group so it runs first. The committed
`tests/integration/inventory.networking` is a shared placeholder. Copy it to a
private absolute path and provide real connection values there. Likewise,
copy `tests/integration/integration_config.yml.template` to the ignored local
`tests/integration/integration_config.yml`; neither local file belongs in the
commit.
