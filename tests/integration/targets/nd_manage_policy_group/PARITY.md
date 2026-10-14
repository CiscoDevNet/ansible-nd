# `nd_manage_policy_group` Harness Parity

The legacy suite under `tests/` is intentionally unchanged. The opt-in ND 4.x
harness scenarios live under `tasks/nd4x_demo_*.yaml` and are selected with
the `nd4x_demo` tag.

The harness scenarios use `ND4X-PG-` descriptions and target-local cleanup, so
they do not remove resources created by the legacy suite or by other users.
Each scenario captures a clean switch-side running-configuration baseline after
its setup cleanup and requires final cleanup to restore that baseline.
Mutation checkpoints that need stronger proof perform a fresh gathered-state
read and, where applicable, a direct switch diff assertion.

## Scenario mapping

### `tests/merged.yaml` → `tasks/nd4x_demo_merged.yaml`

| Original scenario | Harness coverage |
|---|---|
| TC1 create `switch_freeform` | `MERGED TC1` |
| TC2 repeated create/idempotency | `MERGED TC2`, harness idempotency phase |
| TC3 BFD prerequisite and same-template second group | `MERGED TC3-PRE`, `MERGED TC3` |
| TC4 template-input update and priority preservation | `MERGED TC4` |
| TC5 post-update idempotency | `MERGED TC5` |
| TC6 BFD template-input update | `MERGED TC6` |
| TC7 bulk create | `MERGED TC7` |
| TC8 bulk idempotency | `MERGED TC8`, harness idempotency phase |
| TC9 missing description failure | `MERGED TC9` |
| TC10 clock creation | `MERGED TC10` |
| TC11 clock `HOUR_OFFSET` update | `MERGED TC11` |
| TC12 clock idempotency | `MERGED TC12`, harness idempotency phase |
| TC13 switch membership update | `MERGED TC13` |
| TC14 membership idempotency | `MERGED TC14`, harness idempotency phase |
| TC15 mixed-update setup | `MERGED TC15` |
| TC16 membership plus template-input update | `MERGED TC16` |

### `tests/deleted.yaml` → `tasks/nd4x_demo_deleted.yaml`

| Original scenario | Harness coverage |
|---|---|
| TC1 delete with deploy | `DELETED TC1` |
| TC2 already-deleted idempotency | `DELETED TC2`, harness idempotency phase |
| TC3 nonexistent delete | `DELETED TC3` |
| TC4 pending normal-template cleanup | `DELETED TC4`, `TC4B` |
| TC5 `switch_freeform` source cleanup | `DELETED TC5`, `TC5B` |

### `tests/gathered.yaml` → `tasks/nd4x_demo_gathered.yaml`

| Original scenario | Harness coverage |
|---|---|
| TC1 gather all | `GATHERED TC1` |
| TC2 template-name multi-match | `GATHERED TC2` |
| TC3 template-name single-match | `GATHERED TC3` |
| TC4 template plus description exact match | `GATHERED TC4` |
| TC5 gather by policy ID | `GATHERED TC5` |
| TC6 nonexistent template | `GATHERED TC6` |
| TC7 nonexistent policy ID | `GATHERED TC7` |
| TC8 multiple filter entries | `GATHERED TC8` |
| TC9 gathered-output structure | `GATHERED TC9` |
| TC10 repeated gather equality | `GATHERED TC10` |
| TC11 gathered field values | `GATHERED TC11` |

### `tests/gathered_round_trip.yaml` → `tasks/nd4x_demo_round_trip.yaml`

| Original scenario | Harness coverage |
|---|---|
| TC1 gathered → merged idempotent replay | `RT TC1` |
| TC2 gathered → merged membership update | `RT TC2` |
| TC3 gathered → merged priority update | `RT TC3` |
| TC4 gathered → merged template-input update | `RT TC4` |
| TC5 gathered → deleted single entry | `RT TC5` |
| TC6 gathered → deleted remaining entries | `RT TC6` |
| TC7 repeated delete | `RT TC7` |
| TC8 update by gathered policy ID | `RT TC8` |
| TC9 delete by gathered policy ID | `RT TC9` |
| TC10 full delete and recreate from snapshot | `RT TC10` |
| TC11 `switch_freeform` mark-delete fallback | `RT TC11` |

### `tests/special_cases.yaml` → `tasks/nd4x_demo_special.yaml`

| Original scenario | Harness coverage |
|---|---|
| A.TC1 force-create duplicate with description | `SPECIAL A.TC1` |
| A.TC2 force-create without description | `SPECIAL A.TC2` |
| B.TC3 merged global check mode | `SPECIAL B.TC3` |
| B.TC4 deleted global check mode | `SPECIAL B.TC4` |
| C.TC5 create with `deploy: false` | `SPECIAL C.TC5` plus retained manual verification |
| C.TC6 membership removal with `deploy: false` | `SPECIAL C.TC6` plus retained manual verification |
| D.TC7 gather by policy ID | `SPECIAL D.TC7` |
| D.TC8 update by policy ID | `SPECIAL D.TC8` |
| D.TC9 delete by policy ID | `SPECIAL D.TC9` |
| D.TC10 unknown ID in merged state | `SPECIAL D.TC10` |
| D.TC11 unknown ID in deleted state | `SPECIAL D.TC11` |
| D.TC12 mixed ID update and composite create | `SPECIAL D.TC12` |
| E.TC13 missing `name` | `SPECIAL E.TC13` |
| E.TC14 duplicate composite key | `SPECIAL E.TC14` |
| F.TC15 BFD prerequisite and bulk create | `SPECIAL F.TC15` |
| F.TC15b BFD bulk idempotency | `SPECIAL F.TC15b`, harness idempotency phase |
| Optional switch management-IP selector | `SPECIAL G.TC16` when inventory exposes `fabricManagementIp` |
| Optional cluster/ticket context | `SPECIAL G.TC17` when `nd_test_cluster_name` and `nd_test_ticket_id` are supplied |

### `tests/template_input_validation.yaml` → `tasks/nd4x_demo_template_input_validation.yaml`

| Original scenario | Harness coverage |
|---|---|
| TC1 valid template inputs | `TIV-TC1` |
| TC2 unknown template-input key | `TIV-TC2` |
| TC3 wrong integer type | `TIV-TC3` |
| TC4 gathered-output replay | `TIV-TC4` |
| TC5 same-template cache smoke test | `TIV-TC5` |
| TC6 validation in global check mode | `TIV-TC6` |
| TC7 deletion bypasses template validation | `TIV-TC7` |

## Execution

The legacy suite remains the default path. Run the additive harness suite with
the target's existing runner and the opt-in tag. Every supported module-specific
harness tag is also applied to the preflight include, so a state-specific run
executes preflight first. Preflight records `nd4x_supported`; the selected
scenario then runs only when the controller is ND 4.x or newer.

The supported tags for this module are:

- `nd4x_demo_merged`
- `nd4x_demo_gathered`
- `nd4x_demo_round_trip`
- `nd4x_demo_deleted`
- `nd4x_demo_special`
- `nd4x_demo_template_input_validation`

The generic `nd4x_demo_replaced`, `nd4x_demo_negative`,
`nd4x_demo_merged_fanout`, and `nd4x_demo_overridden` tags are not exposed here
because this module has no corresponding harness scenario includes.

For live testing, use the local networking inventory:

```text
ansible-playbook \
  -i /Users/astawast/ansible_collections/cisco/nd/tests/integration/inventory.LOCAL.networking \
  /Users/astawast/ansible_collections/cisco/nd_manage_policy_group/tests/integration/targets/nd_manage_policy_group/run_tests.yaml \
  --tags nd4x_demo_merged
```

Individual groups can be selected with `nd4x_demo_merged`,
`nd4x_demo_gathered`, `nd4x_demo_round_trip`, `nd4x_demo_deleted`,
`nd4x_demo_special`, or `nd4x_demo_template_input_validation`.

Live testing is in progress. The test results will be added to this
`PARITY.md` once testing is complete.
