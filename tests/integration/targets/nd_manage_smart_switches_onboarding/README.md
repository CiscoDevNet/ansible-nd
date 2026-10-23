# Smart Switch onboarding integration target

This destructive target manages Hypershield onboarding associations on two
inventory-present Smart Switches. It requires ND 4.2.1 or later, working HTTPAPI
credentials and a valid Hypershield integration usable by both switches. It does
not discover switches or remove physical inventory.

Use a dedicated fabric with no concurrent writers and exactly one active
inventory host. Before any mutation, the target reads every inventory page,
requires both fixture switches to be Smart-capable with usable hostnames and
explicitly empty integration names, and rejects any existing association anywhere
in the fabric. Missing or ambiguous capability/onboarding evidence fails closed.
Both `additionalData` and `additionalSwitchData` are accepted when unambiguous.
The safety check and subsequent writes are not atomic; isolation is mandatory.

Set these variables in your private integration inventory or extra variables:

```yaml
nd_test_smart_switches_allow_destructive: true
nd_test_smart_switches_isolated_fabric: true
nd_test_smart_switches_fabric_name: YOUR_ISOLATED_FABRIC
nd_test_smart_switches_switch_ids:
  - YOUR_EXACT_FIRST_SERIAL
  - YOUR_EXACT_SECOND_SERIAL
nd_test_smart_switches_integration_name: YOUR_VALID_INTEGRATION
# Optional remote cluster routing:
nd_test_smart_switches_cluster_name: ""
```

All fixture defaults are empty and both safety opt-ins default to false. Run the
target using the collection's network integration workflow on a single host,
without global check mode. Preview tasks inside the suite explicitly select
check mode; a global preview cannot exercise the lifecycle assertions.

The ordered suite covers bulk onboarding, repeat idempotency, replaced subset
retention, empty replaced/deleted no-ops, preview and real subset deletion,
overridden addition/removal, empty override and bulk deletion. It validates
changed/failed independently, planned versus confirmed snapshots, exact resource
outcomes, hostname backfill and snapshot diff semantics. Independent fabric
inventory GETs verify the complete association set after each invocation.
Read-only propagation polling is bounded by `poll_attempts` and `poll_delay`
variables with the `nd_test_smart_switches_` prefix; mutations are never retried.
Pagination similarly uses `page_size` and `max_pages`; increase bounds for a
larger isolated fabric.

Validation cases cover duplicate IDs, missing fields, an independently proven
absent selector, conflicting hostname and unsupported merged/gathered states.
Optionally supply `nd_test_smart_switches_non_smart_id` for a present, explicitly
non-Smart switch; it is validated independently before the suite begins.

Controller failure cases are disabled by default. Enable
`nd_test_smart_switches_controller_failures` only with
`nd_test_smart_switches_rejection_fixture_confirmed: true` and a nonempty
`nd_test_smart_switches_rejection_integration_name`. The operator must first
establish that this integration produces keyed per-resource `failureResults`
with no effect for BOTH switch IDs, while the valid integration succeeds.
No universally invalid integration name is assumed. Mixed and all-failure cases
assert exact outcomes, confirmed successful effects, and failure independent of
changed. Unexpected fixture behavior fails the test visibly.

Cleanup is armed only after all guards pass. The always block uses deleted with
only the two owned IDs; it never performs an empty override. Cleanup failures
remain visible. Existing onboarding is neither pre-cleaned nor restored.
Ownership is independently rechecked before broad override scenarios.

Inventory observations and module outputs do not constitute a wire audit:
unchanged inventory alone cannot prove that no transient or idempotent write was
sent. Unit fixtures, syntax checks and this target's existence do not establish
live controller behavior. In particular, result-name correlation, the inventory
onboarding predicate and bodyless bulk-deboard completion still require evidence
from each supported controller release. Transport uncertainty is not forced here.

TODO: Add update/reassociation scenarios only after live evidence establishes
their supported contract.
