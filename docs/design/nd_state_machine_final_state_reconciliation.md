# NDStateMachine final-state reconciliation

## Problem

`after` must describe controller state supported by API evidence. Today,
`NDStateMachine` mutates `existing` while it plans create and update operations,
before those operations succeed. Delete state is updated only after the whole
delete sequence finishes. A failure can therefore make `after` include changes
that failed or were never attempted, or omit changes that already succeeded.

This is a shared state-machine problem, not an Interface Groups-specific one.
It is especially visible when one Ansible operation expands into several
controller writes, for example:

1. remove an interface from `group-a`;
2. add it to `group-b`;
3. deploy the affected target.

If step 1 succeeds and step 2 fails, the member is ungrouped. Reporting the
complete plan, the original state, or an empty collection would all be wrong.

Error detection and state reconciliation are different concerns. PR #398 can
detect a failed HTTP 207 response, but an aggregate result cannot identify which
resources changed when the response does not provide stable identifiers.

## Proposed v1

Separate planning from confirmed execution and reconcile after each **logical
mutation checkpoint**:

1. Read immutable `before` state.
2. Calculate `planned` without changing confirmed state.
3. Execute logical mutation checkpoints in their required order.
4. After each response, apply only proven effects to `confirmed`.
5. Stop on the first failed or unknown checkpoint by default.
6. At the outer module boundary, select the user-facing result.
7. Only when an outcome is unknown and `verify=true`, perform one forced
   controller readback.

This v1 deliberately does not introduce a generic dependency graph. Ordered
workflows declare checkpoints in execution order. A later checkpoint that
depends on an earlier one is simply not attempted after failure or ambiguity.

## State model

| State | Meaning |
| --- | --- |
| `before` | Controller state read before any mutation. It never changes. |
| `planned` | Expected state if every requested mutation succeeds. Used by check mode. |
| `confirmed` | `before` plus only effects proven by mutation outcomes. |
| `observed` | A fresh, cache-bypassing controller read performed after an unknown outcome. |

`observed` is controller intent visible at readback time. It can include
controller defaults, normalized values, partial effects, and concurrent changes.
It does not prove that configuration reached the switches.

Select `after` as follows:

| Situation | Result |
| --- | --- |
| Check mode | `after=planned` |
| All executed effects are known | `after=confirmed` |
| Unknown effect and conclusive opt-in readback | `after=observed` |
| Unknown effect without conclusive readback | Omit `after`; report it as unknown |

`diff` follows the same selection. `changed` comes from recorded mutation
outcomes, not from comparing `before` with a readback that may include unrelated
controller changes.

Recommended result metadata is:

```yaml
after_status: planned | confirmed | observed | unknown
reconciliation_required: true | false
verification_performed: true | false
affected_identifiers: []
```

When delivery may have changed the controller but no response proves it, retain
the normal Boolean `changed` value derived from confirmed effects and add
`may_have_changed: true`. Never use `after: []` to represent uncertainty.

## Logical mutation checkpoints

A checkpoint represents one controller effect that can be assessed together.
It is defined by the orchestrator because the REST layer cannot infer resource
semantics from a path and payload.

Minimum checkpoint data is:

```text
phase, operation, affected identifiers, previous values, intended values,
request identity, aggregate response result, outcome, error
```

V1 outcomes are:

```text
succeeded, failed, unknown, not_attempted, skipped
```

Checkpoint examples include:

- one individual create, update, or delete;
- one bulk create or delete;
- an Interface Group source detachment;
- each cumulative `any` Interface Group update batch;
- association clearing before resource deletion;
- a deferred remove, save, or deployment action.

The shared executor must record the checkpoint result before returning or
raising. Callers must not mutate `confirmed` while building the plan. On a
proven success, apply the intended effect immediately. On a deterministic
rejection with no change, retain the previous value. On timeout, lost response,
or uncorrelatable partial success, mark the affected scope unknown.

### Interface Group move

PR #495 already validates the complete move before writing and uses
`prepare_mutations()` to detach the source before normal CRUD. Retain that
ordering, but expose its effects as checkpoints:

1. Preflight builds the move plan without changing controller or confirmed state.
2. Source detach is one checkpoint.
3. Target add is a second checkpoint.
4. Deployment is a separate deferred-action checkpoint.

If source detach succeeds and target add fails, `confirmed` contains the source
without the member and the unchanged target. Check mode applies both planned
effects only to `planned` and sends no request.

`prepare_mutations()` currently returns no outcome and mutates shared state
directly. It should instead return or emit checkpoint results so the state
machine owns confirmed-state updates.

## Response handling and HTTP 207

Reuse PR #398's shared Multi-Status parsing. The response layer remains
responsible for producing the final aggregate request result:

```yaml
success: false
changed: true
retryable: false
error_summary: one or more items failed
```

The response and aggregate result must remain available to the checkpoint even
when the request helper raises an exception.

Reconcile aggregate results as follows:

| Result | Reconciliation |
| --- | --- |
| Successful individual request | Confirm its known resource effect. |
| Deterministic individual rejection with no change | Confirm no effect. |
| Successful bulk request | Confirm the submitted batch when the endpoint contract supports it. |
| Failed bulk request with `changed=false` | Confirm no batch effect. |
| Failed bulk request with `changed=true` and no stable item keys | Mark the submitted scope unknown. |
| Timeout or uncertain delivery | Mark the submitted scope unknown. |

Endpoint-specific code may correlate per-item results when stable identifiers
exist. V1 must not infer identity from message text or undocumented response
ordering. Lack of correlation is handled as unknown, not guessed state.

## Continuation policy

State accounting and error continuation are separate decisions.

The safe v1 default is fail-fast: after a failed or unknown checkpoint, mark
later checkpoints `not_attempted` and unwind to finalization. This covers ordered
workflows without a generic dependency graph.

An internal `ignore_errors` option must not erase the failed outcome. If retained,
it may ask a module-specific workflow to continue only operations that the
module explicitly knows are independent. That policy can be added separately;
it is not required for confirmed-state reconciliation.

Ansible task-level `ignore_errors: true` is unrelated. It lets the play continue
after the module returns failure and does not change module-side API handling.

## Deferred mutations and deployment

Deferred controller writes must use the same checkpoint contract and finish
before result finalization. Examples include pending removals, attachment
changes, configuration save, and deployment.

Resource state and deployment state remain separate:

- `deploy=false` can still change controller intent, so `after` changes normally;
- `deploy=true` adds a later action but does not redefine the resource state;
- a deployment failure does not undo already confirmed controller intent;
- save and deploy targets must be derived only from confirmed mutations.

`after` therefore remains independent of the deploy option. It never claims
that controller intent was successfully realized on switches.

## Unknown outcomes and opt-in readback

Do not add a GET after every successful request. Known outcomes already produce
`confirmed`, and repeated GETs add load while still risking stale data.

Readback is allowed only when at least one checkpoint is unknown and
`verify=true`. At the outer finalization boundary:

1. call `refresh_current(force=true)` once;
2. reuse the same query and normalization path used for `before`;
3. bypass initialization and orchestrator caches;
4. use targeted queries when an orchestrator reliably supports affected keys,
   otherwise use `query_all()`;
5. merge targeted results, including confirmed absences, into the complete
   `confirmed` collection so `observed` is never a partial resource list;
6. select `observed` only when the readback is conclusive.

Eventually consistent endpoints can implement a bounded completion check. A
successful but potentially stale GET is not automatically conclusive. If no
completion condition exists or retries expire, keep the outcome unknown and
omit `after`.

With `verify=false`, no readback is performed. Return the mutation failure,
identify the affected scope, omit `after` and `diff`, and advise the user to run
`state=gathered` where supported.

If mutation and readback both fail, preserve the mutation failure as the primary
error and attach the readback failure as reconciliation detail.

## Outer finalization boundary

Finalization belongs to the outermost owner of the complete workflow:

- a simple module entry point after `manage_state()` returns or raises;
- a coordinator after prerequisite, CRUD, deferred, save, and deploy phases
  have completed or stopped.

Inner orchestrators record checkpoint outcomes but do not select `after` or run
verification. This prevents duplicate queries and ensures failures also pass
through finalization. Check mode never performs a final readback.

## Reuse from current work

| Existing work | Reuse in v1 | Required adjustment |
| --- | --- | --- |
| [PR #398](https://github.com/CiscoDevNet/ansible-nd/pull/398) | Aggregate HTTP 207 success, changed, retryable, and error parsing | Preserve the result and response for reconciliation before raising. |
| [PR #515](https://github.com/CiscoDevNet/ansible-nd/pull/515) | Shared verify argument, finalization context, forced query hook, cache handling | Run on failure paths and only for unknown outcomes; require conclusive readback. |
| [PR #495](https://github.com/CiscoDevNet/ansible-nd/pull/495) | Preflight move planning and ordered prerequisite mutation hook | Emit source-detach checkpoints instead of mutating shared state silently. |
| [PR #294](https://github.com/CiscoDevNet/ansible-nd/pull/294) | Returning operation success or failure to callers | Return a structured checkpoint result, not only a Boolean. |
| [PR #522](https://github.com/CiscoDevNet/ansible-nd/pull/522) | Immutable planning and operation-result concepts | Generalize the concepts in shared utilities, without importing Interface Group-specific behavior. |

## Implementation gaps

1. Introduce separate `planned` and `confirmed` collections; keep `before`
   immutable.
2. Add a small structured checkpoint/outcome type and make the shared executor
   record it before raising.
3. Retain PR #398 aggregate response data across exception paths.
4. Convert generic CRUD loops to apply confirmed effects only after checkpoint
   completion.
5. Adapt prerequisite and nested multi-request orchestrators, starting with
   Interface Groups.
6. Route deferred writes through checkpoints and finalize only at the outer
   workflow boundary.
7. Make `NDOutput` support omitted `after` and `diff` with explicit unknown
   metadata.
8. Add forced, cache-bypassing readback for unknown outcomes when `verify=true`.
9. Audit all `NDStateMachine` consumers and direct mutation calls for checkpoint
   coverage.

## Test matrix

Shared state-machine tests must cover:

- first update succeeds, second fails, later update is not attempted;
- deterministic individual failure with no change;
- timeout or lost response with unknown delivery;
- bulk all-success, all-failed/no-change, and mixed HTTP 207;
- `ignore_errors` records failure even when continuation is requested;
- check mode returns `planned` and performs no write or verification;
- unknown outcome with `verify=false` omits `after` and `diff`;
- unknown outcome with conclusive `verify=true` returns `observed`;
- stale or failed readback remains unknown and preserves the mutation error;
- cached query data is bypassed during verification.

Interface Groups must additionally cover:

- source detach succeeds and target add fails;
- one source detach succeeds and a later source detach fails;
- an `any` cumulative batch succeeds before a later batch fails;
- association clearing succeeds before bulk delete fails;
- `deploy=false` and deployment failure both preserve confirmed controller
  intent correctly.

## Non-goals for v1

- transaction rollback;
- a generic dependency graph or scheduler;
- automatic GET after successful known mutations;
- endpoint-specific per-item correlation where stable keys do not exist;
- proof that controller intent was deployed to switches.
