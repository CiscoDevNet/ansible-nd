# Response-first interface breakout: input and execution contract

`cisco.nd.nd_manage_breakout_interfaces` manages breakout and unbreakout on a
standalone fabric. `merged` uses native parent names, such as `Ethernet1/50`.
`deleted` accepts that parent or a child such as `Ethernet1/50/2` as a selector
for unbreaking the whole family. The module selects an observed child internally
when calling unbreakout; a child selector does not request single-lane removal.

```yaml
- name: Ensure a native parent is broken out
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: merged
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50]
        breakout_map: 25g-4x
```

`switch_id` accepts a serial number or management IPv4/IPv6 address. Serial inputs
need no IP-to-serial translation. IP inputs reuse the shared switch resolver;
both reach the same serial-number API identity. Duplicate targets are rejected,
including aliases that resolve to the same switch.

`merged` means **ensure broken out**, not ensure a particular existing map. A
parent already broken out is left unchanged, even when the requested map differs.
The requested map is used only for a new breakout. To change a map, explicitly
unbreak the parent with deleted, then run merged with the new map. There is no
hardware-model/map allowlist in the module.

Automatic map replacement is not supported. An explicit deleted-then-merged
map change is disruptive and non-atomic: both actions can apply immediately,
and a failed new breakout can leave the family native. Hardware coupling can
affect ports outside the named parent. There is no automatic rollback or write
retry, and the controller validates map support when breakout is requested.

```yaml
- name: Ensure the same parent is unbroken
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: deleted
    config:
      - switch_id: 192.0.2.10
        interface_names: [Ethernet1/50]
```

```yaml
- name: Unbreak the whole family using a discovered child selector
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: deleted
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50/2]
```

For `deleted`, a child is normalized to its canonical parent identity before
discovery. If the family is broken out, the child selector must be among its
observed physical children. If the parent is already native, deletion is a no-op
even though that old child no longer exists. The wire request uses a selected
observed child and can therefore differ from the supplied selector. This adds no
API lookup: the existing filtered family discovery already provides membership.
After successful unbreakout, repeating the former child selector is a no-op.
Alternating parent and child selectors across subsequent tasks is also a no-op
while the parent remains native. If neither a physical native parent nor
physical breakout children can be found, discovery fails rather than treating
the missing family as already unbroken.

Use a non-empty fabric, config list and interface list. `merged` requires a
non-blank map; `deleted` must omit it. Child names are rejected for `merged`.
Dotted subinterfaces, four-part names, zero slot/port/lane, FEX interfaces,
replaced/overridden/gathered states, ticket/cluster options and module save/deploy controls
are not accepted. A three-part name alone does not prove that an interface is a
breakout child; discovery must identify it as a physical, non-FEX family member.
A parent and child, or two children of the same family, cannot be specified in
one task. Duplicate family aliases are rejected before mutation; IP/serial
aliases are checked again after shared switch resolution. Nexus Dashboard and the switch decide whether a
map is supported. Coupled hardware can affect ports outside the named parent.

## Reads, actions and verification

The workflow resolves IP identities when necessary, validates the platform of
every requested switch, reads filtered parent-family summaries, then plans
breakout/unbreakout. Native parent existence alone is
not proof of native state: child interfaces must also be considered, including
an intent-only parent that remains after a partial failure.

The request processing map is:

| Input/phase | Controller call | Purpose |
|---|---|---|
| Serial switch input | No translation call | Use the serial directly as `switchId`. |
| Management IP input | Shared fabric switch discovery | Resolve the management address to a serial once and reuse the result. |
| Platform preflight | Cached IP-resolution metadata, otherwise `GET .../switches/{serial}` once per distinct switch | Require `additionalData.platformType=nx-os` for all requested targets before interface discovery or mutation. |
| Initial family discovery | Filtered `GET .../fabrics/{fabric}/interfacesSummary` | Read requested parents, children and dotted descendants before planning. |
| Merged native parents | One bulk `POST .../interfaceActions/breakout` | Send serial, native parent and requested map for new breakouts only. |
| Deleted broken parents | One bulk `POST .../interfaceActions/remove` | Send serial and an observed child; keep the public outcome keyed to the native parent. |
| Optional verification | Fresh filtered family-summary reads | Observe topology without whole-switch inventory or policy-MAP reads. |

All paths below are relative to `/api/v1/manage/fabrics/{fabric}`:

```text
IP input only:
GET /switches?filter=fabricManagementIp:{ip}&max=1000&offset=0

Serial input without cached switch metadata:
GET /switches/{serial}

All requested switches must report additionalData.platformType=nx-os.

Before planning any supported state:
GET /interfacesSummary?switchId={serial}&includeAll=true
    &filter=interfaceName:*Ethernet1/50*&max=1000&offset=0

Merged actionable parents:
POST /interfaceActions/breakout
{"interfaces": [{"switchId": "SERIAL", "interfaceName": "Ethernet1/50", "breakoutMap": "25g-4x"}]}

Deleted actionable parents (child discovered from the filtered summary):
POST /interfaceActions/remove
{"interfaces": [{"switchId": "SERIAL", "interfaceName": "Ethernet1/50/1"}]}
```

The endpoint models encode the query values; pagination advances the offset only
when more filtered rows remain. Each action includes all actionable inputs across
switches in one `interfaces` array, not one POST per input group. Native parents
with no children are actionable for merged; observed child families are
actionable for deleted.
No-ops are omitted from the action payload. Local
identity matching uses a keyed index, so response reordering does not alter the
parent-oriented results.

Discovery groups parents by switch, slot and leading port digit. Their longest
shared numeric prefix supplies one selective
server-side filter. For example, parents 50 and 51 can use
`interfaceName:*Ethernet1/5*`. The response is a candidate set, not an exact
family match: local boundary checks exclude names such as `Ethernet1/500`.
Disjoint ranges are batched separately rather than broadening to every interface
on the switch: 21, 50 and 51 need two filtered reads, not three. Returned rows are
indexed into exact requested families once instead of rescanned for each parent.
Pagination continues for the filtered response; server-side OR grouping is not assumed.

No separate fabric/switch existence preflight, whole-switch interface inventory,
config save or deployment is added. The shared targeted switch cache reuses IP
lookup metadata; serial inputs add one exact switch-detail GET per distinct
switch, not per interface. The tested switch-list OR filters returned zero matches
on the lab controller and are not assumed to work for batch platform discovery.
Merged/deleted never read policy maps. Hardware-model, port and map capability
validation remains with the controller and switch.

Platform validation is independent of fabric type: Campus VXLAN can contain
both NX-OS and IOS-XE switches. NX-OS targets remain eligible; IOS-XE and other
platforms are rejected for merged/deleted, including check mode and
otherwise idempotent requests. Missing/unrecognized platform metadata cannot
establish eligibility and fails safely. Conflicting platform evidence for the
same serial, including missing metadata versus a verified platform, is rejected
before caching a new IP alias; consistent aliases are allowed without extra GETs.
If any requested switch fails preflight,
the task sends no topology/policy query or mutation for any target. A supported
NX-OS platform does not prove a particular port/map supports breakout.

This follows [issue #543](https://github.com/CiscoDevNet/ansible-nd/issues/543)
and the [ND 4.3.1 Campus VXLAN limitations](https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/articles-431/editing-fabric-settings-campus-vxlan.html),
which exclude breakout on IOS-XE rather than excluding every Campus-fabric switch.

## Response matching and optional verification

Changed parents are sent in a bulk action request. The breakout endpoint receives
native parents and maps; the remove endpoint receives observed breakout children.
Responses are correlated by switch/interface identity, never array position.
No missing item, blank-interface summary, duplicate result or timeout is promoted
to a complete per-parent success.

By default, complete identified operation responses are trusted without an
unconditional post-action family query. `after_status: response_confirmed`
does not assert independently observed topology, a running configuration, an
`inSync` status, or a map that was not read. Partial or uncertain outcomes retain
the action evidence and do not fabricate a complete `after` state. Standard
output still includes `after: []` when `after_status: unknown`: that means no
reliable final snapshot is available, not that the inventory is empty or that
native parents have been restored.
Failed or unknown action responses remain failures even if optional readback
finds the requested topology.

```yaml
verify:
  enabled: true
```

This enables focused post-action controller readback. It is disabled by default
and does not expose the generic verification prototype's retry settings.
Only submitted parent families are read back. If every requested parent was
submitted, `after_status: observed` describes that final readback. A mixed run
with changed and no-op parents uses `partially_observed`: changed entries carry
`post_action_discovery` evidence, while no-op entries retain `initial_discovery`
evidence. `verification.scope` lists attempted logical parent targets.
Check mode still performs discovery but sends no breakout or unbreakout
requests; its output is predictive, not controller-confirmed.

## Deployment and staging

On some switch models, Nexus Dashboard applies breakout and unbreakout
configuration internally without a separate deployment call. These topology
operations cannot be staged by this module. It does not expose `config_actions`
or make separate config-save or deployment requests.

After unbreakout, interface-level configuration for restored or otherwise
affected interfaces may remain pending even when the unbreakout itself has been
applied. Manage that configuration separately using the appropriate Ethernet
interface module: `cisco.nd.nd_interface_ethernet_routed`,
`cisco.nd.nd_interface_ethernet_access`, or
`cisco.nd.nd_interface_ethernet_trunk_host`. In those modules,
`config_actions.deploy: false` stages changes made by the task, while
`config_actions.deploy: true` deploys them. These controls do not stage the
breakout or unbreakout itself, nor automatically deploy all previously pending
interface intent. No resource, switch or global deployment scope, or
model-specific adjacent-port mapping, is inferred by the breakout module.

## Output and diagnostics

Every business workflow result uses the collection's shared `NDOutput` formatter
and includes `output_level`, `changed`, `before`, `after` and `diff`. This also
applies to local-validation, initialization and workflow failure paths. Missing
or unreliable snapshots use empty lists; `after_status` explains the provenance
and must be read alongside the snapshot.

`diff` is the planned actionable delta, not a record of successful mutation.
`output_level: info` and `debug` also include grouped `proposed` intent for all
requested parents, including no-ops, and preserves normalized child selectors.
That intent can contain a requested map
which was not read from existing controller state. `debug` additionally includes
`logs`. Output level does not change CLI verbosity or trigger controller reads.

The result includes parent-oriented `api_outcomes`, the actual wire interface
(parent for breakout, selected child for unbreakout), and `after_status`.
`before` and `after` retain canonical parent identity. For a child input,
`api_outcomes.requested_interface_name` records the supplied normalized selector;
`interface_name` is the parent and `api_interface_name` is the actual wire child.
An API-confirmed new breakout reports `requested_breakout_map` and
`evidence: api_response`, not an invented observed `breakout_map`. Check-mode
changes carry prediction evidence instead.
`may_have_changed` distinguishes an uncertain mutation from proven no change.
Workflow `changed` and `failed` remain authoritative at every output/verbosity
level; diagnostic API aggregation does not override them.

CLI `-vv` adds write `api_paths` and `api_verbs`. CLI `-vvv` adds standard full
API response/result/diff/metadata/payload diagnostics for reads and writes, and
the compact `api_calls` trace of method, path, HTTP status and elapsed time.
Shared switch-resolution entries identify their purpose and may omit elapsed
time. The compact trace is absent at lower verbosity. `api_outcomes` remains a
business result at every verbosity, not a raw diagnostic trace. A diagnostic
formatting error adds a warning without discarding the primary operation report.

Every registered call retains its state, operation and check-mode metadata.
Transport failures are recorded without replaying the request. If no response
was received, the diagnostic entry uses `RETURN_CODE: -1` and
`response_received: false`; it is an error record, not a controller response.
If a GET received a reply before a later retry failed, diagnostics retain that
last received reply with the completion error rather than an older request's data.
No credentials are included in this document or its examples.
