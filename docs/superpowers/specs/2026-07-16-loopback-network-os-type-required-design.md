# Design: `network_os_type` as a required user-supplied parameter (`nd_interface_loopback`)

Date: 2026-07-16
Status: Approved (Allen, with naming/placement decisions settled against the ND 4.2.1 OpenAPI schema)
Branch: `nd_interface_loopback_policy_type_union` (PR #403)

## Problem

PR #403's remaining open item was "folding in `platform_type` as a model selector", originally blocked on PR #404
(`FabricContext.get_platform_type()`). Discussion with Mike and Matt resolved the blockage by changing the approach:
the platform/OS selector becomes a **mandatory module parameter read from the argspec**, not a value derived from the
switch inventory. A mandatory parameter lets the module validate every interface parameter — including which policy
templates are legal — *before any call to the controller*.

This supersedes, for now, the position in `docs/design/2026-07-13-interface-modules-across-fabrics-and-os.md` that
`networkOSType` is "derived from the switch, never user-facing". Deriving it remains the long-term direction (see
Future work), but it arrives as a *default*, not as the only source.

## Decisions

### Name: `network_os_type`

Candidates were `os_type` (Matt), `platform_type` (Allen), and `network_os_type`. The collection's philosophy is that
parameters mirror the OpenAPI schema, and the wire field is `networkOSType` at `configData.networkOS.networkOSType` —
so the parameter is `network_os_type`, exactly as `policyType` became `policy_type`.

Supporting evidence from the ND 4.2.1 `manage.json` schema:

- `createInterfaceLoopbackManagedDiscriminator` marks `networkOSType` **required** — the schema itself treats it as a
  mandatory discriminator, which is precisely the role this parameter now plays in the module.
- The field's enum is `["nx-os", "ios-xe"]` and its description reads "Specifies the platform type for loopback
  interfaces operating in managed mode" — both proposed human names describe the same field; the wire name wins.
- The switches-inventory field `additionalData.platformType` (read by the future `FabricContext.get_platform_type()`
  fallback) is a *different* field with a *different* enum (`nx-os`, `ios-xe`, `ios-xr`, `sonic`, `apic`, `other`).
  Naming the module parameter `platform_type` while it maps to `networkOSType` would invite exactly the enum-mismatch
  confusion untangled in PRs #404/#405.

### Placement: nested in its wire position

`config[].config_data.network_os.network_os_type` — a sibling of `policy`. The module's documented invariant is that
playbook config uses the same nesting as the API payload so `to_payload()`/`from_response()` need no custom flattening;
the field already exists on `LoopbackNetworkOSModel` in this position. Ansible enforces `required=True` whenever the
`network_os` dict is supplied — exactly when the OS gate matters. Delete/query tasks that omit `config_data` are
unaffected.

### Choices: `["nx-os"]` only

Only NX-OS loopback policy models exist today. `choices=["nx-os"]` rejects anything else before the module runs, with a
standard Ansible error. The list grows when IOS-XE models land.

### Model wiring: minimal gate

`LoopbackNetworkOSModel.network_os_type` drops its `default="nx-os"` and becomes required, mirroring the schema's
`required: ["networkOSType"]`. It keeps `Literal["nx-os"]`, `alias="networkOSType"`, and `frozen=True`. No
OS-discriminated outer union is introduced — that restructure is deferred until the first IOS-XE model makes it
meaningful (YAGNI).

## Read-path safety

`LoopbackInterfaceOrchestrator.query_all` filters raw interface dicts by `policyType` against the NX-OS-only
`LoopbackPolicyTypeEnum` set *before* any model is constructed, so the strict `Literal["nx-os"]` cannot be tripped by
foreign (e.g. future IOS-XE) interfaces on the read path. ND always returns `networkOSType` on GET, so `from_response`
is unaffected by the removed default.

## Scope

`nd_interface_loopback` only — this branch is the pilot. Other interface modules keep their hardcoded
`network_os_type` until the pattern is adopted.

## Future work (out of scope here)

Make `network_os_type` optional: when the user sets it, read it from the argspec (current behavior); when omitted,
derive it per switch via `FabricContext.get_platform_type()` (PR #404), mapping the switches-inventory `platformType`
onto the interface API's `networkOSType` values. The mandatory-parameter phase keeps pre-controller validation intact
and removes any dependency on #404's merge timing.
