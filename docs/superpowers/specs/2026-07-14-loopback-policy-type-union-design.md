# nd_interface_loopback — policy_type discriminated union

Design spec · Allen Robel · 2026-07-14

Pilot for the "one module per (interfaceType × mode)" boundary from
`docs/design/2026-07-13-interface-modules-across-fabrics-and-os.md`. Consolidates the loopback
policy templates into a single `nd_interface_loopback` module behind a typed `policy_type`
discriminated union.

## Scope

**In scope (this session):** the `policy_type` discriminated union over the three NX-OS managed
loopback templates — `loopback`, `ipfmLoopback`, `mplsLoopback` — with strict per-branch field
validation, plus the set-based `query_all` filtering that lets one module own all three.

**Out of scope (explicit follow-ups):**

- Unfreezing `network_os_type` for IOS-XE (`iosXeLoopback`). Blocked on `FabricContext` exposing the
  switch OS, which is not yet shipped. `network_os_type` stays `Literal["nx-os"], frozen=True`.
- The `userDefined` untyped escape-hatch policy type.
- Generated argspec + interface `config` doc fragment (decision 2 of the granularity doc). This spec
  uses a hand-rolled flat argspec.
- Strict rejection wired through a generated per-`policy_type` suboption argspec — achieved here more
  simply via `extra="forbid"` + `None`-stripping (see below).

## Key decisions

1. **No backward compatibility.** These interface modules are unreleased, so `policy_type` is a
   **required field with no default**. Users must state the template explicitly. This lets the
   discriminated union hard-fail natively when the discriminator is absent — no defaulting validator.
2. **Strict per-branch validation.** Each branch model sets `extra="forbid"`. A field that belongs to a
   different template (e.g. `dci_routing_tag` under `policy_type: loopback`) is a hard failure, not a
   silent drop. Rationale: if a user names a `policy_type`, they are expected to have read the docs;
   rejecting stray fields keeps their source-of-truth config clean.
3. **Shared base + three subclasses** for the branch models (chosen over three independent flat models):
   DRYs the shared fields while keeping each branch independently readable, and survives the later
   IOS-XE extension via a per-branch field override (e.g. `description` maxLength 200 on XE) rather than
   forcing a flat rewrite.

## Field sets (from ND 4.2.1 templates)

Sourced from `intLoopbackTemplate`, `intIpfmLoopbackTemplate`, `intMplsLoopbackTemplate`
(`nd-openapi`, `manage.json`). All three are NX-OS; `description` is uniformly minLength 1 / maxLength
254 across them (the 200 divergence is IOS-XE only, out of scope).

| Field | `loopback` | `ipfmLoopback` | `mplsLoopback` |
| --- | --- | --- | --- |
| `admin_state` (`adminState`, bool) | ✓ | ✓ | ✓ |
| `description` (`description`, str 1–254) | ✓ | ✓ | ✓ |
| `extra_config` (`extraConfig`, str) | ✓ | ✓ | ✓ |
| `ip` (`ip`, ipv4) | ✓ | ✓ | ✓ |
| `vrf` (`vrfInterface`, str 1–32) | ✓ | ✓ | — |
| `ipv6` (`ipv6`, ipv6) | ✓ | — | — |
| `route_map_tag` (`routeMapTag`, str¹) | ✓ | — | — |
| `advertise_loopback` (`advertiseLoopback`, bool) | — | ✓ | — |
| `is_service_reflect` (`isServiceReflect`, bool) | — | ✓ | — |
| `routing_tag` (`routingTag`, str) | — | ✓ | — |
| `secondary_ip_list` (`secondaryIpList`, list of `{ip, prefix}`) | — | ✓ | — |
| `dci_routing_protocol` (`dciRoutingProtocol`, enum ospf/isis) | — | — | ✓ |
| `dci_routing_tag` (`dciRoutingTag`, str) | — | — | ✓ |
| `ospf_area_id` (`ospfAreaId`, str 1–15) | — | — | ✓ |

Shared core = `{admin_state, description, extra_config, ip}`.

¹ `route_map_tag` retains the existing `coerce_route_map_tag` validator: ND 4.2.1 returns it as an
integer though the template types it as a string (`TODO(4.2.1)` GET-side type drift, already in code).

The three route-tag concepts (`routeMapTag` / `routingTag` / `dciRoutingTag`) are genuinely distinct
fields per template, not aliases — they cannot collapse into one.

### Spec-drift note

`mplsLoopback` is **absent from the create-side enum** `createInterfaceLoopbackManagedNexusSubType`
(`[loopback, ipfmLoopback, userDefined]`) but present on the read side and lab-verified creatable. We
model it per the granularity doc's guidance: model against the templates and the wire, not the `oneOf`
mappings.

## Component design

### 1. Enum — `plugins/module_utils/models/interfaces/enums.py`

```python
class LoopbackPolicyTypeEnum(str, Enum):
    LOOPBACK = "loopback"
    IPFM_LOOPBACK = "ipfmLoopback"
    MPLS_LOOPBACK = "mplsLoopback"
```

The multi-member policyType enum the granularity doc calls for. `userDefined` intentionally excluded.

### 2. Models — `plugins/module_utils/models/interfaces/loopback_interface.py`

- `LoopbackPolicyBase(NDNestedModel)` — shared core fields `admin_state`, `ip`, `description`,
  `extra_config`. Sets `model_config = ConfigDict(extra="forbid")` (merges down the MRO, overriding the
  inherited `extra="ignore"`). Carries a `mode="before"` model validator that strips `None`-valued keys
  from the incoming dict so unset flat-argspec options do not trip `forbid`.
- `LoopbackPolicyModel(LoopbackPolicyBase)` — `policy_type: Literal["loopback"]` (required, no default),
  adding `ipv6`, `route_map_tag`, `vrf`; keeps `coerce_route_map_tag`.
- `IpfmLoopbackPolicyModel(LoopbackPolicyBase)` — `policy_type: Literal["ipfmLoopback"]`, adding `vrf`,
  `advertise_loopback`, `is_service_reflect`, `routing_tag`, `secondary_ip_list`
  (nested `SecondaryIpModel` = `{ip: ipv4, prefix: int 4–32}`).
- `MplsLoopbackPolicyModel(LoopbackPolicyBase)` — `policy_type: Literal["mplsLoopback"]`, adding
  `dci_routing_protocol` (enum), `dci_routing_tag`, `ospf_area_id`.
- `LoopbackNetworkOSModel.policy` becomes the discriminated union:

  ```python
  policy: LoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel | None = Field(
      default=None, alias="policy", discriminator="policy_type"
  )
  ```

`network_os_type` unchanged (`Literal["nx-os"], frozen=True`).

Because `policy_type` is required with no default, the discriminator resolves off explicit user input on
the create side and off ND's `policyType` on the read side; an absent discriminator is a hard failure.

### 3. Orchestrator — `plugins/module_utils/orchestrators/loopback_interface.py`

`query_all`'s hardcoded `policyType == "loopback"` filter becomes set-based (matching the
svi/subinterface pattern):

```python
managed_policy_types = {e.value for e in LoopbackPolicyTypeEnum}
managed = [
    lb for lb in loopbacks
    if lb.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_policy_types
]
```

Docstrings updated: the current text stating `ipfmLoopback` / `userDefined` "will be managed by
dedicated modules" is corrected — ipfm and mpls are now owned here; only `userDefined` and
system-provisioned policy types (`underlayLoopback`, etc.) remain excluded.

### 4. Argspec — `get_argument_spec()` in the model

Flat union of all branch fields under `policy`, with `policy_type` required:

```python
policy=dict(
    type="dict",
    options=dict(
        policy_type=dict(type="str", required=True,
                         choices=["loopback", "ipfmLoopback", "mplsLoopback"]),
        # shared
        admin_state=dict(type="bool"), ip=dict(type="str"),
        description=dict(type="str"), extra_config=dict(type="str"),
        # loopback
        ipv6=dict(type="str"), route_map_tag=dict(type="str"), vrf=dict(type="str"),
        # ipfm
        advertise_loopback=dict(type="bool"), is_service_reflect=dict(type="bool"),
        routing_tag=dict(type="str"),
        secondary_ip_list=dict(type="list", elements="dict", options=dict(
            ip=dict(type="str"), prefix=dict(type="int"))),
        # mpls
        dci_routing_protocol=dict(type="str", choices=["ospf", "isis"]),
        dci_routing_tag=dict(type="str"), ospf_area_id=dict(type="str"),
    ),
)
```

`vrf` appears once (shared by loopback + ipfm). Wrong-branch fields left unset arrive as `None` and are
stripped before validation; wrong-branch fields set to a real value are rejected by `extra="forbid"`.

### 5. Module — `plugins/modules/nd_interface_loopback.py`

No orchestration/logic change. DOCUMENTATION/EXAMPLES updated to describe `policy_type` and the
per-template fields (fuller docs arrive with the doc-fragment work, decision 2).

### 6. Tests

- **Model unit tests** (`tests/unit/module_utils/models/test_loopback_interface.py`): each `policy_type`
  parses to the correct branch type; `to_payload()` / `from_response()` round-trips per branch; a
  wrong-branch field set to a real value raises (strict `forbid`); unset wrong-branch fields (`None`) are
  accepted; missing `policy_type` raises.
- **Orchestrator unit test** (`tests/unit/module_utils/orchestrators/test_loopback_interface.py`):
  `query_all` returns interfaces of all three managed policy types and still excludes `userDefined` /
  system-provisioned ones. New fixture keys per existing conventions.

## Data flow

Create/update: playbook `config[]` → module argspec (flat `policy`, required `policy_type`) →
`LoopbackInterfaceModel` → `LoopbackNetworkOSModel` before-validator strips `None` → discriminator
selects branch → branch validates with `extra="forbid"` → `to_payload()` (`exclude_none=True`,
`by_alias=True`) → orchestrator injects `switchId`, wraps in `interfaces[]` → POST/PUT → queued deploy.

Read: ND GET → `query_all` set-filters on `policyType` → each dict enriched with `switchIp` →
`from_response()` → discriminator selects branch off ND's `policyType`.

## Risks / notes

- **Flat argspec vs `forbid`** depends on the `None`-stripping before-validator. If that validator is
  wrong, unset options would spuriously fail. Covered by the "unset wrong-branch fields accepted" test.
- **`secondary_ip_list`** is the only nested structure; kept minimal (`{ip, prefix}`) and fully modeled
  so the ipfm branch does not falsely reject a valid field under `forbid`.
- **`mplsLoopback` creatability** rests on lab verification, not the OpenAPI create enum. Integration
  coverage against a live fabric is the real confirmation; unit tests assert the model/round-trip only.
