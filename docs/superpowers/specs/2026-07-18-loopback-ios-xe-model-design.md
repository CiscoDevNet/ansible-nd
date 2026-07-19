# Design: IOS-XE Loopback Model for `nd_interface_loopback`

Date: 2026-07-18
Branch: `nd_interface_loopback_policy_type_union` (draft PR #403)
Builds on: `2026-07-14-loopback-policy-type-union-design.md`, `2026-07-16-loopback-network-os-type-required-design.md`

## Goal

Add IOS-XE loopback support to the policy_type-union POC so `network_os_type` becomes a *real* model discriminator, not a single-value gate.
This supersedes the 2026-07-16 "minimal gate, no outer union" YAGNI call: with a second OS, the outer union restructure of the network-OS
container is now meaningful. Scope decisions (confirmed with Allen, 2026-07-17/18):

- **All 6 real XE templates** are modeled (`userDefined` stays excluded, matching NX-OS).
- **Lab verification is in scope** — an IOS-XE device is available; the `csrLoopback`/`csrIntLoopback` drift and XE read-path injected keys
  get verified against the wire before the read handling is finalized.
- **Units + integration tasks** — full unit coverage with lab-derived fixtures, plus new integration tasks targeting the lab XE switch.

## Source data: ND 4.2.1 OpenAPI XE loopback surface

From `createInterfaceLoopbackManagedXe` (create) and `interfaceLoopbackManagedXe*` (read), `manage.json`:

| policyType (create) | Template | Fields beyond `adminState` |
| --- | --- | --- |
| `iosXeLoopback` | `ios_xe_int_loopback` | `description` (1-200), `extraConfig`, `ip` (ipv4), `vrfInterface` (1-32) |
| `iosXeLoopbackShutNoshut` | `ios_xe_int_loopback_admin_state` | — (adminState only) |
| `iosXeUnderlayLoopback` | `ios_xe_int_underlay_loopback` | `description` (1-**254**), `extraConfig`, `ip` (ipv4), `secondaryIp` (string) |
| `iosXeInternalLoopback` | `ios_xe_int_loopback_internal` | `description` (1-200), `enablePim` (bool), `extraConfig`, `ip` (**unvalidated string**), `ipv6` (string), `vrfInterface` (1-32) |
| `csrLoopback` | `csr_int_loopback` | `description` (1-254), `extraConfig`, `ip` (ipv4), `vrfInterface` (1-32) |
| `csr1kvLoopback` | `csr1kv_loopback` | `extraConfig` only |

**Spec drift — csr naming.** The create-side discriminator enum and the `userDefined` branch say `csrLoopback`; the read-side enum and the
per-branch `policyType` enums inside the create schema say `csrIntLoopback`; the create discriminator maps `csrLoopback` →
`csrIntLoopbackTemplate`. Working assumption (to lab-verify): create accepts `csrLoopback`, GET echoes `csrIntLoopback`. Vault note +
`TODO(4.2.1)` marker once verified.

## Section 1: Model layer (`models/interfaces/loopback_interface.py`)

### Base-class split

The read-tolerant `strip_none_valued_keys` validator and `extra="forbid"` currently live on `LoopbackPolicyBase` together with NX-common
fields (`ip`, `description` 1-254, `extra_config`). XE branches cannot inherit those fields: `iosXeLoopbackShutNoshut` is adminState-only,
`csr1kvLoopback` has no `ip`/`description`, and three XE branches cap `description` at 200. Under write-strict `forbid`, an inherited field a
template lacks would be silently accepted and sent on the wire — exactly the config-hygiene hole `forbid` exists to close. So:

- **`LoopbackPolicyStrictBase`** (new): `extra="forbid"` + the strip-none / read-tolerant before-validator + `admin_state`
  (the only field common to all 9 branches). Nothing else.
- **`LoopbackPolicyBase`** (existing, NX): now subclasses `LoopbackPolicyStrictBase`; keeps `ip` / `description(1-254)` / `extra_config`.
  The three NX branch models (`LoopbackPolicyModel`, `IpfmLoopbackPolicyModel`, `MplsLoopbackPolicyModel`) are untouched.
- **Six new XE branch models** subclass `LoopbackPolicyStrictBase` directly, each declaring exactly its template's fields per the table above:
  - `XeLoopbackPolicyModel` — `policy_type: Literal["iosXeLoopback"]`, `description` (1-200), `extra_config`, `ip: IPv4Host`, `vrf` (1-32)
  - `XeLoopbackShutNoshutPolicyModel` — `policy_type: Literal["iosXeLoopbackShutNoshut"]` (admin_state only)
  - `XeUnderlayLoopbackPolicyModel` — `policy_type: Literal["iosXeUnderlayLoopback"]`, `description` (1-254), `extra_config`,
    `ip: IPv4Host`, `secondary_ip: str | None` (alias `secondaryIp`)
  - `XeInternalLoopbackPolicyModel` — `policy_type: Literal["iosXeInternalLoopback"]`, `description` (1-200), `enable_pim: bool | None`
    (alias `enablePim`), `extra_config`, `ip: str | None` and `ipv6: str | None` (plain strings — the schema deliberately leaves them
    unvalidated for this template; documented in the field descriptions)
  - `CsrLoopbackPolicyModel` — `policy_type: Literal["csrLoopback", "csrIntLoopback"]`, `description` (1-254), `extra_config`,
    `ip: IPv4Host`, `vrf` (1-32). A before-validator normalizes the read-side `csrIntLoopback` to the create-side `csrLoopback` so
    payloads and idempotency comparison always use the create name (multi-value `Literal` is legal in a discriminated union as long as
    values are unique across branches). `TODO(4.2.1)` marker at the normalization site once lab-verified.
  - `Csr1kvLoopbackPolicyModel` — `policy_type: Literal["csr1kvLoopback"]`, `extra_config` only.
- `ip` uses `IPv4Host` (bare-host normalization, same as the NX fix for issue #401) wherever the schema says `format: ipv4`.

### Outer union (the approved restructure)

`LoopbackNetworkOSModel` splits into two OS-specific models; `config_data.network_os` becomes a discriminated union on `network_os_type`:

```python
class NexusLoopbackNetworkOSModel(NDNestedModel):
    network_os_type: Literal["nx-os"] = Field(alias="networkOSType", ...)
    policy: LoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel | None = Field(
        default=None, alias="policy", discriminator="policy_type")

class XeLoopbackNetworkOSModel(NDNestedModel):
    network_os_type: Literal["ios-xe"] = Field(alias="networkOSType", ...)
    policy: (XeLoopbackPolicyModel | XeLoopbackShutNoshutPolicyModel | XeUnderlayLoopbackPolicyModel
             | XeInternalLoopbackPolicyModel | CsrLoopbackPolicyModel | Csr1kvLoopbackPolicyModel | None) = Field(
        default=None, alias="policy", discriminator="policy_type")

class LoopbackConfigDataModel(NDNestedModel):
    mode: Literal["managed"] = Field(default="managed", alias="mode", frozen=True)
    network_os: NexusLoopbackNetworkOSModel | XeLoopbackNetworkOSModel = Field(alias="networkOS", discriminator="network_os_type")
```

Cross-OS mismatches (`network_os_type: nx-os` + `policy_type: iosXeLoopback`) fail structurally with a Pydantic discriminated-union error —
no hand-written cross-check table. Neither OS model is frozen (same `merge()` rationale as the 2026-07-16 spec).

## Section 2: Enums + orchestrator

- `LoopbackPolicyTypeEnum` (NX) stays as-is. New `XeLoopbackPolicyTypeEnum` with the six create-side names **plus**
  `CSR_INT_LOOPBACK = "csrIntLoopback"` as an explicitly-commented read-side alias (the `query_all` filter sees read names).
- `query_all`'s managed set becomes the union of both enums' values. No per-OS split: the two OSes' policy-type names are fully disjoint,
  so a single combined set keeps the single-pass filter. `userDefined` and system-provisioned types stay excluded;
  `iosXeUnderlayLoopback` is *included* (unlike NX `underlayLoopback`) because it appears in the XE create-side enum, i.e. user-creatable.
- No orchestrator CRUD changes: payload shape, `switchId` injection, and deploy/remove batching are OS-agnostic.

## Section 3: Module surface (`plugins/modules/nd_interface_loopback.py`)

- Argspec: `network_os_type` choices become `["nx-os", "ios-xe"]`; `policy_type` choices grow to the nine create-side names
  (`csrLoopback`, not `csrIntLoopback`). Two new flat options: `secondary_ip` (str), `enable_pim` (bool). All other XE fields reuse
  existing options (`ip`, `description`, `vrf`, `extra_config`, `ipv6`, `admin_state`). Per-branch constraints (description length,
  which options a branch accepts) stay model-side, where `forbid` enforces them.
- DOCUMENTATION: per-option notes on which `policy_type` values accept it; `network_os_type` description updated.
- EXAMPLES: add `ios-xe` examples covering **every supported state** — `merged`, `replaced`, `overridden`, and `deleted` — per
  mikewiebe's standing review guidance that module EXAMPLES must include all ansible states. Use `iosXeLoopback` for the full
  state set, plus one `merged` example showing a CSR branch (`csrLoopback`). The existing NX-OS examples already cover all states;
  keep that structure and mirror it for `ios-xe`.

## Section 4: Lab verification (before finalizing read handling)

Using the intent-only raw-REST technique (raw POST = intent-only, no deploy — see the `nd-live-lab-and-raw-rest-probing` memory) against
the lab XE device:

1. Create `iosXeLoopback` and `csrLoopback` loopbacks (raw POST, intent only).
2. GET them back; record (a) the echoed `policyType` for the CSR branch (expected `csrIntLoopback`), (b) any ND-injected keys not in the
   read schema (the XE analogue of NX's `linkStateRoutingTag`) — these must survive the read-tolerant path.
3. Write the vault note for the csr drift (stable `id` → the `TODO(4.2.1)` slug), plus notes for any new injected-key discrepancies.
4. Delete the probe interfaces (intent removal, nothing was deployed).

If the wire contradicts the working assumption (e.g. GET echoes `csrLoopback`), simplify `CsrLoopbackPolicyModel` to a single-value
`Literal` and drop the normalization.

## Section 5: Testing

- **Unit tests**: per-XE-branch validation tests (accept template fields, reject wrong-branch fields under `forbid`, description length
  bounds, `IPv4Host` normalization); outer-union tests (cross-OS mismatch rejected, correct OS model selected); csr normalization
  (`csrIntLoopback` read → `csrLoopback` model, payload emits `csrLoopback`); read-tolerant path with lab-captured injected keys;
  `query_all` filtering including XE read names. Fixtures follow the existing key convention, derived from real lab GETs where possible.
- **Integration**: new XE task block(s) in the existing `nd_interface_loopback` integration target, gated on XE switch vars
  (switch IP supplied via integration vars like the NX tasks); exercises all four states — merged/replaced/overridden/deleted — plus
  idempotency for `iosXeLoopback`, and merged/deleted for the csr branch (the drift case). The `overridden` tasks deliberately mix
  NX-OS and XE managed loopbacks in one fabric to prove cross-OS convergence in `query_all`.
- All unit tests + linters green via the `nd-dev` wrappers before pushing; integration run against the lab.

## Out of scope

- `userDefined` policy type (both OSes) — unchanged.
- Auto-deriving `network_os_type` from the switch (`FabricContext.get_platform_type()`) — still the planned follow-up; the parameter
  stays required user input.
- Other interface families' XE templates.
