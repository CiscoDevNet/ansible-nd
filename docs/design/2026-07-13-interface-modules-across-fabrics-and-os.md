# Interface modules across fabric types and switch OSes

_What we found looking at ECL, Campus, and IOS-XE — and where it leaves module granularity._

Allen Robel · July 2026

> Converted from `2026-07-13-interface-modules-across-fabrics-and-os.pptx`. Context for the
> `nd_interface_loopback` pilot: consolidating loopback into one module with a typed `policy_type`
> union and deriving `networkOSType` from the switch to support IOS-XE. See especially the sections on
> the four-level API tree, loopback drift, the proposed boundary, machinery status, and spec inconsistencies.

## Where this came from

**Matt asked:** How do we handle interfaces across DC fabrics, Campus, and ECL — and across device types (NX-OS, IOS-XE)? What does that look like for modules?

**Mike's framing:** And it was the right one: "how we carve up the functionality" is a different discussion
from "what actually differs across fabric types." Complete picture first.

**So that's what I did:** Walked the full ND 4.2.1 interface tree — every family, mode, switch OS, template — and measured our code and dcnm_interface line by line.

> Short version: the June deck's answer doesn't hold up once you look past loopback. Here's the fuller picture.

## Two questions, two different answers

They aren't the same kind of question — ND's API only has one of the two axes.

| Question | What the API says |
| --- | --- |
| 1. One module per template across fabric types (VXLAN / ECL / Campus)? | It's not an axis. Fabric type appears nowhere in the interface API. |
| 2. One module per template across switch OSes (NX-OS / IOS-XE)? | It is an axis — but it sits above the template. Derive it from the switch. |

**Where that lands us:** One module per (interfaceType × mode). Inside it, `policy_type` is a typed union and `networkOSType` is auto-derived from the switch.

**Roughly 27 modules. Not ~74 (strict one-per-template). Not 1 (dcnm-style).**

## Fabric type isn't in the interface API at all

This was the surprise, and it settles a good chunk of the question.

**17 fabric types exist:** `fabricTypeEnum`: vxlanIbgp, vxlanEbgp, vxlanCampus, classicLan,
classicLanEnhanced (ECL), ipfm, externalConnectivity, dataBroker, aci, …

**It discriminates on none:** No fabric-type field in the POST body. None in the GET response — not even
in `operData`. All 10 `interfaceActions/*` are scoped by `{fabricName}` in the path only.

**What it does discriminate on:** A four-level tree — and fabric type simply isn't a level in it.

```text
interfaceType
  → mode
    → networkOSType
      → policyType
```

> nd_interface_loopback already works in ECL, Campus, and VXLAN today — wherever the loopback template is legal.

## "Support ECL" is a coverage question

Not a parameter question. ECL leans on template families we don't ship yet.

| ECL needs | Templates | Shipped? |
| --- | --- | --- |
| FEX | fexPo, aaFexPo, fexPoInternal | No |
| Private VLAN | pvlanHost, pvlanVpcHost, pvlanPoHost | No |
| Dot1q tunnel | dot1qTunnelHost, dot1qTunnelVpc | No |
| First-hop redundancy | hsrpSvi, vrrp* SVIs | No |
| VRF-Lite | VRF-Lite subinterfaces | No |

> Fabric type decides which templates are legal — ND only tells us at runtime (HTTP 400, or capableSwitches).

## Switch OS is a real axis — and disjoint

In every family, NX-OS and IOS-XE share exactly one policyType: `userDefined`, the untyped escape hatch.

| Family | NX-OS (read/create) | IOS-XE (read/create) | Real shared |
| --- | --- | --- | --- |
| Ethernet | 43 / 15 | 16 / 10 | 0 |
| PortChannel | 23 / 11 | 5 / 5 | 0 |
| VPC | 11 / 7 | 0 / 0 | NX-OS only |
| Loopback | 9 / 3 | 7 / 7 | 0 |
| SVI | 11 / 7 | 3 / 3 | 0 |
| SubInterface | 6 / 4 | 4 / 4 | 0 |
| Tunnel | 0 / 0 | 5 / 4 | IOS-XE only |
| NVE | 2 / 2 | 3 / 3 | 0 |
| Management | 2 / 2 | 2 / 2 | 0 |

> Whole families are OS-exclusive: vPC and FEX don't exist on IOS-XE. Tunnel doesn't exist on NX-OS.

## Even the closest analogues drift

`loopback` (NX-OS) vs `iosXeLoopback` (IOS-XE) — the most similar pair in the whole surface.

|  | NX-OS | IOS-XE |
| --- | --- | --- |
| Shared fields | adminState, description, extraConfig, ip, vrfInterface | the same 5 |
| NX-OS only | ipv6, routeMapTag | — |
| description maxLength | 254 | 200 |
| ip validation | format: ipv4 | ipv4 — except iosXeInternalLoopback, an unvalidated string |
| Route-tag concept | 4 spellings, 2 types (routeMapTag int, tag int, routingTag str, dciRoutingTag) | doesn't exist |

Field names across all loopback templates: NX-OS 23 · IOS-XE 8 · overlap 7. OSPF auth, MPLS/DCI, IPFM, multisite, phantom-RP — all absent from XE.

> A module can't conditionally have a vPC. But users also shouldn't have to declare their OS.

## The number that moved me off the June position

**The full surface:** 75 user-creatable policyTypes across 92 creatable (family × OS × template) combinations. 139 readable, 159 read combinations.

**Strict per-template ⇒ ~74 modules:** At our measured ~1,150 lines per template, that's ~85,000 lines. That's more than we want to own.

**And it breaks on its own terms:** The IPFM variant is a sibling of the plain template in the same cell — and that repeats in every family.

```text
createInterfaceLoopbackManagedNexusSubType = [loopback, ipfmLoopback, userDefined]
createInterfaceEthernetAccessNexusSubType  = [accessHost, ipfmAccessHost, userDefined]
```

Taken strictly, we'd ship nd_interface_svi_ipfm, nd_interface_ethernet_access_ipfm, and so on.

> IPFM on its own would roughly double the module count. That's where the June recommendation stops making sense.

## The duplication concern is real — and fixable

The honest measurement, and it doesn't flatter us.

|  | LOC | User-facing surfaces | LOC per surface |
| --- | --- | --- | --- |
| nd_interface_* (10 modules + 10 models + 10 orchestrators) | 11,213 | 10 templates | ~1,120 |
| cisco.dcnm dcnm_interface (one file) | 7,034 (5,195 logic) | 9 types / 46 templates | ~280 |

We're ~4× more expensive per template. I under-sold that in June. But 65% of our per-template cost is boilerplate:

- **~108 lines of main()** — byte-identical across 8 of 10 modules but for three tokens
- **~90 lines of argspec shell** — re-declared by hand — 752 lines family-wide
- **~300–500 lines of DOCUMENTATION** — written from scratch each time; no doc fragment for the config tree

> Every one of those lines can go away with a doc fragment and a generated argspec — without merging a single module.

## What the fully-consolidated shape costs

dcnm_interface is the consolidated design, already built — a useful thing to learn from.

- **Hand-rolled dispatch:** 13 per-type validators and 15 per-type arg specs, behind a type-keyed dispatch chain.
- **Conditional docs:** 954 lines of DOCUMENTATION — fields needing "…only when type is X."
- **No typed model layer:** Validation is hand-rolled per type. No Pydantic contract to lean on. And no OS concept at all — NX-OS only; networkOSType never appears.

> Scaled to 4 OSes and 92 combinations, most of that cost comes back — in one file, without the types.

## Where I'd land: cut at (interfaceType × mode)

- **policy_type:** Explicit and typed, backed by a Pydantic discriminated union — each template's fields validated on their own branch.
- **networkOSType:** Derived from the switch, never user-facing. Picks loopback vs iosXeLoopback for us.
- **fabric type:** Not a parameter. Runtime-gated by the capableSwitches preflight we already have.
- **~27 modules:** Ethernet 7 modes · PortChannel 7 · VPC 6 · SubInterface 2 · Loopback/SVI/NVE/Mgmt/Tunnel 1 each
- **8 of 10 unchanged:** (ethernet, access) already IS this boundary — we just hadn't named it
- **Loopback becomes one module:** policy_type: loopback | ipfm | mpls — essentially what Mike was pushing for

> And IOS-XE arrives with no new modules — same nd_interface_loopback; we resolve the OS from the switch.

## Most of the machinery is already there

Already in place:

- **Set-based dispatch ✓** — Orchestrators already dispatch on `_managed_policy_types() -> set[str]`, consumed by query_all in all three
  type bases. Singleton today only because every enum has one member.
- **Discriminated unions ✓** — `Field(discriminator=…)` is shipped and proven — `manage_vpc_pair/vpc_pair_model.py:79`.
- **Fabric type already fetched ✓** — FabricContext already pulls the fabric summary carrying type — and discards it. Awareness would cost zero extra API calls.

The genuinely new work:

- **Multi-member enums** — policyType enums need more than one member, and a union-typed policy field in the interface models.
- **Suboption argspec** — An argspec that can express per-policyType suboptions.
- **Unfreeze network_os_type** — Today `Literal["nx-os"]`, `frozen=True` in all 10 models — IOS-XE isn't representable at all right now.

## What I'd like us to decide

1. **The boundary** — One module per (interfaceType × mode); policy_type a typed union; OS derived; fabric type not a parameter. A change from my June deck.
2. **Kill the boilerplate first** — Doc fragment for the interface config tree + argspec generated from the Pydantic models. ~750 lines
   per template. Best return on the board.
3. **Consolidate loopback** — One module with policy_type, absorbing mplsLoopback / ipfmLoopback. A good pilot for the union pattern.
4. **Unfreeze networkOSType** — Derive it from the switch. Also pilot on loopback — XE loopback is nearly a strict subset, so it's the cheapest first case.
5. **Treat ECL as coverage** — It needs fex*, pvlan*, dot1qTunnel*, hsrpSvi/vrrp*, VRF-Lite — and we ship none. Worth deciding what we fund.
6. **Budget for spec drift** — The OpenAPI isn't self-consistent. Six inconsistencies found in a single walk — see next section.

Happy to walk through any of these on Webex.

## One caution — the spec isn't self-consistent

All found in a single walk of the tree.

- **csrLoopback vs csrIntLoopback:** The XE read enum and its own discriminator mapping disagree; neither side has both.
- **csrNve vs csrIntNve:** The same defect again, in the NVE family.
- **accessHost missing:** Absent from interfaceEthernetAccessNexusSubType — the very enum whose mapping defines it.
- **"freefrom":** A policyType literally misspelled in the spec.
- **ethernet missing:** Absent from the read-side interfaceSubType enum, though the family exists.
- **mplsLoopback undocumented:** Lab-verified creatable, but not listed in loopback's create discriminator.

> Model against the templates and the wire, not the oneOf mappings. Every typed model doubles as a spec-conformance test.

## Bottom line

Mike was right to re-open this, and the June answer was too simple.

- **Fabric type:** Not an axis, not a parameter. ECL is a coverage question — and today the answer is that we ship none of its templates.
- **Switch OS:** A real axis, but it sits above the template. Derive it from the switch rather than forking modules or pushing it onto users.
- **Templates:** They belong inside the module as a typed union. Not separate modules, not an untyped free-for-all.

> Cut at (interfaceType × mode). ~27 modules. Eight of ten unchanged. Loopback consolidates. IOS-XE comes along for free.
