# Loopback policy_type Discriminated Union — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan
task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate the `nd_interface_loopback` module to own three NX-OS loopback templates (`loopback`, `ipfmLoopback`, `mplsLoopback`) behind a typed
`policy_type` Pydantic discriminated union with strict per-branch validation.

**Architecture:** A shared `LoopbackPolicyBase` holds the four common fields; three subclasses each add a `policy_type` `Literal` discriminator plus their
template-specific fields. `LoopbackNetworkOSModel.policy` becomes a discriminated union keyed on `policy_type`. Branch models set `extra="forbid"` plus a
`None`-stripping before-validator so unset flat-argspec options are dropped while explicitly-set wrong-branch fields hard-fail. `query_all` filtering moves
from a hardcoded string to a set built from a new `LoopbackPolicyTypeEnum`.

**Tech Stack:** Python 3.10+, Pydantic v2 (via `common/pydantic_compat`), Ansible module argspec, pytest. Tests/lint run inside the `nd-dev` container via
`ndpytest` / `ndblack` / `ndisort` / `ndpylint` / `ndmypy`.

## Global Constraints

- Line length: **159** (black, isort, pylint all configured in `pyproject.toml`).
- Modern type annotations only: `X | None`, `list[X]`, `dict[K, V]` — no `Optional`/`List`/`Dict`.
- All Pydantic imports go through `plugins/module_utils/common/pydantic_compat` (never import `pydantic` directly in `plugins/`), which exports `BaseModel`,
  `ConfigDict`, `Field`, `field_validator`, `model_validator`.
- Class/method docstrings MUST have a `# Summary` and a `## Raises` section (`None` if it does not raise); Markdown formatting, single backticks for code refs.
- `network_os_type` stays `Literal["nx-os"], frozen=True` — IOS-XE is out of scope.
- Unit tests run with `ndpytest <path>` (the wrapper sets `PYTHONPATH` and pydantic inject; no manual `source env`).
- Enum member values MUST match the ND API strings exactly (`loopback`, `ipfmLoopback`, `mplsLoopback`).
- Spec of record: `docs/superpowers/specs/2026-07-14-loopback-policy-type-union-design.md`.

---

## File Structure

- **Modify** `plugins/module_utils/models/interfaces/enums.py` — add `LoopbackPolicyTypeEnum`.
- **Modify** `plugins/module_utils/models/interfaces/loopback_interface.py` — add `LoopbackPolicyBase`, refactor `LoopbackPolicyModel`, add
  `IpfmLoopbackPolicyModel` + `SecondaryIpModel` + `MplsLoopbackPolicyModel`, convert `LoopbackNetworkOSModel.policy` to a discriminated union, extend
  `get_argument_spec()`.
- **Modify** `plugins/module_utils/orchestrators/loopback_interface.py` — set-based `query_all` filter + docstring corrections.
- **Modify** `plugins/modules/nd_interface_loopback.py` — DOCUMENTATION/EXAMPLES for `policy_type` and the new fields.
- **Modify** `tests/unit/module_utils/models/test_loopback_interface.py` — branch + union + strict-rejection tests.
- **Modify** `tests/unit/module_utils/orchestrators/test_loopback_interface.py` — multi-policy-type `query_all` test.
- **Modify** `tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json` — fixture for the new orchestrator test.
- **Modify** 4 integration files under `tests/integration/targets/nd_interface_loopback/` — add `policy_type: loopback`.

---

## Task 1: Add `LoopbackPolicyTypeEnum`

**Files:**

- Modify: `plugins/module_utils/models/interfaces/enums.py`
- Test: `tests/unit/module_utils/models/test_loopback_interface.py`

**Interfaces:**

- Produces: `LoopbackPolicyTypeEnum(str, Enum)` with members `LOOPBACK="loopback"`, `IPFM_LOOPBACK="ipfmLoopback"`, `MPLS_LOOPBACK="mplsLoopback"`. Consumed by
  Task 7 (`query_all`).

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/module_utils/models/test_loopback_interface.py` (extend the existing import from `...interfaces.enums` or add one):

```python
def test_loopback_policy_type_enum_members():
    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import LoopbackPolicyTypeEnum

    assert {e.value for e in LoopbackPolicyTypeEnum} == {"loopback", "ipfmLoopback", "mplsLoopback"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_loopback_policy_type_enum_members -v`
Expected: FAIL with `ImportError` / `cannot import name 'LoopbackPolicyTypeEnum'`.

- [ ] **Step 3: Add the enum**

Append to `plugins/module_utils/models/interfaces/enums.py`:

```python
class LoopbackPolicyTypeEnum(str, Enum):
    """
    # Summary

    Managed NX-OS loopback policy types owned by the `nd_interface_loopback` module. `userDefined` is intentionally excluded.
    """

    LOOPBACK = "loopback"
    IPFM_LOOPBACK = "ipfmLoopback"
    MPLS_LOOPBACK = "mplsLoopback"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_loopback_policy_type_enum_members -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add plugins/module_utils/models/interfaces/enums.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Add LoopbackPolicyTypeEnum for loopback policy_type union"
```

---

## Task 2: `LoopbackPolicyBase` + refactor `LoopbackPolicyModel`

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py`
- Test: `tests/unit/module_utils/models/test_loopback_interface.py`

**Interfaces:**

- Produces: `LoopbackPolicyBase(NDNestedModel)` with shared fields `admin_state`, `ip`, `description`, `extra_config`, `model_config =
  ConfigDict(extra="forbid")`, and a `mode="before"` `_strip_none` validator. `LoopbackPolicyModel(LoopbackPolicyBase)` with **required** `policy_type:
  Literal["loopback"]` plus `ipv6`, `route_map_tag`, `vrf`.

- [ ] **Step 1: Write the failing tests**

Add to the model test file (`LoopbackPolicyModel` is already imported at the top of the file; no new import needed):

```python
def test_loopback_policy_strict_rejects_foreign_field():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LoopbackPolicyModel(policyType="loopback", dciRoutingTag="MPLS_UNDERLAY")


def test_loopback_policy_requires_policy_type():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LoopbackPolicyModel(ip="10.1.1.1/32")


def test_loopback_policy_strips_none_valued_keys():
    # Unset flat-argspec options arrive as None and must be dropped, not rejected by extra="forbid".
    model = LoopbackPolicyModel(policyType="loopback", ip="10.1.1.1/32", routeMapTag=None, ipv6=None)
    assert model.route_map_tag is None
    assert model.ipv6 is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_loopback_policy_strict_rejects_foreign_field
tests/unit/module_utils/models/test_loopback_interface.py::test_loopback_policy_requires_policy_type -v`
Expected: FAIL — foreign field currently ignored (no error), and `policy_type` currently has a default so no error.

- [ ] **Step 3: Add the base and refactor the loopback branch**

In `plugins/module_utils/models/interfaces/loopback_interface.py`, add `ConfigDict` and `model_validator` to the `pydantic_compat` import, then replace the
existing `LoopbackPolicyModel` class with:

```python
class LoopbackPolicyBase(NDNestedModel):
    """
    # Summary

    Shared policy fields common to every managed NX-OS loopback template. Sets `extra="forbid"` so fields belonging to a
    different `policy_type` are rejected, and strips `None`-valued keys first so unset flat-argspec options are not rejected.

    ## Raises

    None
    """

    model_config = ConfigDict(extra="forbid")

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")
    ip: IPv4CIDR = Field(default=None, alias="ip", description="Loopback IPv4 address in CIDR notation (e.g. 10.1.1.1/32)")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")

    @model_validator(mode="before")
    @classmethod
    def strip_none_valued_keys(cls, data):
        """
        # Summary

        Drop keys whose value is `None` before validation so unset flat-argspec options do not trip `extra="forbid"`.

        ## Raises

        None
        """
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if value is not None}
        return data


class LoopbackPolicyModel(LoopbackPolicyBase):
    """
    # Summary

    Policy fields for the NX-OS `loopback` template. Maps to `configData.networkOS.policy` where `policyType == "loopback"`.

    ## Raises

    None
    """

    policy_type: Literal["loopback"] = Field(alias="policyType", description="Loopback policy template discriminator")
    ipv6: IPv6CIDR = Field(default=None, alias="ipv6", description="Loopback IPv6 address in CIDR notation")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")
    route_map_tag: str | None = Field(default=None, alias="routeMapTag", description="Route-Map tag associated with interface IP")

    # TODO(4.2.1): Remove coerce_route_map_tag once GET-side type drift is fixed.
    # ND 4.2.1 returns `routeMapTag` as an integer even though the template defines it as a string.
    # The same drift affects SVI `routingTag` - keep both validators in sync.
    @field_validator("route_map_tag", mode="before")
    @classmethod
    def coerce_route_map_tag(cls, value):
        """
        # Summary

        Coerce `route_map_tag` to a string. The ND API returns this field as an integer, but the template defines it as a string.

        ## Raises

        None
        """
        if value is None:
            return value
        return str(value)
```

Update the module-header `## Model Hierarchy` docstring bullet for `policy` to note the union (`policy_type: loopback | ipfmLoopback | mplsLoopback`).

- [ ] **Step 4: Run the tests to verify they pass (including the full existing suite for regressions)**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -v`
Expected: PASS. If any pre-existing test fails because it constructs a loopback policy without `policy_type`, add `policyType="loopback"` (or `"policy_type":
"loopback"` in dict form) to that test's data — this is the intended required-field change.

- [ ] **Step 5: Lint**

Run: `ndblack plugins/module_utils/models/interfaces/loopback_interface.py && ndisort plugins/module_utils/models/interfaces/loopback_interface.py && ndpylint
plugins/module_utils/models/interfaces/loopback_interface.py && ndmypy plugins/module_utils/models/interfaces/loopback_interface.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Add LoopbackPolicyBase; make loopback policy_type required and strict"
```

---

## Task 3: `IpfmLoopbackPolicyModel` + `SecondaryIpModel`

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py`
- Test: `tests/unit/module_utils/models/test_loopback_interface.py`

**Interfaces:**

- Produces: `SecondaryIpModel(NDNestedModel)` (`ip: str | None`, `prefix: int | None`) and `IpfmLoopbackPolicyModel(LoopbackPolicyBase)` with required
  `policy_type: Literal["ipfmLoopback"]` plus `vrf`, `advertise_loopback`, `is_service_reflect`, `routing_tag`, `secondary_ip_list`.

- [ ] **Step 1: Write the failing tests**

```python
def test_ipfm_loopback_parses_and_round_trips():
    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import IpfmLoopbackPolicyModel
    model = IpfmLoopbackPolicyModel(
        policyType="ipfmLoopback", ip="10.2.2.2", advertiseLoopback=True,
        routingTag="777", secondaryIpList=[{"ip": "10.2.2.3", "prefix": 32}],
    )
    payload = model.to_payload()
    assert payload["policyType"] == "ipfmLoopback"
    assert payload["advertiseLoopback"] is True
    assert payload["secondaryIpList"] == [{"ip": "10.2.2.3", "prefix": 32}]


def test_ipfm_loopback_strict_rejects_foreign_field():
    from pydantic import ValidationError
    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import IpfmLoopbackPolicyModel
    with pytest.raises(ValidationError):
        IpfmLoopbackPolicyModel(policyType="ipfmLoopback", ospfAreaId="0")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_ipfm_loopback_parses_and_round_trips -v`
Expected: FAIL with `ImportError` (`IpfmLoopbackPolicyModel` not defined).

- [ ] **Step 3: Add the models**

Insert after `LoopbackPolicyModel`:

```python
class SecondaryIpModel(NDNestedModel):
    """
    # Summary

    A secondary IPv4 address entry for an IPFM loopback (`secondaryIpList` item).

    ## Raises

    None
    """

    ip: str | None = Field(default=None, alias="ip", description="Secondary IPv4 address")
    prefix: int | None = Field(default=None, alias="prefix", ge=4, le=32, description="Subnet mask length (4-32)")


class IpfmLoopbackPolicyModel(LoopbackPolicyBase):
    """
    # Summary

    Policy fields for the NX-OS `ipfmLoopback` template (IP Fabric for Media). Maps to `configData.networkOS.policy` where
    `policyType == "ipfmLoopback"`.

    ## Raises

    None
    """

    policy_type: Literal["ipfmLoopback"] = Field(alias="policyType", description="IPFM loopback policy template discriminator")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")
    advertise_loopback: bool | None = Field(default=None, alias="advertiseLoopback", description="Advertise loopback via OSPF/IS-IS")
    is_service_reflect: bool | None = Field(default=None, alias="isServiceReflect", description="Use loopback as service-reflect source")
    routing_tag: str | None = Field(default=None, alias="routingTag", description="Routing tag associated with the interface IP")
    secondary_ip_list: list[SecondaryIpModel] | None = Field(default=None, alias="secondaryIpList", description="Secondary IPv4 addresses")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -k ipfm -v`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `ndblack plugins/module_utils/models/interfaces/loopback_interface.py && ndisort plugins/module_utils/models/interfaces/loopback_interface.py && ndpylint
plugins/module_utils/models/interfaces/loopback_interface.py && ndmypy plugins/module_utils/models/interfaces/loopback_interface.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Add IpfmLoopbackPolicyModel and SecondaryIpModel"
```

---

## Task 4: `MplsLoopbackPolicyModel`

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py`
- Test: `tests/unit/module_utils/models/test_loopback_interface.py`

**Interfaces:**

- Produces: `MplsLoopbackPolicyModel(LoopbackPolicyBase)` with required `policy_type: Literal["mplsLoopback"]` plus `dci_routing_protocol: Literal["ospf",
  "isis"] | None`, `dci_routing_tag`, `ospf_area_id`.

- [ ] **Step 1: Write the failing tests**

```python
def test_mpls_loopback_parses_and_round_trips():
    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import MplsLoopbackPolicyModel
    model = MplsLoopbackPolicyModel(
        policyType="mplsLoopback", ip="10.3.3.3",
        dciRoutingProtocol="isis", dciRoutingTag="MPLS_UNDERLAY", ospfAreaId="0",
    )
    payload = model.to_payload()
    assert payload["policyType"] == "mplsLoopback"
    assert payload["dciRoutingProtocol"] == "isis"
    assert payload["dciRoutingTag"] == "MPLS_UNDERLAY"


def test_mpls_loopback_strict_rejects_foreign_field():
    from pydantic import ValidationError
    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import MplsLoopbackPolicyModel
    with pytest.raises(ValidationError):
        MplsLoopbackPolicyModel(policyType="mplsLoopback", routingTag="777")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_mpls_loopback_parses_and_round_trips -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Add the model**

Insert after `IpfmLoopbackPolicyModel`:

```python
class MplsLoopbackPolicyModel(LoopbackPolicyBase):
    """
    # Summary

    Policy fields for the NX-OS `mplsLoopback` template. Maps to `configData.networkOS.policy` where
    `policyType == "mplsLoopback"`. Note: `mplsLoopback` is lab-verified creatable but absent from the ND create-side
    discriminator enum (spec drift); modelled per the template and wire.

    ## Raises

    None
    """

    policy_type: Literal["mplsLoopback"] = Field(alias="policyType", description="MPLS loopback policy template discriminator")
    dci_routing_protocol: Literal["ospf", "isis"] | None = Field(default=None, alias="dciRoutingProtocol", description="DCI link-state routing protocol")
    dci_routing_tag: str | None = Field(default=None, alias="dciRoutingTag", description="DCI routing tag")
    ospf_area_id: str | None = Field(default=None, alias="ospfAreaId", min_length=1, max_length=15, description="OSPF area identifier")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -k mpls -v`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `ndblack plugins/module_utils/models/interfaces/loopback_interface.py && ndisort plugins/module_utils/models/interfaces/loopback_interface.py && ndpylint
plugins/module_utils/models/interfaces/loopback_interface.py && ndmypy plugins/module_utils/models/interfaces/loopback_interface.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Add MplsLoopbackPolicyModel"
```

---

## Task 5: Wire the discriminated union on `LoopbackNetworkOSModel.policy`

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py`
- Test: `tests/unit/module_utils/models/test_loopback_interface.py`

**Interfaces:**

- Consumes: `LoopbackPolicyModel`, `IpfmLoopbackPolicyModel`, `MplsLoopbackPolicyModel` (Tasks 2-4).
- Produces: `LoopbackNetworkOSModel.policy` typed as `LoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel | None` with
  `discriminator="policy_type"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_network_os_discriminator_selects_branch():
    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
        IpfmLoopbackPolicyModel, LoopbackNetworkOSModel, MplsLoopbackPolicyModel,
    )
    lo = LoopbackNetworkOSModel(networkOSType="nx-os", policy={"policyType": "loopback", "ip": "10.1.1.1/32"})
    assert isinstance(lo.policy, LoopbackPolicyModel)
    ipfm = LoopbackNetworkOSModel(networkOSType="nx-os", policy={"policyType": "ipfmLoopback", "advertiseLoopback": True})
    assert isinstance(ipfm.policy, IpfmLoopbackPolicyModel)
    mpls = LoopbackNetworkOSModel(networkOSType="nx-os", policy={"policyType": "mplsLoopback", "dciRoutingTag": "X"})
    assert isinstance(mpls.policy, MplsLoopbackPolicyModel)


def test_network_os_missing_discriminator_raises():
    from pydantic import ValidationError
    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackNetworkOSModel
    with pytest.raises(ValidationError):
        LoopbackNetworkOSModel(networkOSType="nx-os", policy={"ip": "10.1.1.1/32"})


def test_full_interface_round_trip_via_api_response():
    # Uses the existing SAMPLE_API_RESPONSE (policyType: loopback) to prove from_response + to_payload survive extra="forbid".
    model = LoopbackInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    assert isinstance(model.config_data.network_os.policy, LoopbackPolicyModel)
    payload = model.to_payload()
    assert payload["configData"]["networkOS"]["policy"]["policyType"] == "loopback"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_network_os_discriminator_selects_branch
tests/unit/module_utils/models/test_loopback_interface.py::test_network_os_missing_discriminator_raises -v`
Expected: FAIL — `policy` is still typed as a single `LoopbackPolicyModel`, so ipfm/mpls dicts mis-parse and a missing discriminator does not raise.

- [ ] **Step 3: Convert the `policy` field to a discriminated union**

In `LoopbackNetworkOSModel`, replace the `policy` field with:

```python
    policy: LoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel | None = Field(
        default=None, alias="policy", discriminator="policy_type"
    )
```

- [ ] **Step 4: Run tests to verify they pass (full model suite)**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -v`
Expected: PASS. If `test_full_interface_round_trip_via_api_response` fails because the ND response's `policy` object carries a key not modelled on the
`loopback` branch, that is the `extra="forbid"` read-path risk from the spec — add that field to the correct branch model (it is a real template field we
missed) rather than relaxing `forbid`.

- [ ] **Step 5: Lint (with mypy — the union type is the risk here)**

Run: `ndblack plugins/module_utils/models/interfaces/loopback_interface.py && ndisort plugins/module_utils/models/interfaces/loopback_interface.py && ndpylint
plugins/module_utils/models/interfaces/loopback_interface.py && ndmypy plugins/module_utils/models/interfaces/loopback_interface.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Wire loopback policy discriminated union on policy_type"
```

---

## Task 6: Extend the argspec with `policy_type` + union fields

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py` (`get_argument_spec`)
- Test: `tests/unit/module_utils/models/test_loopback_interface.py`

**Interfaces:**

- Produces: `LoopbackInterfaceModel.get_argument_spec()` whose `config.options.config_data.options.network_os.options.policy.options` includes a required
  `policy_type` (choices `loopback`/`ipfmLoopback`/`mplsLoopback`) and the union of all branch fields.

- [ ] **Step 1: Write the failing test**

```python
def test_argument_spec_policy_options():
    spec = LoopbackInterfaceModel.get_argument_spec()
    policy = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    assert policy["policy_type"]["required"] is True
    assert set(policy["policy_type"]["choices"]) == {"loopback", "ipfmLoopback", "mplsLoopback"}
    # union fields present across all three branches
    for field in ("ipv6", "route_map_tag", "advertise_loopback", "routing_tag", "secondary_ip_list", "dci_routing_tag", "ospf_area_id"):
        assert field in policy, field
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_argument_spec_policy_options -v`
Expected: FAIL — `policy_type` and the new fields are absent from the current argspec.

- [ ] **Step 3: Replace the `policy` options block in `get_argument_spec`**

In `get_argument_spec()`, replace the `policy=dict(...)` options with:

```python
                                    policy=dict(
                                        type="dict",
                                        options=dict(
                                            policy_type=dict(type="str", required=True, choices=["loopback", "ipfmLoopback", "mplsLoopback"]),
                                            admin_state=dict(type="bool"),
                                            ip=dict(type="str"),
                                            description=dict(type="str"),
                                            extra_config=dict(type="str"),
                                            vrf=dict(type="str"),
                                            ipv6=dict(type="str"),
                                            route_map_tag=dict(type="str"),
                                            advertise_loopback=dict(type="bool"),
                                            is_service_reflect=dict(type="bool"),
                                            routing_tag=dict(type="str"),
                                            secondary_ip_list=dict(type="list", elements="dict", options=dict(ip=dict(type="str"), prefix=dict(type="int"))),
                                            dci_routing_protocol=dict(type="str", choices=["ospf", "isis"]),
                                            dci_routing_tag=dict(type="str"),
                                            ospf_area_id=dict(type="str"),
                                        ),
                                    ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py::test_argument_spec_policy_options -v`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `ndblack plugins/module_utils/models/interfaces/loopback_interface.py && ndisort plugins/module_utils/models/interfaces/loopback_interface.py && ndpylint
plugins/module_utils/models/interfaces/loopback_interface.py && ndmypy plugins/module_utils/models/interfaces/loopback_interface.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Extend loopback argspec with policy_type and union fields"
```

---

## Task 7: Set-based `query_all` filter in the orchestrator

**Files:**

- Modify: `plugins/module_utils/orchestrators/loopback_interface.py`
- Test: `tests/unit/module_utils/orchestrators/test_loopback_interface.py`
- Modify: `tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json`

**Interfaces:**

- Consumes: `LoopbackPolicyTypeEnum` (Task 1).
- Produces: `query_all` returns interfaces whose `policyType` is in `{loopback, ipfmLoopback, mplsLoopback}`.

- [ ] **Step 1: Add the fixture**

Add three keys to `tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json` (a=summary, b=one switch, c=mixed interfaces):

```json
    "test_loopback_interface_00760a": {
        "TEST_NOTES": ["query_all multi-type: fabric summary"],
        "RETURN_CODE": 200, "METHOD": "GET",
        "REQUEST_PATH": "/api/v1/manage/fabrics/fabric_1/summary",
        "MESSAGE": "OK",
        "DATA": {"name": "fabric_1", "ownerCluster": "cluster_a", "local": true, "fabricStatus": "default"}
    },
    "test_loopback_interface_00760b": {
        "TEST_NOTES": ["query_all multi-type: one switch"],
        "RETURN_CODE": 200, "METHOD": "GET",
        "REQUEST_PATH": "/api/v1/manage/fabrics/fabric_1/switches",
        "MESSAGE": "OK",
        "DATA": {"switches": [{"fabricManagementIp": "192.168.12.151", "switchId": "FDO12345ABC"}]}
    },
    "test_loopback_interface_00760c": {
        "TEST_NOTES": ["query_all multi-type: loopback+ipfm+mpls kept; userDefined+underlay excluded"],
        "RETURN_CODE": 200, "METHOD": "GET",
        "REQUEST_PATH": "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces",
        "MESSAGE": "OK",
        "DATA": {"interfaces": [
            {"interfaceName": "loopback10", "interfaceType": "loopback", "configData": {"networkOS": {"policy": {"policyType": "loopback"}}}},
            {"interfaceName": "loopback11", "interfaceType": "loopback", "configData": {"networkOS": {"policy": {"policyType": "ipfmLoopback"}}}},
            {"interfaceName": "loopback12", "interfaceType": "loopback", "configData": {"networkOS": {"policy": {"policyType": "mplsLoopback"}}}},
            {"interfaceName": "loopback13", "interfaceType": "loopback", "configData": {"networkOS": {"policy": {"policyType": "userDefined"}}}},
            {"interfaceName": "loopback0", "interfaceType": "loopback", "configData": {"networkOS": {"policy": {"policyType": "underlayLoopback"}}}}
        ]}
    },
```

- [ ] **Step 2: Write the failing test**

Add to `tests/unit/module_utils/orchestrators/test_loopback_interface.py`:

```python
def test_loopback_interface_00760() -> None:
    """
    # Summary

    Verify `query_all` returns interfaces of all three managed policy types (`loopback`, `ipfmLoopback`, `mplsLoopback`)
    and excludes `userDefined` and system-provisioned (`underlayLoopback`) interfaces.

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, state="overridden")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    returned = {item["configData"]["networkOS"]["policy"]["policyType"] for item in result}
    assert returned == {"loopback", "ipfmLoopback", "mplsLoopback"}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `ndpytest tests/unit/module_utils/orchestrators/test_loopback_interface.py::test_loopback_interface_00760 -v`
Expected: FAIL — current filter keeps only `policyType == "loopback"`, so `returned == {"loopback"}`.

- [ ] **Step 4: Replace the filter**

In `plugins/module_utils/orchestrators/loopback_interface.py`, add the import:

```python
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import LoopbackPolicyTypeEnum
```

and in `query_all`, replace the `managed = [...]` line with:

```python
                managed_policy_types = {policy_type.value for policy_type in LoopbackPolicyTypeEnum}
                managed = [
                    lb
                    for lb in loopbacks
                    if lb.get("configData", {}).get("networkOS", {}).get("policy", {}).get("policyType") in managed_policy_types
                ]
```

Update the `query_all` docstring and the module-level docstring: they currently claim `ipfmLoopback` is handled by a dedicated module — change to state that
`loopback`, `ipfmLoopback`, and `mplsLoopback` are managed here and only `userDefined` / system-provisioned policy types are excluded.

- [ ] **Step 5: Run test + full orchestrator suite**

Run: `ndpytest tests/unit/module_utils/orchestrators/test_loopback_interface.py -v`
Expected: PASS (existing 00700-series still green — their fixtures contain only `loopback` plus excluded types).

- [ ] **Step 6: Lint**

Run: `ndblack plugins/module_utils/orchestrators/loopback_interface.py && ndisort plugins/module_utils/orchestrators/loopback_interface.py && ndpylint
plugins/module_utils/orchestrators/loopback_interface.py && ndmypy plugins/module_utils/orchestrators/loopback_interface.py`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add plugins/module_utils/orchestrators/loopback_interface.py tests/unit/module_utils/orchestrators/test_loopback_interface.py tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json
git commit -m "query_all: manage loopback, ipfmLoopback, mplsLoopback via set filter"
```

---

## Task 8: Module DOCUMENTATION / EXAMPLES

**Files:**

- Modify: `plugins/modules/nd_interface_loopback.py`

**Interfaces:**

- Consumes: the argspec shape from Task 6. No code/logic change — DOCUMENTATION and EXAMPLES only.

- [ ] **Step 1: Update DOCUMENTATION**

In the module's `DOCUMENTATION` string, under `config.suboptions.config_data.suboptions.network_os.suboptions.policy.suboptions`, add `policy_type` (required;
choices `loopback`, `ipfmLoopback`, `mplsLoopback`) and document the per-template fields: `vrf`, `ipv6`, `route_map_tag` (loopback); `advertise_loopback`,
`is_service_reflect`, `routing_tag`, `secondary_ip_list` (ipfmLoopback); `dci_routing_protocol`, `dci_routing_tag`, `ospf_area_id` (mplsLoopback). Note in each
field's description which `policy_type` it applies to.

- [ ] **Step 2: Add EXAMPLES**

Add one EXAMPLES task per policy type showing `policy_type` set, e.g.:

```yaml
- name: Create an IPFM loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric_1
    state: merged
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback11
        config_data:
          network_os:
            policy:
              policy_type: ipfmLoopback
              ip: 10.2.2.2
              advertise_loopback: true
```

- [ ] **Step 3: Validate the module docs**

Run: `ndtest --test validate-modules plugins/modules/nd_interface_loopback.py`
Expected: PASS (DOCUMENTATION argspec matches `get_argument_spec`).

- [ ] **Step 4: Commit**

```bash
git add plugins/modules/nd_interface_loopback.py
git commit -m "Document loopback policy_type and per-template fields"
```

---

## Task 9: Update integration tasks with `policy_type: loopback`

**Files:**

- Modify: `tests/integration/targets/nd_interface_loopback/vars/main.yaml` (5 blocks)
- Modify: `tests/integration/targets/nd_interface_loopback/tasks/replaced.yaml` (2 blocks)
- Modify: `tests/integration/targets/nd_interface_loopback/tasks/overridden.yaml` (1 block)
- Modify: `tests/integration/targets/nd_interface_loopback/tasks/merged.yaml` (1 block)

**Interfaces:**

- Consumes: the now-required `policy_type` (Task 2). No new interfaces produced.

- [ ] **Step 1: Add `policy_type: loopback` to every `policy:` block**

In each file, for every `policy:` mapping, add `policy_type: loopback` as the first key under it. Example (`vars/main.yaml`):

```yaml
        policy:
          policy_type: loopback
          admin_state: true
          ip: 10.100.100.1/32
```

- [ ] **Step 2: Verify all blocks are covered**

Run: `grep -rc "policy_type: loopback" tests/integration/targets/nd_interface_loopback/`
Expected counts: `vars/main.yaml:5`, `tasks/replaced.yaml:2`, `tasks/overridden.yaml:1`, `tasks/merged.yaml:1`.

Cross-check none were missed:

Run: `grep -rn "^\s*policy:\s*$" tests/integration/targets/nd_interface_loopback/ | wc -l`
Expected: `9` (matching the 9 added `policy_type: loopback` lines).

- [ ] **Step 3: YAML sanity**

Run: `ndm bash -lc "python3 -c 'import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob(\"tests/integration/targets/nd_interface_loopback/**/*.yaml\",
recursive=True)]'"`
Expected: no exception (all task/vars YAML still parses).

- [ ] **Step 4: Commit**

```bash
git add tests/integration/targets/nd_interface_loopback/
git commit -m "Integration: add required policy_type: loopback to loopback tasks"
```

---

## Final verification

- [ ] **Run the full loopback unit suites**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py tests/unit/module_utils/orchestrators/test_loopback_interface.py -v`
Expected: all PASS.

- [ ] **Run sanity on the touched module + model**

Run: `ndtest --test validate-modules plugins/modules/nd_interface_loopback.py`
Expected: PASS.

- [ ] **Full lint sweep of changed Python files**

Run: `ndblack --check plugins/module_utils/models/interfaces/loopback_interface.py plugins/module_utils/models/interfaces/enums.py
plugins/module_utils/orchestrators/loopback_interface.py && ndpylint plugins/module_utils/models/interfaces/loopback_interface.py
plugins/module_utils/orchestrators/loopback_interface.py && ndmypy plugins/module_utils/models/interfaces/loopback_interface.py
plugins/module_utils/orchestrators/loopback_interface.py`
Expected: no errors.

---

## Notes / risks (from the spec)

- **`extra="forbid"` on the read path:** `from_response` also runs through the branch models. If ND 4.2.1 returns a `policy` key not modelled on the matched
  branch, `forbid` will reject the read. Task 5 Step 4 guards this with a real-response round-trip test; the fix if it triggers is to add the missing real
  field to the correct branch, not to relax `forbid`. Integration testing against a live fabric is the ultimate check.
- **`mplsLoopback` creatability** is lab-verified but not in the OpenAPI create enum; unit tests assert model/round-trip only, integration confirms create.
- **IOS-XE / `network_os_type`** stays frozen — separate follow-up, blocked on `FabricContext` exposing switch OS.
