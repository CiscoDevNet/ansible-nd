# IOS-XE Loopback Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan
  task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add all six IOS-XE loopback policy branches to `nd_interface_loopback` so `network_os_type` becomes a real discriminated-union discriminator (spec:
`docs/superpowers/specs/2026-07-18-loopback-ios-xe-model-design.md`).

**Architecture:** Split the policy base class so `extra="forbid"` + the read-tolerant validator + `admin_state` live in a new `LoopbackPolicyStrictBase`; add
six XE branch models; split `LoopbackNetworkOSModel` into `NexusLoopbackNetworkOSModel` | `XeLoopbackNetworkOSModel` discriminated on `network_os_type`.
Orchestrator only widens its `query_all` policy-type filter set.

**Tech Stack:** Pydantic v2 via `pydantic_compat`, Ansible collection layout, `nd-dev` container wrappers (`ndpytest`, `ndlint`, `ndpylint`, `ndmypy`,
`ndblack`, `ndisort`, `ndtest`).

## Global Constraints

- Line length **159** (black/isort/pylint/mypy config in `pyproject.toml`); markdown MD013 also 159.
- Docstrings: Markdown, `# Summary` + `## Raises` sections mandatory (use `None` when nothing raises).
- Modern annotations (PEP 585/604): `X | None`, `list[X]`; no `Optional`/`Union`/`List` imports.
- All Pydantic imports via `plugins/module_utils/common/pydantic_compat.py`.
- `__init__.py` files under `plugins/` stay **empty** (zero bytes).
- Never use `_` as a variable name in tests (pylint `disallowed-name`); use `result`.
- Unit-test fixture keys: `test_<module>_<NNNNN><letter>`; each test's fixture data is unique.
- New model tests use the descriptive snake_case convention already used by the union tests in `tests/unit/module_utils/models/test_loopback_interface.py`
  (e.g. `test_loopback_policy_strict_rejects_foreign_field`); orchestrator tests keep the numbered convention.
- `TODO(X.Y.Z) <slug>` markers require a bug-tracker vault note with that slug to exist FIRST (CLAUDE.md "Workaround Markers"). Task 6 writes the note; do not
  add the marker before then.
- Run unit tests with `ndpytest <path>`; if the wrapper is unavailable in your shell, the explicit form is `ndm bash -lc "source env && python3 -m pytest
  <path>"`.
- Commit after each task with the trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: `LoopbackPolicyStrictBase` split (pure refactor, suite stays green)

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py` (classes `LoopbackPolicyBase`, lines ~42-81)

**Interfaces:**

- Consumes: existing `NDNestedModel`, `ConfigDict`, `Field`, `model_validator` (already imported in the file).
- Produces: `LoopbackPolicyStrictBase(NDNestedModel)` with `model_config = ConfigDict(extra="forbid")`, field `admin_state`, and classmethod before-validator
  `strip_none_valued_keys(cls, data, info)`. `LoopbackPolicyBase(LoopbackPolicyStrictBase)` keeps `ip`, `description`, `extra_config` only. Tasks 2-3 subclass
  `LoopbackPolicyStrictBase`.

- [ ] **Step 1: Run the existing model suite to establish the green baseline**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py`
Expected: all tests PASS.

- [ ] **Step 2: Split the base class**

Replace the current `LoopbackPolicyBase` class with two classes (docstring format per Global Constraints; keep the existing validator body verbatim — only its
home moves):

```python
class LoopbackPolicyStrictBase(NDNestedModel):
    """
    # Summary

    Write-strict / read-tolerant base for every managed loopback policy branch (NX-OS and IOS-XE). Sets `extra="forbid"` so fields belonging
    to a different `policy_type` are rejected, strips `None`-valued keys first so unset flat-argspec options are not rejected, and declares
    `admin_state` — the only field common to all loopback templates on both network OS types.

    ## Raises

    None
    """

    model_config = ConfigDict(extra="forbid")

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")

    @model_validator(mode="before")
    @classmethod
    def strip_none_valued_keys(cls, data, info):
        """
        # Summary

        Drop `None`-valued keys before validation so unset flat-argspec options do not trip `extra="forbid"`. On the read
        path (validation `context={"mode": "read"}`, set by `from_response`), also drop keys not declared on this model so
        ND-injected read-only keys (e.g. `linkStateRoutingTag`) do not trip `extra="forbid"` while write-side input stays strict.

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        data = {key: value for key, value in data.items() if value is not None}
        if info.context and info.context.get("mode") == "read":
            allowed = set(cls.model_fields) | {field.alias for field in cls.model_fields.values() if field.alias}
            data = {key: value for key, value in data.items() if key in allowed}
        return data


class LoopbackPolicyBase(LoopbackPolicyStrictBase):
    """
    # Summary

    Shared policy fields common to every managed NX-OS loopback template. Inherits write-strict / read-tolerant behavior and
    `admin_state` from `LoopbackPolicyStrictBase`.

    ## Raises

    None
    """

    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form, e.g. 10.1.1.1; CIDR input is accepted and normalized)")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
```

(`admin_state`, the `model_config`, and the validator are REMOVED from `LoopbackPolicyBase` — they now come from the parent.)

- [ ] **Step 3: Re-run the suite to prove the refactor is behavior-neutral**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py`
Expected: all tests PASS, same count as Step 1.

- [ ] **Step 4: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py
git commit -m "Refactor: split LoopbackPolicyStrictBase out of LoopbackPolicyBase

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Six IOS-XE branch models

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py` (insert after `MplsLoopbackPolicyModel`)
- Test: `tests/unit/module_utils/models/test_loopback_interface.py` (append after the existing strict-base tests)

**Interfaces:**

- Consumes: `LoopbackPolicyStrictBase` (Task 1), `AsciiDescription`, `IPv4Host` (already imported), `field_validator` (already imported).
- Produces: `XeLoopbackPolicyModel`, `XeLoopbackShutNoshutPolicyModel`, `XeUnderlayLoopbackPolicyModel`, `XeInternalLoopbackPolicyModel`,
  `CsrLoopbackPolicyModel`, `Csr1kvLoopbackPolicyModel` — Task 3 places them in `XeLoopbackNetworkOSModel.policy`.

- [ ] **Step 1: Write the failing tests** (append to the model test file; docstring format as the neighboring union tests)

```python
def test_xe_loopback_parses_and_round_trips() -> None:
    """
    # Summary

    Verify `XeLoopbackPolicyModel` accepts its template fields and round-trips through `model_dump(by_alias=True)`.

    ## Test

    - Construct with all `ios_xe_int_loopback` template fields
    - Dump by alias and verify wire keys

    ## Classes and Methods

    - XeLoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        instance = XeLoopbackPolicyModel(policyType="iosXeLoopback", adminState=True, ip="10.2.2.2", description="xe lo", vrfInterface="blue", extraConfig="delay 100")
    dumped = instance.model_dump(by_alias=True, exclude_none=True)
    assert dumped["policyType"] == "iosXeLoopback"
    assert dumped["ip"] == "10.2.2.2"
    assert dumped["vrfInterface"] == "blue"


def test_xe_loopback_rejects_foreign_field() -> None:
    """
    # Summary

    Verify `XeLoopbackPolicyModel` rejects an NX-OS-only field (`routeMapTag`) under `extra="forbid"`.

    ## Test

    - Construct with `routeMapTag`
    - `ValidationError` is raised

    ## Classes and Methods

    - XeLoopbackPolicyModel.__init__()
    """
    with pytest.raises(ValidationError):
        result = XeLoopbackPolicyModel(policyType="iosXeLoopback", routeMapTag="1")  # pylint: disable=unused-variable


def test_xe_loopback_description_max_200() -> None:
    """
    # Summary

    Verify `XeLoopbackPolicyModel.description` enforces the XE 200-character maximum (NX-OS allows 254).

    ## Test

    - 200-character description validates
    - 201-character description raises `ValidationError` matching `description`

    ## Classes and Methods

    - XeLoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        result = XeLoopbackPolicyModel(policyType="iosXeLoopback", description="d" * 200)  # pylint: disable=unused-variable
    with pytest.raises(ValidationError, match="description"):
        result = XeLoopbackPolicyModel(policyType="iosXeLoopback", description="d" * 201)  # pylint: disable=unused-variable


def test_xe_shut_noshut_rejects_ip() -> None:
    """
    # Summary

    Verify `XeLoopbackShutNoshutPolicyModel` accepts only `admin_state` and rejects `ip` (the template has no other fields).

    ## Test

    - Construct with `adminState` only succeeds
    - Construct with `ip` raises `ValidationError`

    ## Classes and Methods

    - XeLoopbackShutNoshutPolicyModel.__init__()
    """
    with does_not_raise():
        result = XeLoopbackShutNoshutPolicyModel(policyType="iosXeLoopbackShutNoshut", adminState=False)  # pylint: disable=unused-variable
    with pytest.raises(ValidationError):
        result = XeLoopbackShutNoshutPolicyModel(policyType="iosXeLoopbackShutNoshut", ip="10.1.1.1")  # pylint: disable=unused-variable


def test_xe_underlay_accepts_secondary_ip_rejects_vrf() -> None:
    """
    # Summary

    Verify `XeUnderlayLoopbackPolicyModel` accepts `secondaryIp` and rejects `vrfInterface` (absent from the underlay template).

    ## Test

    - Construct with `secondaryIp` succeeds
    - Construct with `vrfInterface` raises `ValidationError`

    ## Classes and Methods

    - XeUnderlayLoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        result = XeUnderlayLoopbackPolicyModel(policyType="iosXeUnderlayLoopback", ip="10.3.3.3", secondaryIp="10.3.3.4")  # pylint: disable=unused-variable
    with pytest.raises(ValidationError):
        result = XeUnderlayLoopbackPolicyModel(policyType="iosXeUnderlayLoopback", vrfInterface="blue")  # pylint: disable=unused-variable


def test_xe_internal_ip_and_ipv6_are_unvalidated_strings() -> None:
    """
    # Summary

    Verify `XeInternalLoopbackPolicyModel` accepts `enablePim`/`ipv6` and leaves `ip` unvalidated (the `ios_xe_int_loopback_internal`
    template deliberately declares `ip` as a bare string in the ND 4.2.1 schema).

    ## Test

    - Construct with a non-IPv4 `ip` string, `ipv6`, and `enablePim` succeeds

    ## Classes and Methods

    - XeInternalLoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        instance = XeInternalLoopbackPolicyModel(policyType="iosXeInternalLoopback", ip="not-an-ip", ipv6="2001:db8::1/128", enablePim=True)
    assert instance.ip == "not-an-ip"
    assert instance.enable_pim is True


def test_csr_loopback_normalizes_read_alias() -> None:
    """
    # Summary

    Verify `CsrLoopbackPolicyModel` accepts the read-side `csrIntLoopback` discriminator value and normalizes it to the
    create-side `csrLoopback` so payloads and idempotency comparison always use the create name.

    ## Test

    - Construct with `policyType="csrIntLoopback"`
    - `policy_type` normalizes to `csrLoopback`; dump emits `csrLoopback`

    ## Classes and Methods

    - CsrLoopbackPolicyModel.__init__()
    - CsrLoopbackPolicyModel.normalize_csr_policy_type()
    """
    instance = CsrLoopbackPolicyModel(policyType="csrIntLoopback", ip="10.4.4.4")
    assert instance.policy_type == "csrLoopback"
    assert instance.model_dump(by_alias=True, exclude_none=True)["policyType"] == "csrLoopback"


def test_csr1kv_rejects_ip() -> None:
    """
    # Summary

    Verify `Csr1kvLoopbackPolicyModel` accepts only `admin_state`/`extraConfig` and rejects `ip` (absent from the csr1kv template).

    ## Test

    - Construct with `extraConfig` succeeds
    - Construct with `ip` raises `ValidationError`

    ## Classes and Methods

    - Csr1kvLoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        result = Csr1kvLoopbackPolicyModel(policyType="csr1kvLoopback", extraConfig="shutdown")  # pylint: disable=unused-variable
    with pytest.raises(ValidationError):
        result = Csr1kvLoopbackPolicyModel(policyType="csr1kvLoopback", ip="10.5.5.5")  # pylint: disable=unused-variable
```

Add the six new class names to the existing `from ...loopback_interface import (...)` block at the top of the test file.

- [ ] **Step 2: Run to verify they fail**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -k "xe_ or csr" -v`
Expected: FAIL/ERROR with `ImportError` (models not defined yet).

- [ ] **Step 3: Implement the six models** (insert after `MplsLoopbackPolicyModel`)

```python
class XeLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeLoopback` template (`ios_xe_int_loopback`). Maps to `configData.networkOS.policy` where
    `policyType == "iosXeLoopback"`.

    ## Raises

    None
    """

    policy_type: Literal["iosXeLoopback"] = Field(alias="policyType", description="IOS-XE loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form; CIDR input is accepted and normalized)")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")


class XeLoopbackShutNoshutPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeLoopbackShutNoshut` template (`ios_xe_int_loopback_admin_state`). The template carries only
    `adminState`, inherited from `LoopbackPolicyStrictBase`.

    ## Raises

    None
    """

    policy_type: Literal["iosXeLoopbackShutNoshut"] = Field(alias="policyType", description="IOS-XE admin-state-only loopback policy template discriminator")


class XeUnderlayLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeUnderlayLoopback` template (`ios_xe_int_underlay_loopback`). Unlike NX-OS `underlayLoopback`
    (system-provisioned, excluded), this policy type is in the XE create-side enum and therefore user-creatable.

    ## Raises

    None
    """

    policy_type: Literal["iosXeUnderlayLoopback"] = Field(alias="policyType", description="IOS-XE underlay loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form; CIDR input is accepted and normalized)")
    secondary_ip: str | None = Field(default=None, alias="secondaryIp", description="Secondary IP address of the NVE interface loopback")


class XeInternalLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `iosXeInternalLoopback` template (`ios_xe_int_loopback_internal`). `ip` and `ipv6` are plain strings —
    the ND 4.2.1 schema deliberately leaves them unvalidated for this template (no `format: ipv4`), so the model matches the schema.

    ## Raises

    None
    """

    policy_type: Literal["iosXeInternalLoopback"] = Field(alias="policyType", description="IOS-XE internal loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=200, description="Interface description")
    enable_pim: bool | None = Field(default=None, alias="enablePim", description="Enable PIM")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: str | None = Field(default=None, alias="ip", description="Loopback IP address (unvalidated string per the ND schema for this template)")
    ipv6: str | None = Field(default=None, alias="ipv6", description="Loopback IPv6 address (unvalidated string per the ND schema for this template)")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")


class CsrLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `csrLoopback` template (`csr_int_loopback`). The ND 4.2.1 spec drifts on this branch's name:
    the create-side discriminator enum says `csrLoopback` while the read-side enum says `csrIntLoopback`. Both are accepted as the
    discriminator; the validator normalizes to the create-side `csrLoopback` so payloads and idempotency comparison use one name.
    Lab verification and the vault note / `TODO(4.2.1)` marker land in the lab-verification task.

    ## Raises

    None
    """

    policy_type: Literal["csrLoopback", "csrIntLoopback"] = Field(alias="policyType", description="CSR loopback policy template discriminator")
    description: AsciiDescription = Field(default=None, alias="description", min_length=1, max_length=254, description="Interface description")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Additional CLI for the interface")
    ip: IPv4Host = Field(default=None, alias="ip", description="Loopback IPv4 address (bare host form; CIDR input is accepted and normalized)")
    vrf: str | None = Field(default=None, alias="vrfInterface", min_length=1, max_length=32, description="Interface VRF name")

    @field_validator("policy_type", mode="after")
    @classmethod
    def normalize_csr_policy_type(cls, value):
        """
        # Summary

        Normalize the read-side `csrIntLoopback` discriminator value to the create-side `csrLoopback`.

        ## Raises

        None
        """
        if value == "csrIntLoopback":
            return "csrLoopback"
        return value


class Csr1kvLoopbackPolicyModel(LoopbackPolicyStrictBase):
    """
    # Summary

    Policy fields for the IOS-XE `csr1kvLoopback` template (`csr1kv_loopback`). The template carries only `adminState` and `extraConfig`.

    ## Raises

    None
    """

    policy_type: Literal["csr1kvLoopback"] = Field(alias="policyType", description="CSR1kv loopback policy template discriminator")
    extra_config: str | None = Field(default=None, alias="extraConfig", description="Interface freeform config")
```

Note: `policy_type` narrowing in `CsrLoopbackPolicyModel` — mypy may flag returning `"csrLoopback"` from the validator; the field's declared type includes it,
so no cast is needed.

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -k "xe_ or csr" -v`
Expected: 8 new tests PASS. Then run the full file: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py` — all PASS.

- [ ] **Step 5: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Add six IOS-XE loopback policy branch models

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Outer `network_os_type` discriminated union

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py` (`LoopbackNetworkOSModel` → split; `LoopbackConfigDataModel.network_os`; module
  docstring hierarchy lines 12-25)
- Modify: `tests/unit/module_utils/models/test_loopback_interface.py` (import + references at lines ~22, 685-830, 1868-1919; the `networkOSType="ios-xe"`
  rejection test at ~774-777 flips)
- Modify: `tests/unit/module_utils/orchestrators/test_loopback_interface.py` (import at line 33, usage at line 89)

**Interfaces:**

- Consumes: the six XE models (Task 2), the three NX branch models (existing).
- Produces: `NexusLoopbackNetworkOSModel` (`network_os_type: Literal["nx-os"]`), `XeLoopbackNetworkOSModel` (`network_os_type: Literal["ios-xe"]`), and
  `LoopbackConfigDataModel.network_os: NexusLoopbackNetworkOSModel | XeLoopbackNetworkOSModel` with `discriminator="network_os_type"`. Task 5's argspec and
  Task 4's fixtures rely on the wire aliases being unchanged (`networkOSType`, `policy`).

- [ ] **Step 1: Write the failing tests** (append to the model test file)

```python
def test_network_os_outer_union_selects_xe_branch() -> None:
    """
    # Summary

    Verify `LoopbackConfigDataModel.network_os` selects `XeLoopbackNetworkOSModel` when `networkOSType == "ios-xe"` and
    `NexusLoopbackNetworkOSModel` when `networkOSType == "nx-os"`.

    ## Test

    - Construct config data for each OS
    - The selected branch model type is correct

    ## Classes and Methods

    - LoopbackConfigDataModel.__init__()
    """
    xe = LoopbackConfigDataModel(networkOS={"networkOSType": "ios-xe", "policy": {"policyType": "iosXeLoopback", "ip": "10.2.2.2"}})
    assert isinstance(xe.network_os, XeLoopbackNetworkOSModel)
    assert isinstance(xe.network_os.policy, XeLoopbackPolicyModel)
    nx = LoopbackConfigDataModel(networkOS={"networkOSType": "nx-os", "policy": {"policyType": "loopback", "ip": "10.1.1.1"}})
    assert isinstance(nx.network_os, NexusLoopbackNetworkOSModel)


def test_cross_os_policy_type_rejected() -> None:
    """
    # Summary

    Verify cross-OS mismatches fail structurally: `nx-os` with an XE `policy_type` and `ios-xe` with an NX-OS `policy_type`
    both raise `ValidationError` from the discriminated union — no hand-written cross-check.

    ## Test

    - `nx-os` + `iosXeLoopback` raises
    - `ios-xe` + `loopback` raises

    ## Classes and Methods

    - LoopbackConfigDataModel.__init__()
    """
    with pytest.raises(ValidationError):
        result = LoopbackConfigDataModel(networkOS={"networkOSType": "nx-os", "policy": {"policyType": "iosXeLoopback"}})  # pylint: disable=unused-variable
    with pytest.raises(ValidationError):
        result = LoopbackConfigDataModel(networkOS={"networkOSType": "ios-xe", "policy": {"policyType": "loopback"}})  # pylint: disable=unused-variable


def test_xe_from_response_tolerates_injected_policy_key() -> None:
    """
    # Summary

    Verify the read-tolerant path works for XE branches: `from_response` with an undeclared ND-injected policy key validates,
    while direct (write-path) construction with the same key raises.

    ## Test

    - `from_response` with an injected key succeeds (read mode strips it)
    - Direct construction with the same key raises `ValidationError`

    ## Classes and Methods

    - LoopbackInterfaceModel.from_response()
    - LoopbackPolicyStrictBase.strip_none_valued_keys()
    """
    response = {
        "switchIp": "192.168.1.2",
        "interfaceName": "loopback105",
        "interfaceType": "loopback",
        "configData": {
            "mode": "managed",
            "networkOS": {"networkOSType": "ios-xe", "policy": {"policyType": "iosXeLoopback", "ip": "10.2.2.2", "ndInjectedKey": "x"}},
        },
    }
    with does_not_raise():
        instance = LoopbackInterfaceModel.from_response(response)
    assert isinstance(instance.config_data.network_os.policy, XeLoopbackPolicyModel)
    with pytest.raises(ValidationError):
        result = XeLoopbackPolicyModel(policyType="iosXeLoopback", ndInjectedKey="x")  # pylint: disable=unused-variable
```

- [ ] **Step 2: Run to verify they fail**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -k "outer_union or cross_os or xe_from_response" -v`
Expected: FAIL with `ImportError`/`NameError` (`NexusLoopbackNetworkOSModel`, `XeLoopbackNetworkOSModel` not defined).

- [ ] **Step 3: Implement the split**

Replace `LoopbackNetworkOSModel` with:

```python
class NexusLoopbackNetworkOSModel(NDNestedModel):
    """
    # Summary

    NX-OS branch of the network-OS container for a loopback interface. Selected from the outer union when `networkOSType == "nx-os"`.

    ## Raises

    None
    """

    # Not frozen: NDBaseModel.merge() assigns every explicitly-set field, and required fields are always
    # explicitly set. The Literal constrains the value; same pattern as the policy_type discriminator.
    network_os_type: Literal["nx-os"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: LoopbackPolicyModel | IpfmLoopbackPolicyModel | MplsLoopbackPolicyModel | None = Field(default=None, alias="policy", discriminator="policy_type")


class XeLoopbackNetworkOSModel(NDNestedModel):
    """
    # Summary

    IOS-XE branch of the network-OS container for a loopback interface. Selected from the outer union when `networkOSType == "ios-xe"`.

    ## Raises

    None
    """

    network_os_type: Literal["ios-xe"] = Field(alias="networkOSType", description="Network OS (platform) type discriminator; required by the ND API schema")
    policy: (
        XeLoopbackPolicyModel
        | XeLoopbackShutNoshutPolicyModel
        | XeUnderlayLoopbackPolicyModel
        | XeInternalLoopbackPolicyModel
        | CsrLoopbackPolicyModel
        | Csr1kvLoopbackPolicyModel
        | None
    ) = Field(default=None, alias="policy", discriminator="policy_type")
```

In `LoopbackConfigDataModel` change the field to:

```python
    network_os: NexusLoopbackNetworkOSModel | XeLoopbackNetworkOSModel = Field(alias="networkOS", discriminator="network_os_type")
```

Update the module docstring hierarchy (lines 12-25) to show the two OS branches and their policy unions.

- [ ] **Step 4: Update existing references in both test files**

- `tests/unit/module_utils/models/test_loopback_interface.py`: change the import and every `LoopbackNetworkOSModel(` construction (lines ~685-830, 1868-1919)
  to `NexusLoopbackNetworkOSModel`. Rewrite the test at ~774-777 (which asserted `networkOSType="ios-xe"` raises): it now asserts that an unknown OS
  (`networkOSType="junos"`) raises `ValidationError` — preserving the "invalid discriminator rejected" intent.
- `tests/unit/module_utils/orchestrators/test_loopback_interface.py`: change the import (line 33) and construction (line 89) to `NexusLoopbackNetworkOSModel`.

- [ ] **Step 5: Run both suites to verify everything passes**

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py tests/unit/module_utils/orchestrators/test_loopback_interface.py`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/models/test_loopback_interface.py tests/unit/module_utils/orchestrators/test_loopback_interface.py
git commit -m "Split network_os into an outer discriminated union (nx-os | ios-xe)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: `XeLoopbackPolicyTypeEnum` + `query_all` filter union

**Files:**

- Modify: `plugins/module_utils/models/interfaces/enums.py` (append after `LoopbackPolicyTypeEnum`)
- Modify: `plugins/module_utils/orchestrators/loopback_interface.py` (import + `query_all` lines ~231-270 + module/method docstrings)
- Test: `tests/unit/module_utils/orchestrators/test_loopback_interface.py`
- Modify: `tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json`

**Interfaces:**

- Consumes: `LoopbackPolicyTypeEnum` (existing).
- Produces: `XeLoopbackPolicyTypeEnum` with members `IOS_XE_LOOPBACK`, `IOS_XE_LOOPBACK_SHUT_NOSHUT`, `IOS_XE_UNDERLAY_LOOPBACK`, `IOS_XE_INTERNAL_LOOPBACK`,
  `CSR_LOOPBACK`, `CSR_INT_LOOPBACK`, `CSR1KV_LOOPBACK`. `query_all` filter = union of both enums' values.

- [ ] **Step 1: Write the failing orchestrator test** (numbered convention; `query_all` block ends at `00760`, so use `00770`; fixture key
  `test_loopback_interface_00770a`)

The test mirrors `test_loopback_interface_00700` (query_all filter + `switchIp` enrichment) with a GET whose interface list contains one XE `iosXeLoopback`,
one XE `csrIntLoopback` (read-side name), one NX `loopback`, and one `userDefined`. Assert the first three survive the filter and the `userDefined` is
excluded. Copy the setup skeleton (ResponseGenerator/Sender/RestSend wiring and `_switches_to_query` arrangement) from `test_loopback_interface_00700` — same
fixture-envelope shape, new key `00770a` — and assert:

```python
    result = orchestrator.query_all()
    returned_policy_types = {item["configData"]["networkOS"]["policy"]["policyType"] for item in result}
    assert returned_policy_types == {"loopback", "iosXeLoopback", "csrIntLoopback"}
    assert all(item["switchIp"] == "192.168.12.150" for item in result)
```

Add the matching `test_loopback_interface_00770a` entry to `tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json`: duplicate the
`00700a`-series envelope (same `RETURN_CODE`/`METHOD`/`REQUEST_PATH`/`DATA` structure — verify against the existing entry before writing) and set the interface
list to the four interfaces above, each shaped like the existing loopback entries but with `"networkOSType": "ios-xe"` and the XE `policyType` for the two XE
items. Include a `TEST_NOTES` list stating the data is spec-derived pending the lab-verification task.

- [ ] **Step 2: Run to verify it fails**

Run: `ndpytest tests/unit/module_utils/orchestrators/test_loopback_interface.py -k 00770 -v`
Expected: FAIL — XE policy types are filtered out (assertion mismatch: only `{"loopback"}` survives).

- [ ] **Step 3: Implement enum + filter**

Append to `plugins/module_utils/models/interfaces/enums.py`:

```python
class XeLoopbackPolicyTypeEnum(str, Enum):
    """
    # Summary

    Managed IOS-XE loopback policy types owned by the `nd_interface_loopback` module. `userDefined` is intentionally excluded.

    `CSR_INT_LOOPBACK` is the READ-side alias of `CSR_LOOPBACK`: the ND 4.2.1 create-side discriminator enum says `csrLoopback`
    while the read-side enum says `csrIntLoopback`. Both are listed so read-path filtering (`query_all`) matches the wire.

    ## Raises

    None
    """

    IOS_XE_LOOPBACK = "iosXeLoopback"
    IOS_XE_LOOPBACK_SHUT_NOSHUT = "iosXeLoopbackShutNoshut"
    IOS_XE_UNDERLAY_LOOPBACK = "iosXeUnderlayLoopback"
    IOS_XE_INTERNAL_LOOPBACK = "iosXeInternalLoopback"
    CSR_LOOPBACK = "csrLoopback"
    CSR_INT_LOOPBACK = "csrIntLoopback"
    CSR1KV_LOOPBACK = "csr1kvLoopback"
```

In the orchestrator, import `XeLoopbackPolicyTypeEnum` alongside `LoopbackPolicyTypeEnum` and change the filter line in `query_all`:

```python
                managed_policy_types = {policy_type.value for policy_type in LoopbackPolicyTypeEnum} | {policy_type.value for policy_type in XeLoopbackPolicyTypeEnum}
```

Update the orchestrator module docstring (lines 20-21) and the `query_all` docstring (lines 233-242) to say the filter covers both NX-OS and IOS-XE managed
policy types, that `iosXeUnderlayLoopback` is user-creatable (unlike NX `underlayLoopback`), and that `userDefined`/system-provisioned types stay excluded.

- [ ] **Step 4: Run tests to verify they pass**

Run: `ndpytest tests/unit/module_utils/orchestrators/test_loopback_interface.py`
Expected: all PASS including `00770`.

- [ ] **Step 5: Commit**

```bash
git add plugins/module_utils/models/interfaces/enums.py plugins/module_utils/orchestrators/loopback_interface.py tests/unit/module_utils/orchestrators/test_loopback_interface.py tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json
git commit -m "query_all: include IOS-XE loopback policy types via XeLoopbackPolicyTypeEnum

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Module surface — argspec, DOCUMENTATION, EXAMPLES

**Files:**

- Modify: `plugins/module_utils/models/interfaces/loopback_interface.py` (`get_argument_spec`, lines ~282-329)
- Modify: `plugins/modules/nd_interface_loopback.py` (DOCUMENTATION lines 11-198, EXAMPLES lines 200-376)
- Test: `tests/unit/module_utils/models/test_loopback_interface.py` (the existing `get_argument_spec` test — locate with `grep -n "get_argument_spec"
  tests/unit/module_utils/models/test_loopback_interface.py`)

**Interfaces:**

- Consumes: model surface from Tasks 2-3 (flat option names: `secondary_ip`, `enable_pim`; nine `policy_type` choices; two `network_os_type` choices).
- Produces: the user-facing argspec/docs. Task 7's integration tasks use these option names verbatim.

- [ ] **Step 1: Extend the failing argspec test first**

In the existing `get_argument_spec` test add assertions:

```python
    policy_options = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    assert spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["network_os_type"]["choices"] == ["nx-os", "ios-xe"]
    assert policy_options["policy_type"]["choices"] == [
        "loopback",
        "ipfmLoopback",
        "mplsLoopback",
        "iosXeLoopback",
        "iosXeLoopbackShutNoshut",
        "iosXeUnderlayLoopback",
        "iosXeInternalLoopback",
        "csrLoopback",
        "csr1kvLoopback",
    ]
    assert policy_options["secondary_ip"] == {"type": "str"}
    assert policy_options["enable_pim"] == {"type": "bool"}
```

(Adapt the local variable names to the test's existing style; `spec` is the `get_argument_spec()` return value.)

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -k argument_spec -v`
Expected: FAIL on the choices assertions.

- [ ] **Step 2: Update `get_argument_spec`**

In `plugins/module_utils/models/interfaces/loopback_interface.py`:

- `network_os_type=dict(type="str", required=True, choices=["nx-os", "ios-xe"])`
- `policy_type=dict(type="str", required=True, choices=["loopback", "ipfmLoopback", "mplsLoopback", "iosXeLoopback", "iosXeLoopbackShutNoshut",
  "iosXeUnderlayLoopback", "iosXeInternalLoopback", "csrLoopback", "csr1kvLoopback"])`
- Add `secondary_ip=dict(type="str"),` and `enable_pim=dict(type="bool"),` after `secondary_ip_list`.

Run: `ndpytest tests/unit/module_utils/models/test_loopback_interface.py -k argument_spec -v` — PASS.

- [ ] **Step 3: Update DOCUMENTATION** in `plugins/modules/nd_interface_loopback.py`

- `network_os_type` (lines 58-65): choices become `[ nx-os, ios-xe ]`; replace the "ios-xe planned/unimplemented" note with "Use V(nx-os) for Nexus switches
  and V(ios-xe) for Catalyst/CSR IOS-XE devices."
- `policy_type` (lines 72-81): choices become the nine values from Step 2; add per-value guidance lines following the existing `Use V(...)` style:
  - `- Use V(iosXeLoopback) for a general-purpose IOS-XE loopback.`
  - `- Use V(iosXeLoopbackShutNoshut) to manage only the admin state of an IOS-XE loopback.`
  - `- Use V(iosXeUnderlayLoopback) for an IOS-XE underlay (NVE source) loopback.`
  - `- Use V(iosXeInternalLoopback) for an IOS-XE internal loopback (unvalidated ip/ipv6, PIM option).`
  - `- Use V(csrLoopback) for a CSR loopback. ND reads this policy back as C(csrIntLoopback); the module normalizes it.`
  - `- Use V(csr1kvLoopback) for a CSR1kv loopback (admin state and freeform config only).`
- Applicability sentences (exact replacements):
  - `admin_state`: "Applies to all policy_type values."
  - `ip`: "Applies to all policy_type values except C(iosXeLoopbackShutNoshut) and C(csr1kvLoopback)."
  - `description`: "Applies to all policy_type values except C(iosXeLoopbackShutNoshut) and C(csr1kvLoopback). Maximum length is 200 for C(iosXeLoopback) and
    C(iosXeInternalLoopback), 254 otherwise."
  - `extra_config`: "Applies to all policy_type values except C(iosXeLoopbackShutNoshut)."
  - `vrf` (line 108): "Applies when policy_type is C(loopback), C(ipfmLoopback), C(iosXeLoopback), C(iosXeInternalLoopback), or C(csrLoopback)."
  - `ipv6` (line 113): "Applies when policy_type is C(loopback) or C(iosXeInternalLoopback)."
- New suboptions (place after `secondary_ip_list`, same indentation/style):

```yaml
              secondary_ip:
                description:
                  - Secondary IP address of the NVE interface loopback.
                  - Applies when policy_type is C(iosXeUnderlayLoopback).
                type: str
              enable_pim:
                description:
                  - Enable PIM on the interface.
                  - Applies when policy_type is C(iosXeInternalLoopback).
                type: bool
```

- Notes section (lines 195-197): mention the six IOS-XE managed templates now covered and that `userDefined` remains excluded for both OSes.

- [ ] **Step 4: Update EXAMPLES** — append after the existing NX examples (all four states for `ios-xe`, per mikewiebe's standing guidance that EXAMPLES cover
  every supported state, plus one CSR merged example):

```yaml
- name: Merge an IOS-XE loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeLoopback
              admin_state: true
              ip: "10.200.100.1"
              description: "XE loopback100"
              vrf: blue
    state: merged

- name: Replace an IOS-XE loopback (full desired state)
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeLoopback
              admin_state: true
              ip: "10.200.100.2"
              description: "XE loopback100 replaced"
    state: replaced

- name: Override all managed loopbacks (mixed NX-OS and IOS-XE desired state)
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              admin_state: true
              ip: "10.100.100.1"
      - switch_ip: 192.168.2.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeLoopback
              admin_state: true
              ip: "10.200.100.1"
    state: overridden

- name: Delete an IOS-XE loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.1
        interface_name: loopback100
    state: deleted

- name: Merge a CSR loopback (ND reads this back as csrIntLoopback; the module normalizes)
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.2
        interface_name: loopback101
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: csrLoopback
              admin_state: true
              ip: "10.200.101.1"
    state: merged
```

- [ ] **Step 5: Sanity + full unit run**

Run: `ndtest --test validate-modules plugins/modules/nd_interface_loopback.py`
Expected: PASS (doc/argspec choices must match exactly).
Run: `ndpytest tests/unit/`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py plugins/modules/nd_interface_loopback.py tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Expose IOS-XE loopback policy types in argspec/DOCUMENTATION/EXAMPLES

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Lab verification — csr drift, injected keys, vault note, TODO marker

**REQUIRES LIVE LAB ACCESS** (the IOS-XE device; see the `nd-live-lab-and-raw-rest-probing` memory for the intent-only raw-REST technique — raw POST creates
intent only, nothing deploys). Coordinate with Allen for the XE switch IP/fabric before starting.

**Files:**

- Modify (potentially): `plugins/module_utils/models/interfaces/loopback_interface.py` (`CsrLoopbackPolicyModel`)
- Modify: `tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json` (`00770a` refresh from real GET)
- Create: vault note in `~/Obsidian/ND` via the bug-tracker conventions (outside this repo)

**Interfaces:**

- Consumes: `CsrLoopbackPolicyModel.normalize_csr_policy_type` (Task 2), fixture `00770a` (Task 4).
- Produces: lab-verified read handling; the `TODO(4.2.1)` slug referenced from the code comment.

- [ ] **Step 1: Probe.** Raw POST (intent-only) an `iosXeLoopback` and a `csrLoopback` loopback onto the XE switch; GET each back (per-interface GET and the
  list GET `query_all` uses).
- [ ] **Step 2: Record.** (a) the echoed `policyType` for the CSR branch (working assumption: `csrIntLoopback`); (b) every key ND injects into the XE `policy`
  object that is not in the read schema (the XE analogue of NX's `linkStateRoutingTag`).
- [ ] **Step 3: Vault note.** Write a bug-tracker vault note for the csr create/read name drift with a stable kebab-case `id` (proposal:
  `csr-loopback-read-name-drift`); additional notes for any injected-key discrepancies found.
- [ ] **Step 4: Marker.** Add above `normalize_csr_policy_type` in `CsrLoopbackPolicyModel`:

```python
    # TODO(4.2.1) csr-loopback-read-name-drift
    # Create-side discriminator is `csrLoopback` but ND echoes `csrIntLoopback` on the read path (lab-verified).
    # Both are accepted as the discriminator; reads normalize to the create-side name so idempotency comparison works.
```

(Use the actual slug from Step 3 if it differs.) If the wire instead echoes `csrLoopback`, DELETE the validator and the `"csrIntLoopback"` Literal member,
update `test_csr_loopback_normalizes_read_alias` to assert single-name behavior, remove `CSR_INT_LOOPBACK` from the enum, and record the finding in the vault
note instead.

- [ ] **Step 5: Refresh fixtures.** Replace the spec-derived interface objects in fixture key `test_loopback_interface_00770a` with sanitized copies of the
  real GET payloads; update its `TEST_NOTES`. If Step 2(b) found injected keys, extend `test_xe_from_response_tolerates_injected_policy_key` to use a real
  injected key name.
- [ ] **Step 6: Clean up the probe interfaces** (intent removal — nothing was deployed).
- [ ] **Step 7: Run + commit**

Run: `ndpytest tests/unit/module_utils/`
Expected: all PASS.

```bash
git add plugins/module_utils/models/interfaces/loopback_interface.py tests/unit/module_utils/fixtures/fixture_data/test_loopback_interface.json tests/unit/module_utils/models/test_loopback_interface.py
git commit -m "Lab-verify csr loopback read-name drift; refresh XE fixtures from wire

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Integration tasks for IOS-XE

**Files:**

- Modify: `tests/integration/targets/nd_interface_loopback/vars/main.yaml`
- Modify: `tests/integration/targets/nd_interface_loopback/tasks/main.yaml`
- Create: `tests/integration/targets/nd_interface_loopback/tasks/xe.yaml`

**Interfaces:**

- Consumes: module surface from Task 5 (option names `secondary_ip`, `enable_pim` unused here; `policy_type` values `iosXeLoopback`, `csrLoopback`).
- Produces: XE integration coverage gated on `nd_test_xe_switch_ip`.

- [ ] **Step 1: Vars.** Append to `vars/main.yaml` (IDs 105-107 from the reserved 100-109 range; XE switch vars have NO defaults — the gate skips XE tasks when
  unset):

```yaml
# IOS-XE coverage — set nd_test_xe_switch_ip (and optionally nd_test_xe_fabric_name)
# in inventory/extra-vars to enable; xe.yaml is skipped when unset.
test_xe_fabric_name: "{{ nd_test_xe_fabric_name | default(test_fabric_name) }}"

xe_loopback_105:
  switch_ip: "{{ nd_test_xe_switch_ip | default('') }}"
  interface_name: loopback105
  config_data:
    network_os:
      network_os_type: ios-xe
      policy:
        policy_type: iosXeLoopback
        admin_state: true
        ip: "10.100.105.1"
        description: "Ansible integration test loopback105"

xe_loopback_105_updated:
  switch_ip: "{{ nd_test_xe_switch_ip | default('') }}"
  interface_name: loopback105
  config_data:
    network_os:
      network_os_type: ios-xe
      policy:
        policy_type: iosXeLoopback
        admin_state: true
        ip: "10.100.105.2"
        description: "Updated loopback105 description"

xe_loopback_106:
  switch_ip: "{{ nd_test_xe_switch_ip | default('') }}"
  interface_name: loopback106
  config_data:
    network_os:
      network_os_type: ios-xe
      policy:
        policy_type: csrLoopback
        admin_state: true
        ip: "10.100.106.1"
```

- [ ] **Step 2: Gate.** In `tasks/main.yaml`, inside the existing `block`, after the `deleted.yaml` include add:

```yaml
    - name: Run IOS-XE loopback tests (requires nd_test_xe_switch_ip)
      ansible.builtin.include_tasks: xe.yaml
      when: nd_test_xe_switch_ip is defined
```

- [ ] **Step 3: XE task file.** Create `tasks/xe.yaml` covering all four states plus idempotency, mirroring the assertion style of the existing state files
  (register + `assert` on `changed`). Content outline with the same task style as `merged.yaml`:

1. Pre-clean: `state: deleted` for `xe_loopback_105`/`xe_loopback_106` (ignore result).
2. `state: merged` with `xe_loopback_105` + `xe_loopback_106` → assert `changed`.
3. Re-run same merged → assert `not changed` (idempotency; for `xe_loopback_106` this is the csr drift case — ND reads back `csrIntLoopback` and the model must
   normalize for the compare).
4. `state: replaced` with `xe_loopback_105_updated` → assert `changed`.
5. `state: overridden` with `loopback_100` (NX, from existing vars, using `test_switch_ip`) + `xe_loopback_105` → assert `changed`; this deliberately mixes
   NX-OS and XE managed loopbacks to prove cross-OS convergence in `query_all`. Only run the mixed override when `test_xe_fabric_name == test_fabric_name`
   (guard with `when:` on the task); otherwise override with XE-only config.
6. `state: deleted` for everything created (including NX `loopback_100` if the mixed override ran) → assert `changed`; re-run → assert `not changed`.

Use `fabric_name: "{{ test_xe_fabric_name }}"` throughout the XE tasks.

- [ ] **Step 4: Lint + run.**

Run: `ndlint tests/integration/targets/nd_interface_loopback/`
Expected: no findings.
Run the integration target against the lab (Allen's run; XE vars supplied via extra-vars).
Expected: all tasks pass, idempotency asserts hold — especially step 3's csr re-merge.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/targets/nd_interface_loopback/
git commit -m "Integration: IOS-XE loopback coverage gated on nd_test_xe_switch_ip

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Full verification sweep + push

**Files:** none new — verification only.

- [ ] **Step 1: Formatters/linters on every changed Python file**

```bash
ndblack --check plugins/module_utils/models/interfaces/loopback_interface.py plugins/module_utils/models/interfaces/enums.py plugins/module_utils/orchestrators/loopback_interface.py plugins/modules/nd_interface_loopback.py
ndisort --check-only plugins/module_utils/models/interfaces/loopback_interface.py plugins/module_utils/models/interfaces/enums.py plugins/module_utils/orchestrators/loopback_interface.py plugins/modules/nd_interface_loopback.py
ndpylint plugins/modules/nd_interface_loopback.py
ndpylint plugins/module_utils/models/interfaces/loopback_interface.py
ndpylint plugins/module_utils/orchestrators/loopback_interface.py
ndmypy plugins/module_utils/models/interfaces/loopback_interface.py
ndmypy plugins/module_utils/orchestrators/loopback_interface.py
```

Expected: clean (run `ndmypy` per-file, not per-dir — see the `ndmypy-pylint-import-fix-27-behavior` memory). Fix and re-run on any finding.

- [ ] **Step 2: Full unit + sanity**

```bash
ndpytest tests/unit/
ndtest --test validate-modules plugins/modules/nd_interface_loopback.py
```

Expected: all PASS.

- [ ] **Step 3: Markdown lint the spec/plan** (host-side `markdownlint` is fine per the `markdownlint-nd-dev-followup` memory)

```bash
markdownlint docs/superpowers/specs/2026-07-18-loopback-ios-xe-model-design.md docs/superpowers/plans/2026-07-18-loopback-ios-xe-model.md
```

Expected: no output.

- [ ] **Step 4: Push and update PR #403** — push the branch; edit the PR body's "Proposed Changes"/"Test Notes" to cover the XE addition (note: CI does not
  trigger on stacked PRs — cite the local verification per the `ansible-nd-ci-trigger-develop-only` memory). Do NOT retarget or un-draft; #403 stays a draft
  POC.

---

## Verification (end-to-end)

1. `ndpytest tests/unit/` — entire unit suite green.
2. `ndtest --test validate-modules plugins/modules/nd_interface_loopback.py` — doc/argspec agreement.
3. Integration target run against the live lab with `nd_test_xe_switch_ip` set — all four states + idempotency on a real XE device, csr drift exercised by the
   re-merge of `xe_loopback_106`.
4. `git log --oneline` shows one commit per task; PR #403 diff shows the XE addition stacked on the union commits.
