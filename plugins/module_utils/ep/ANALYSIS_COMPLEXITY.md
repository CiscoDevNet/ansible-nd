# Complexity Analysis: Endpoint Designs

## Overview

This document provides a comprehensive complexity analysis comparing:

- **Current implementation** — files in `plugins/module_utils/ep/ep_api_v1_*.py`
- **Proposed alternative** — `plugins/module_utils/ep/alternate_endpoint_implementation.py`

Complexity is measured across cyclomatic complexity, structural overhead, inheritance depth, and cognitive load.

---

## Current Implementation Complexity

### Structural Metrics

**Lines of code (LoC) per endpoint:**

Using `ep_api_v1_infra_aaa.py` as example:

- **File total**: 207 lines
- **Per verb class**: ~50 lines (documentation + implementation)
- **Base class**: ~30 lines
- **Docstrings**: ~30 lines per class

**Class count for AAA LocalUsers endpoint:**

- 1 base class: `_EpApiV1InfraAaaLocalUsersBase`
- 4 verb classes: `Get`, `Post`, `Put`, `Delete`
- **Total**: 5 classes per endpoint resource

**Inheritance hierarchy:**

```
BaseModel (Pydantic)
  └─ LoginIdMixin
       └─ _EpApiV1InfraAaaLocalUsersBase
            ├─ EpApiV1InfraAaaLocalUsersGet
            ├─ EpApiV1InfraAaaLocalUsersPost
            ├─ EpApiV1InfraAaaLocalUsersPut
            └─ EpApiV1InfraAaaLocalUsersDelete
```

**Depth**: 4 levels (including Pydantic BaseModel)

### Cyclomatic Complexity

**Per class**:

- Base class `path` property: CC = 2 (one if statement)
- Verb classes `verb` property: CC = 1 (simple return)
- **Total per verb class**: CC ≤ 1

**File total**: CC ≈ 2 (dominated by base class path logic)

**Interpretation**: Extremely low cyclomatic complexity. Each class is trivial.

### Code Duplication

**Verb property implementations**:

```python
@property
def verb(self) -> HttpVerbEnum:
    """Return the HTTP verb for this endpoint."""
    return HttpVerbEnum.GET
```

Repeated 4 times with only the return value changing.

**Literal type fields**:

```python
class_name: Literal["EpApiV1InfraAaaLocalUsersGet"] = Field(default="...")
```

Repeated 4 times per endpoint.

**Duplication ratio**: ~15-20% of endpoint file consists of repeated patterns

### Complexity per Endpoint Type

#### Simple Endpoint (No Query Parameters)

`ep_api_v1_infra_aaa.py` — AAA LocalUsers:

- Minimal query parameter handling
- Single mixin (`LoginIdMixin`)
- Path logic: simple conditional on `login_id`

```
Complexity Score: LOW
- 5 classes
- CC = 2
- LoC = 207 for complete endpoint
```

#### Complex Endpoint (Multiple Query Parameters)

`ep_api_v1_manage_switches.py` — Switches:

- Multiple query parameter types
- Composite query parameter handling
- Path construction with query string assembly

```
Complexity Score: MEDIUM
- 1 endpoint class (no verb subclasses yet)
- CC = 2-3 (path construction + query string building)
- LoC = 166 for single verb
- Additional 55 lines for SwitchesEndpointParams class
```

`ep_api_v1_infra_clusterhealth.py` — ClusterHealth:

- Two separate endpoint classes (Config and Status)
- Two separate parameter classes
- Path construction with optional query string

```
Complexity Score: MEDIUM
- 2 endpoint classes (GET only)
- CC = 2 per endpoint (path + query string)
- LoC = 229 total
- Additional 81 lines for parameter classes
```

### Structural Complexity: Parameter Handling

When query parameters are involved, additional classes are created:

```
Current: SimpleEndpoint (no query params)
├─ Base path class
└─ Mixin class (LoginIdMixin)

Current: ComplexEndpoint (with query params)
├─ Base path class
├─ Mixin class (LoginIdMixin)
├─ Query parameter class (e.g., SwitchesEndpointParams)
└─ Lucene parameter class (LuceneQueryParams)
└─ Composite parameter class (CompositeQueryParams)
```

**Parameter class stack**: 3-4 classes per complex endpoint

**Total hierarchy**: 6-7 classes for a complex endpoint with all verbs

---

## Proposed Implementation Complexity

### Structural Metrics

**Lines of code per endpoint:**

Using `alternate_endpoint_implementation.py` as example:

- **File total**: 146 lines
- **Base class**: ~44 lines
- **Infra base class**: ~8 lines
- **Per concrete endpoint**: ~20 lines average
- **Docstrings**: ~10-20 lines per class

**Class count for AAA LocalUsers endpoint:**

- 1 base class: `Endpoint`
- 1 infra base class: `InfraEndpoint`
- 1 concrete class: `AaaLocalUsersEndpoint`
- **Total**: 3 classes per endpoint resource

**Inheritance hierarchy:**

```
Endpoint (ABC, dataclass)
  └─ InfraEndpoint
       └─ AaaLocalUsersEndpoint

ManageEndpoint
  └─ SwitchesEndpoint
```

**Depth**: 3 levels (ABC + one or two intermediate classes)

### Cyclomatic Complexity

**Per class**:

- `Endpoint.supports()`: CC = 1 (membership test)
- Concrete endpoint `resource_path`: CC = 1 (simple return or conditional)
- Concrete endpoint `path`: CC = 1-2 (base path + optional query string)
- `SwitchesEndpoint.path`: CC = 2-3 (complex query string building)

**File total**: CC ≈ 3-4 (higher than current due to consolidated logic)

**Interpretation**: Still low, but slightly higher than current due to consolidation

### Code Duplication

**Verb property implementations**:

None. The `supported_verbs` is a class variable:

```python
supported_verbs: ClassVar[Set[HttpVerb]] = {HttpVerb.GET, HttpVerb.POST}
```

**Mixin usage**:

Eliminated. Parameters are direct class fields.

**Duplication ratio**: ~5-10% (primarily docstrings)

### Complexity per Endpoint Type

#### Simple Endpoint (No Query Parameters)

`AaaLocalUsersEndpoint`:

```python
@dataclass
class AaaLocalUsersEndpoint(InfraEndpoint):
    supported_verbs: ClassVar[Set[HttpVerb]] = {HttpVerb.GET, HttpVerb.POST, HttpVerb.PUT, HttpVerb.DELETE}

    login_id: Optional[str] = None

    @property
    def resource_path(self) -> str:
        if self.login_id:
            return f"aaa/localUsers/{self.login_id}"
        return "aaa/localUsers"
```

```
Complexity Score: LOW
- 1 class
- CC = 1
- LoC = ~15
```

#### Complex Endpoint (Multiple Query Parameters)

`SwitchesEndpoint`:

```python
@dataclass
class SwitchesEndpoint(ManageEndpoint):
    supported_verbs: ClassVar[Set[HttpVerb]] = {HttpVerb.GET}

    fabric_name: Optional[str] = None
    switch_id: Optional[str] = None

    @property
    def resource_path(self) -> str:
        return "inventory/switches"

    @property
    def query_params(self) -> dict:
        return {k: v for k, v in {
            "fabricName": self.fabric_name,
            "switchId": self.switch_id,
        }.items() if v}

    @property
    def path(self) -> str:
        base = super().path
        if self.query_params:
            qs = "&".join(f"{k}={v}" for k, v in self.query_params.items())
            return f"{base}?{qs}"
        return base
```

```
Complexity Score: MEDIUM
- 1 class
- CC = 2-3 (query_params + path logic)
- LoC = ~28
```

**Observation**: Even complex endpoints stay within a single class

### Structural Complexity: Parameter Handling

No separate parameter classes in proposed design. Parameters are fields on the endpoint class:

```python
@dataclass
class SwitchesEndpoint(ManageEndpoint):
    fabric_name: Optional[str] = None
    switch_id: Optional[str] = None
```

**Total hierarchy**: 2-3 classes max (base + one/two intermediate + concrete)

---

## Comparative Analysis

### Metrics Comparison Table

| Metric | Current | Proposed | Winner |
|--------|---------|----------|--------|
| **Classes per simple endpoint** | 5 (base + 4 verbs) | 1 | Proposed |
| **Classes per complex endpoint** | 5-7 (with params) | 1-2 | Proposed |
| **Inheritance depth** | 4 levels | 3 levels | Proposed |
| **Cyclomatic complexity** | CC ≈ 2 | CC ≈ 3-4 | Current (marginally) |
| **Code duplication** | 15-20% | 5-10% | Proposed |
| **Verb class boilerplate per verb** | ~50 lines | N/A | Proposed |
| **Query param class overhead** | 3-4 classes | 0 classes | Proposed |

### Codebase Scale Analysis

#### Scaling to 50 Endpoints

**Current approach** (4 verbs per endpoint):

```
50 endpoints × 5 classes per endpoint = 250 classes
50 endpoints × 207 lines average = 10,350 lines
Plus shared parameter classes = ~2,000 additional lines
Total: ~12,350 lines
```

**Proposed approach** (distributed verbs):

```
50 endpoints × 1 class per endpoint = 50 classes
50 endpoints × 25 lines average = 1,250 lines
Plus shared base classes = ~200 additional lines
Total: ~1,450 lines
```

**Scaling ratio**: Current approach generates 8-9x more code

#### File Organization

**Current**: 3 files total (aaa, clusterhealth, switches)

**Proposed**: 1 file shown with many classes co-located

**File structure in current approach** scales poorly if each endpoint gets its own file:
- 50 endpoints × 4 verbs = 200 potential files (or very large files)

---

## Cognitive Complexity Analysis

### Developer Mental Model

#### Current Approach

**To use an endpoint:**

1. Know the resource name (e.g., `AaaLocalUsers`)
2. Know the HTTP verb needed (GET, POST, etc.)
3. Instantiate the correct class: `EpApiV1InfraAaaLocalUsersGet()`
4. Set parameters: `request.login_id = "admin"`
5. Read verb from class: `verb = request.verb` (type is known at step 3)
6. Read path from method: `path = request.path`

**Cognitive load**: MEDIUM

- Must remember verb classes exist (4 variants)
- Must choose correct variant (catches errors at import time)
- Type checker prevents wrong verb class
- **IDE autocomplete is HIGHLY EFFECTIVE**: Shows only available verb classes for the resource
  - Example: typing `EpApiV1InfraAaaLocalUsers` shows exactly 4 options: Get, Post, Put, Delete
  - No guessing — wrong verb class is simply unavailable
- Class name itself documents the verb

**To add a new parameter:**

1. Add field to base class
2. Update docstring
3. Update path property if needed
4. Changes apply to all 4 verb classes automatically

**Cognitive load**: LOW (4 verb classes inherit automatically)

#### Proposed Approach

**To use an endpoint:**

1. Know the resource name (e.g., `AaaLocalUsers`)
2. Instantiate: `AaaLocalUsersEndpoint(login_id="admin")`
3. **Check verb support** ← must know which verbs are supported!
   - Look at `supported_verbs: ClassVar[Set[HttpVerb]] = {...}`
   - Or remember from documentation
   - Or call `ep.supports(HttpVerb.GET)` as a guard
4. Set verb separately: `rest_send.verb = HttpVerb.GET`
5. Read path from method: `path = ep.path`

**Cognitive load**: HIGH (significantly increased)

- Single class to remember (✓ simpler)
- **BUT must know which verbs endpoint supports** (✗ new burden)
- **IDE autocomplete is INEFFECTIVE**: Shows all HttpVerb values regardless of endpoint
  - Example: `SwitchesEndpoint` only supports GET, but IDE shows GET, POST, PUT, DELETE, PATCH
  - Developer must know/check which are actually valid
  - Easy to accidentally use unsupported verb (only caught at runtime if `supports()` is checked)
- No obvious way to discover supported verbs from IDE alone
  - Must read source code to see `supported_verbs`
  - Or read documentation
  - Or try it and get runtime error
- **Verb/path coupling is invisible** — must either:
  - Check `supported_verbs` before using
  - Or call `ep.supports(verb)` as guard (easy to forget)
  - Or rely on documentation (documentation can be out of sync)

**To add a new parameter:**

1. Add field to endpoint class
2. Update query_params property if it affects URL
3. Changes apply to all verbs automatically (but now multiple verbs are supported!)
4. Must verify all supported verbs still work with new parameter

**Cognitive load**: MEDIUM-HIGH (one place to update, but must consider all supported verbs)

---

## Critical Issue: Verb Discovery in Proposed Approach

The proposed approach has a **documentation and discoverability problem**:

### How Does a Developer Know What Verbs Are Supported?

**Current approach:**

```python
# Simply try to import
from plugins.module_utils.ep.ep_api_v1_infra_aaa import (
    EpApiV1InfraAaaLocalUsersGet,      # ✓ Exists — GET is supported
    EpApiV1InfraAaaLocalUsersPost,     # ✓ Exists — POST is supported
    EpApiV1InfraAaaLocalUsersPatch,    # ✗ Import error — PATCH is NOT supported
)

# Or use IDE autocomplete
EpApiV1InfraAaaLocalUsers*  # Shows exactly 4 classes

# Verb is self-documenting in the class name
```

**Proposed approach:**

```python
# Create endpoint
ep = AaaLocalUsersEndpoint()

# How do I know what verbs are supported?
# Option 1: Look at source code
#   supported_verbs: ClassVar[Set[HttpVerb]] = {HttpVerb.GET, HttpVerb.POST, HttpVerb.PUT, HttpVerb.DELETE}

# Option 2: Check runtime
if ep.supports(HttpVerb.GET):
    # ... use GET
if ep.supports(HttpVerb.DELETE):
    # ... use DELETE
if ep.supports(HttpVerb.PATCH):  # Not supported, but how do I know?
    # ... use PATCH

# Option 3: Read documentation
# But documentation can become out of sync with code

# IDE autocomplete is USELESS for verb discovery
rest_send.verb = HttpVerb.*  # Shows 5+ verbs, but only 4 are valid!
```

### Documentation Burden

**Current approach:**

- Verb is part of the class name (self-documenting)
- No separate documentation needed
- IDE + class name = complete information

**Proposed approach:**

- Each endpoint class needs documentation listing supported verbs
- This documentation must be kept in sync with `supported_verbs` ClassVar
- Example docstring requirement:

```python
class AaaLocalUsersEndpoint(InfraEndpoint):
    """
    ND Infra AAA Local Users Endpoint

    ## Supported HTTP Verbs

    - GET: Retrieve local users (all or specific user if login_id is set)
    - POST: Create a new local user
    - PUT: Update an existing local user (requires login_id)
    - DELETE: Delete a local user (requires login_id)

    ## Parameters

    - login_id: Optional[str] — Login ID of specific user

    ## Usage

    ```python
    # Get all users
    ep = AaaLocalUsersEndpoint()
    if ep.supports(HttpVerb.GET):
        rest_send.verb = HttpVerb.GET
        rest_send.path = ep.path

    # Delete specific user
    ep = AaaLocalUsersEndpoint(login_id="admin")
    if ep.supports(HttpVerb.DELETE):
        rest_send.verb = HttpVerb.DELETE
        rest_send.path = ep.path
    ```
    """
```

- **Problem**: This documentation is not enforced by the type system
- **Problem**: If someone updates `supported_verbs` but forgets docstring, it falls out of sync
- **Problem**: Type checker doesn't verify docstring accuracy

### Typo/Discoverability Risk

**Current approach:**

```python
# Typo in class name
ep = EpApiV1InfraAaaLocalUsersGET()  # ✗ NameError: name not defined (caught immediately)
```

**Proposed approach:**

```python
ep = AaaLocalUsersEndpoint()
rest_send.verb = HttpVerbEnum.GET  # ✓ Spelled correctly (no way to be wrong)
rest_send.verb = HttpVerbEnum.PATCH  # ✓ Valid enum value, but endpoint doesn't support it
                                      # ✗ Runtime error only if ep.supports() is called
                                      # ✗ Silent failure if ep.supports() is forgotten
```

### Error-Proneness

#### Current Approach

**Possible errors:**

1. ❌ Import wrong verb class → **Type error at import time** (caught immediately)
2. ❌ Forget `supports()` check → Not applicable (verb is part of type)
3. ❌ Mismatch verb/path → Impossible (type guarantees match)
4. ❌ Use unsupported verb → **Impossible** (class doesn't exist)

**Error surface**: MINIMAL

**Example:**

```python
# Typo — this endpoint doesn't have a PATCH class
from plugins.module_utils.ep.ep_api_v1_infra_aaa import EpApiV1InfraAaaLocalUsersPatch
# ✗ NameError: name 'EpApiV1InfraAaaLocalUsersPatch' is not defined
#   Caught immediately at import time

# Wrong verb — verb classes only exist for supported operations
ep = EpApiV1InfraAaaLocalUsersDelete(login_id="admin")
rest_send.verb = ep.verb  # ✓ Always DELETE, type-safe
```

#### Proposed Approach

**Possible errors:**

1. ❌ Forget `supports()` check → **Silent failure** (wrong verb sent to API)
   - Developer doesn't call `ep.supports(HttpVerb.PATCH)` before using
   - Code runs successfully
   - API returns error or wrong result
   - Silent failure — code doesn't obviously break

2. ❌ Override verb after instantiation → **Silent failure** (verb/path mismatch)
   - `ep = AaaLocalUsersEndpoint(login_id="admin")`
   - `rest_send.verb = HttpVerb.GET  # Oops! Should be DELETE`
   - Type system doesn't catch this
   - Runtime error only if API validation is strict

3. ❌ Misunderstand which verbs are supported → **Runtime error**
   - Must check `supported_verbs` in source code
   - Or read documentation (out of sync risk)
   - Or discover at runtime

4. ❌ Use unsupported verb → **Not caught by type system**
   - `rest_send.verb = HttpVerb.PATCH` (valid enum value)
   - Endpoint only supports GET, but no compile-time error
   - Only caught if `ep.supports(HttpVerb.PATCH)` is called and checked

5. ❌ Documentation drift → **Serious maintenance burden**
   - `supported_verbs` ClassVar must match docstring
   - No enforcement — easy to update one and forget the other
   - New developers can't trust documentation

**Error surface**: LARGER and MORE SILENT

**Example:**

```python
# Developer intends to use GET, but forgets to check supported verbs
ep = SwitchesEndpoint(fabric_name="fabric1")
rest_send.verb = HttpVerb.DELETE  # ✗ Invalid! Switches endpoint only supports GET
rest_send.path = ep.path

# If ep.supports() check is NOT present:
#   - Code runs
#   - API returns 405 Method Not Allowed or 404 Not Found
#   - Developer has to debug by reading source code
#
# If ep.supports() check IS present:
#   - Still requires developer to remember to include it
#   - Easy to accidentally omit

# Better approach:
if ep.supports(HttpVerb.DELETE):  # ✓ This check must ALWAYS happen
    rest_send.verb = HttpVerb.DELETE
    rest_send.path = ep.path
else:
    # What now? Raise exception? Use GET instead? Depends on code context
    pass
```

**Cognitive load for error avoidance**: HIGH

- Developer must remember to check `supports()` every time
- Or trust documentation (fragile)
- Or discover errors via API responses (slow debugging)

### Testability Complexity

#### Current Approach

**Testing requirements:**

- Test each verb class separately (4 tests per endpoint)
- Each test verifies correct verb is returned
- Minimal setup per test

**Test overhead**: 4x tests per endpoint

#### Proposed Approach

**Testing requirements:**

- Test endpoint class once
- Verify `supports()` works correctly
- Verify path construction
- Verify query params if applicable

**Test overhead**: 1x test per endpoint (but might need multiple sub-tests for verbs)

---

## Complexity Summary by Dimension

### Code Volume

```
Current:   10,350 lines (50 endpoints)
Proposed:  1,450 lines (50 endpoints)
Reduction: 86% (8.6x smaller)
```

**Winner**: Proposed (dramatically)

### Class Count

```
Current:   250 classes (50 endpoints)
Proposed:  50 classes (50 endpoints)
Reduction: 80% (5x fewer classes)
```

**Winner**: Proposed (significant organizational simplification)

### Cyclomatic Complexity

```
Current:   CC ≈ 2 per endpoint
Proposed:  CC ≈ 3-4 per endpoint (consolidated)
```

**Winner**: Current (but difference is negligible — both under CC 5)

### Cognitive Load — Type Safety

```
Current:   Type system prevents verb mismatch
Proposed:  Runtime checks required (easy to forget)
```

**Winner**: Current (significantly safer)

### Cognitive Load — Verb Discovery

```
Current:   IDE autocomplete shows exactly which verbs are available
           Class name self-documents the verb
           No guessing or documentation needed

Proposed:  Developer must know/discover which verbs endpoint supports
           IDE autocomplete shows all HttpVerb values (misleading)
           Must check source code or documentation
           Documentation can drift out of sync
```

**Winner**: Current (verb discovery is trivial; proposed requires knowledge burden)

### Cognitive Load — Learning Curve

```
Current:   Must understand 4-verb pattern per endpoint
           But: verb discovery and usage is guided by IDE + type system

Proposed:  Must understand single class + supports() pattern
           But: verb discovery requires code reading or documentation
           And: must remember to call supports() check
           And: must remember which verbs are valid for each endpoint
```

**Winner**: Current (simpler and more self-guided)

### Cognitive Load — Parameter Addition

```
Current:   One place (base class, auto-inherited by all verbs)
Proposed:  One place (endpoint class)
```

**Winner**: Tie (identical)

### Scalability

```
Current:   Grows O(4n) where n = number of endpoints
Proposed:  Grows O(n) where n = number of endpoints
```

**Winner**: Proposed (linear growth vs quadratic)

---

## Analysis Interpretation

### Current Implementation Strengths

1. **Type safety uncompromised** — verb/path coupling enforced by type system
2. **Minimal cyclomatic complexity** — each class is trivial (~1-2 CC)
3. **IDE support excellent** — autocomplete shows only correct verb classes
4. **Impossible to misuse** — wrong verb class causes import-time error
5. **Self-documenting** — class name immediately reveals verb and resource

### Current Implementation Weaknesses

1. **Severe code duplication** — verb property repeated 4x per endpoint
2. **High class count** — 5 classes per simple endpoint is overhead
3. **Scales poorly** — 200+ files or massive files for 50 endpoints
4. **Parameter class overhead** — separate classes for query parameters
5. **Verbose boilerplate** — literal type fields, docstring repetition

### Proposed Implementation Strengths

1. **Minimal code volume** — 86% less code for same functionality
2. **Single class per endpoint** — far better organization
3. **Linear scaling** — O(n) growth, not O(4n)
4. **No parameter class overhead** — parameters are direct fields
5. **Simpler inheritance** — 3 levels vs 4

### Proposed Implementation Weaknesses

1. **Type safety reduced** — verb is runtime value, not enforced by type
2. **Runtime checks required** — must remember to call `supports()`
3. **Verb/path decoupling** — possible for verb and path to diverge
4. **Slightly higher CC** — consolidated logic has more branches
5. **IDE support degraded** — autocomplete shows all verbs, not just supported ones

---

## Recommendation Context

### For Type Safety Maximization

**Current approach wins decisively**

- Impossible-to-misuse design
- Every verb/path mismatch caught at type-check time
- Zero runtime checks needed
- Cost: ~8x code volume

### For Codebase Maintainability

**Proposed approach wins decisively**

- 86% less code
- Linear scaling vs quadratic
- Single class per endpoint vs 5
- Cost: Type safety reduced (mitigated by required `supports()` checks)

### For Production Ansible Collection

**Current approach is recommended** (from ANALYSIS_TYPE_SAFETY.md conclusion)

- Unattended execution = silent failures unacceptable
- Type system prevents silent failures
- Extra classes are a small price for impossible-to-misuse design
- Boilerplate cost is acceptable

---

## Conclusion

**Complexity Paradox:**

- **Structurally**, the proposed approach is dramatically simpler (86% less code, 5x fewer classes)
- **Semantically**, the current approach is vastly simpler (type system + IDE autocomplete + self-documenting)

The choice between them is not about absolute complexity, but about where complexity is incurred and accepted:

### Current Approach

**Accepts**: Structural overhead (5 classes per endpoint, 250 classes for 50 endpoints)

**Gains**:

- Type system prevents verb mismatch (impossible to choose wrong verb)
- IDE autocomplete is highly effective (shows only available verbs)
- Class name self-documents the verb (no guessing)
- Zero runtime checks needed (verb is guaranteed by type)
- No documentation drift risk (verb is part of the type definition)
- Error-proneness: MINIMAL (wrong choice caught at import time)

### Proposed Approach

**Accepts**:

1. Structural simplicity (1 class per endpoint, 50 classes for 50 endpoints)
2. **Cognitive burden**: Developer must remember which verbs each endpoint supports
3. **Documentation burden**: Must document supported verbs and keep in sync
4. **IDE limitation**: Autocomplete can't guide verb choice (shows all HttpVerb values)
5. **Runtime checks**: Must remember to call `ep.supports(verb)` check
6. **Error-proneness**: HIGHER (silent failures if checks are forgotten)

**Gains**:

- 86% less code
- 5x fewer classes
- Linear scaling instead of quadratic
- Simpler inheritance hierarchy

---

## Cognitive Load Assessment

The proposed approach has **HIGHER cognitive load** than the current approach:

| Dimension | Current | Proposed | Winner |
| --- | --- | --- | --- |
| **Discovering available verbs** | IDE shows all 4 options | Must read code/docs | Current |
| **Remembering supported verbs** | Class name encodes it | Must memorize per endpoint | Current |
| **IDE guidance** | Autocomplete is precise | Autocomplete is misleading | Current |
| **Documentation required** | None (type is docs) | Must document `supported_verbs` | Current |
| **Drift risk** | None (type enforced) | High (docstring can desync) | Current |
| **Runtime checks needed** | None | Every usage must call `supports()` | Current |
| **Learning curve** | Understand 4-verb pattern | Understand single-class + remember verbs | Current |

**Assessment**: Current approach has **significantly LOWER cognitive load**. The proposed approach introduces new, ongoing cognitive burdens around verb discovery and validation.

---

## Recommendation

For a **production Ansible collection**, the current approach is superior despite structural overhead because:

1. **Type safety is paramount** — Silent failures in production are unacceptable
2. **Cognitive burden is lower** — IDE + type system handle discovery
3. **Documentation drift is prevented** — Verb is part of the type definition
4. **Error-proneness is minimal** — Wrong choice caught at import/parse time
5. **Maintenance burden is lower** — No need to keep `supported_verbs` docs in sync with code
6. **Boilerplate cost is acceptable** — 5 classes is a small price for impossible-to-misuse design

The proposed approach trades structural complexity for semantic simplicity, but in production this creates new cognitive and maintenance burdens that outweigh the code reduction benefits.
