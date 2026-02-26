# Type Safety Analysis: Endpoint Design

## Overview

This document expands on the type safety implications of the current endpoint implementation versus the reviewer's proposed inheritance-based approach.

## The Core Issue

**Current implementation** — one class per (resource + HTTP verb):
```python
EpApiV1InfraAaaLocalUsersGet      # path + verb=GET
EpApiV1InfraAaaLocalUsersPost     # path + verb=POST
EpApiV1InfraAaaLocalUsersPut      # path + verb=PUT
EpApiV1InfraAaaLocalUsersDelete   # path + verb=DELETE
```

**Proposed implementation** — one class per resource, verb is a field:
```python
AaaLocalUsersEndpoint(login_id="admin", verb=HttpVerbEnum.DELETE)
```

The difference is subtle but consequential for type safety.

---

## Current Implementation — Verb is Guaranteed by Type

### How It Works

```python
# The TYPE itself guarantees the verb
ep = EpApiV1InfraAaaLocalUsersDelete(login_id="admin")

# The verb and path are BUNDLED — they always match
rest_send.verb = ep.verb  # Type checker KNOWS this is DELETE
rest_send.path = ep.path  # Type checker KNOWS this matches DELETE semantics
```

### What the Type System Prevents

```python
# ✅ This is obviously correct
ep = EpApiV1InfraAaaLocalUsersDelete(login_id="admin")
rest_send.verb = ep.verb
rest_send.path = ep.path

# ❌ This is a compile-time error
# Can't instantiate the wrong verb class
ep = EpApiV1InfraAaaLocalUsersDelete(login_id="admin")
rest_send.verb = HttpVerbEnum.GET  # Type checker catches: DELETE class with GET verb
```

### Key Property: Bundling

The verb and path are **inseparable**. You can't have one without the other:
- If you have `EpApiV1InfraAaaLocalUsersDelete`, you must use `HttpVerbEnum.DELETE`
- If you want a GET request, you must instantiate `EpApiV1InfraAaaLocalUsersGet`

---

## Proposed Implementation — Verb is a Runtime Value

### How It Works

```python
# Verb is just a field, decoupled from the path
ep = AaaLocalUsersEndpoint(login_id="admin", verb=HttpVerbEnum.DELETE)

rest_send.verb = ep.verb  # Could be GET, POST, PUT, or DELETE
rest_send.path = ep.path  # Path is derived from login_id, independent of verb
```

### What Can Now Go Wrong

```python
# ❌ Verb defaults — but to what?
ep = AaaLocalUsersEndpoint(login_id="admin")
rest_send.verb = HttpVerbEnum.GET
rest_send.path = ep.path
# Did the endpoint support GET? Without checking supports(), you don't know

# ❌ Verb/path mismatch
ep = AaaLocalUsersEndpoint(login_id="admin", verb=HttpVerbEnum.DELETE)
rest_send.verb = HttpVerbEnum.GET  # Someone changed the verb!
rest_send.path = ep.path           # Path is still for DELETE semantics
# Path and verb are now mismatched, only caught at runtime

# ❌ Unsupported verb silently accepted
ep = AaaLocalUsersEndpoint(login_id="admin", verb=HttpVerbEnum.PATCH)
rest_send.verb = ep.verb
rest_send.path = ep.path
# PATCH isn't supported on this endpoint
# Only discovered when the API returns an error or 404
```

---

## Type System Guarantees — Comparison Table

| Scenario | Current | Proposed |
|----------|---------|----------|
| **Asking for wrong verb class** | ❌ Compile error — class doesn't exist | ✅ Runs fine, caught at runtime with `supports()` check |
| **Verb in `rest_send` mismatches endpoint intent** | ❌ Impossible — verb is part of the type | ✅ Possible — field can be changed after instantiation |
| **IDE autocomplete gives wrong options** | ❌ Only shows 4 correct classes (Get, Post, Put, Delete) | ✅ Shows all HttpVerbEnum values (many are unsupported) |
| **Reading code — what verb will be used?** | ✅ Obvious from class name `...Delete` | ❌ Must read code to see if verb was set and not overridden |
| **Forgetting runtime safety check** | ❌ Impossible — verb is part of type | ✅ Common mistake — easy to forget `supports()` check |
| **Field reassignment after instantiation** | ❌ Can't reassign `verb` (it's a property) | ✅ `verb` field can be modified at any point |

---

## Concrete Example: A Hard-to-Catch Bug

### With Current Approach — Impossible

```python
# Current: You choose the class, so verb is locked in by type
ep_get = EpApiV1InfraAaaLocalUsersGet(login_id="admin")
ep_delete = EpApiV1InfraAaaLocalUsersDelete(login_id="admin")

def send_request(endpoint: EndpointBase, rest_send: RestSend) -> None:
    rest_send.verb = endpoint.verb      # ALWAYS matches endpoint type
    rest_send.path = endpoint.path
    rest_send.send()

# Type system prevents this:
send_request(ep_delete, rest_send)  # Verb MUST be DELETE
send_request(ep_get, rest_send)     # Verb MUST be GET
# No way to accidentally send a GET with a Delete endpoint
```

### With Proposed Approach — Easy Bug

```python
# Proposed: Verb is just a field
ep = AaaLocalUsersEndpoint(login_id="admin", verb=HttpVerbEnum.DELETE)

def send_request(endpoint: AaaLocalUsersEndpoint, rest_send: RestSend) -> None:
    rest_send.verb = endpoint.verb
    rest_send.path = endpoint.path
    rest_send.send()

# But what if somewhere in the code path...
endpoint.verb = HttpVerbEnum.GET  # Oops! Someone reassigned it
# or in a different part:
rest_send.verb = HttpVerbEnum.GET  # Oops! Overridden after assignment

# The path is still derived for DELETE's semantics
# But verb is now GET
# Server gets confused, returns wrong data or error
```

---

## Static Type Checker Perspective

### Using mypy or Pyright

**Current approach:**

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from plugins.module_utils.ep.ep_api_v1_infra_aaa import EpApiV1InfraAaaLocalUsersDelete

def configure_delete(ep: "EpApiV1InfraAaaLocalUsersDelete", rest_send: RestSend) -> None:
    rest_send.verb = ep.verb  # Type checker: HttpVerbEnum.DELETE ✓
    rest_send.path = ep.path  # Type checker: str ✓

# Caller passes wrong class:
ep = EpApiV1InfraAaaLocalUsersGet(...)
configure_delete(ep, rest_send)
# ❌ mypy error: Argument 1 to "configure_delete" has incompatible type
#    "EpApiV1InfraAaaLocalUsersGet"; expected "EpApiV1InfraAaaLocalUsersDelete"
```

**Proposed approach:**

```python
def configure_delete(ep: AaaLocalUsersEndpoint, rest_send: RestSend) -> None:
    # Type checker can't verify ep.verb is actually DELETE
    # It's typed as HttpVerbEnum — could be any valid HTTP verb
    rest_send.verb = ep.verb  # Type checker: HttpVerbEnum (GET|POST|PUT|DELETE|PATCH)
    rest_send.path = ep.path  # Type checker: str ✓

# Caller passes endpoint with wrong verb:
ep = AaaLocalUsersEndpoint(login_id="admin", verb=HttpVerbEnum.GET)
configure_delete(ep, rest_send)
# ✅ No type error — type checker doesn't know this is wrong!
# The endpoint is the right type, so the call succeeds
# But verb/path mismatch is a semantic bug, not caught until runtime
```

---

## Why This Matters in Ansible Code

### Production Implications

Ansible modules often run unattended in production environments:

1. **Compile-time bugs are prevented before deployment**
   - Type checking happens during development
   - Mismatches are caught in the editor or CI pipeline

2. **Runtime bugs can fail mid-playbook**
   - A `supports()` check failure stops the module
   - But this happens after module execution has begun

3. **Silent bugs are catastrophic**
   - A verb/path mismatch that's neither caught at compile-time nor has a `supports()` guard
   - Results in wrong behavior: module thinks it deleted a resource, but actually queried it
   - The playbook completes "successfully" but the wrong action was taken

### Example Failure Scenario

```python
# Developer writes code to delete a user
ep = AaaLocalUsersEndpoint(login_id="admin", verb=HttpVerbEnum.DELETE)

# Later, someone refactors and accidentally changes the verb:
if some_condition:
    ep.verb = HttpVerbEnum.GET  # Oops! Wrong verb

rest_send.verb = ep.verb
rest_send.path = ep.path
result = rest_send.send()

# The API returns 200 OK with the user data
# Module thinks it successfully deleted the user
# Playbook reports success
# User is still there — silent failure

# With current approach, this is impossible:
# You'd need to instantiate EpApiV1InfraAaaLocalUsersDelete
# The verb is locked in by the class type
# You can't accidentally use GET
```

---

## The Cost/Benefit Tradeoff

### Cost of Current Approach

- **More class definitions** — 4 classes per endpoint (one per verb) instead of 1
- **More code** — each class has boilerplate (`@property def verb`, etc.)
- **More files** — endpoint definitions are spread across multiple classes
- **Harder to scan** — understanding all operations on a resource requires reading 4 class definitions

### Benefit of Current Approach

- **Verb is guaranteed by type** — type checker enforces verb/path coupling
- **Impossible to misuse** — can't instantiate wrong verb class for a resource
- **Self-documenting** — class names clearly indicate what verb will be used
- **No runtime checks needed** — `supports()` validation is unnecessary
- **IDE support** — autocomplete only shows valid verb classes
- **Fail-fast behavior** — mistakes caught before runtime

### Cost of Proposed Approach

- **Type safety reduced** — verb/path decoupling allows mismatches
- **Runtime checks required** — `supports()` calls must be remembered
- **Field reassignment risk** — verb can be changed after instantiation
- **Silent failures possible** — unsupported verbs only caught when API responds
- **Less self-documenting** — must read code to see what verb is being used

### Benefit of Proposed Approach

- **Fewer classes** — 1 class per endpoint instead of 4
- **Less boilerplate** — no per-verb property definitions
- **Resource-centric model** — aligns with REST thinking (resource + operation)
- **Smaller codebase** — fewer lines of code to maintain

---

## Design Tension

This is a classic tradeoff between:

| Dimension | Current | Proposed |
|-----------|---------|----------|
| **Type safety** | High (verb encoded in type) | Low (verb is runtime value) |
| **Conciseness** | Low (4 classes per endpoint) | High (1 class per endpoint) |
| **Fail-fast** | Compile-time errors | Runtime errors |
| **Self-documenting** | Yes (class name shows verb) | No (must check field) |
| **IDE support** | Excellent (autocomplete) | Adequate (shows all verbs) |

---

## Recommendation

### For a Production Ansible Collection

Prioritize **type safety** over conciseness because:

1. **Unattended execution** — Ansible playbooks run in production with minimal oversight
2. **Silent failures are unacceptable** — a typo in verb/path doesn't fail the playbook, it silently does the wrong thing
3. **Type checking is free** — catching bugs at compile-time before deployment is a major win
4. **Boilerplate cost is acceptable** — 4 classes per endpoint is verbose but small and focused

The extra classes are a small price for impossible-to-misuse endpoint definitions.

### If Conciseness is Critical

Consider a hybrid approach:

```python
# Base class handles all shared logic
class EndpointBase(BaseModel):
    @property
    def path(self) -> str:
        """Build path with query params — implemented by subclass"""

    def verb(self) -> HttpVerbEnum:
        """Must be implemented by subclass"""

# One class per endpoint (not per verb)
class AaaLocalUsersEndpoint(EndpointBase):
    login_id: Optional[str] = None
    endpoint_params: AaaLocalUsersParams = Field(default_factory=...)

    def get_base_path(self) -> str:
        if self.login_id:
            return BasePath.nd_infra_aaa(f"localUsers/{self.login_id}")
        return BasePath.nd_infra_aaa("localUsers")

# But create TYPE-SAFE factory functions
def aaa_local_users_get(login_id: Optional[str] = None) -> tuple[AaaLocalUsersEndpoint, HttpVerbEnum]:
    """Factory function for GET — return type guarantees verb"""
    ep = AaaLocalUsersEndpoint(login_id=login_id)
    return ep, HttpVerbEnum.GET

def aaa_local_users_delete(login_id: str) -> tuple[AaaLocalUsersEndpoint, HttpVerbEnum]:
    """Factory function for DELETE — return type guarantees verb"""
    ep = AaaLocalUsersEndpoint(login_id=login_id)
    return ep, HttpVerbEnum.DELETE

# Usage — type safety is preserved
ep, verb = aaa_local_users_delete("admin")
rest_send.verb = verb  # Type checker knows this is DELETE
rest_send.path = ep.path
```

This reduces class count while preserving type safety through factory functions.

---

## Summary

The current implementation trades boilerplate for safety. Each endpoint class (one per verb) is "expensive" to define but "cheap" to misuse — impossible, in fact. The proposed inheritance approach is cheaper to define but more expensive to use safely — it requires runtime checks and discipline from callers.

For a production Ansible collection, **type safety wins**.
