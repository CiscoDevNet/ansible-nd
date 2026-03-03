# Endpoint Design Analysis

Two approaches to modeling REST endpoints are compared below:

- **Current implementation** — files in `plugins/module_utils/ep/ep_api_v1_*.py`
- **Reviewer's proposal** — `plugins/module_utils/ep/alternate_endpoint_implementation.py`

## The Core Difference

**Current implementation** — one class per verb per resource:

```python
EpApiV1InfraAaaLocalUsersGet    # path + verb=GET
EpApiV1InfraAaaLocalUsersPost   # path + verb=POST
EpApiV1InfraAaaLocalUsersPut    # path + verb=PUT
EpApiV1InfraAaaLocalUsersDelete # path + verb=DELETE
```

**Reviewer's proposal** — one class per resource, all verbs:

```python
AaaLocalUsersEndpoint           # path + supported_verbs={GET,POST,PUT,DELETE}
```

## Reviewer's Proposal

### Advantages

- Fewer classes (1 instead of 4 for a resource with 4 verbs)
- "REST resource-centric" mental model — the resource is the concept, verbs are operations on it
- `supports(verb)` allows runtime guards:

  ```python
  if not ep.supports(HttpVerb.DELETE):
      raise ValueError("DELETE not supported")
  ```

### Disadvantages

- **No `verb` property** — the caller must supply the verb separately. The current implementation
  allows `rest_send.verb = ep.verb`. The reviewer's proposal requires `rest_send.verb = HttpVerb.GET`,
  decoupling the endpoint from its verb and re-introducing the possibility of a mismatch.

- **Uses plain `dataclass` instead of Pydantic** — loses `validate_assignment`, `min_length`,
  `max_length`, and the `pydantic_compat` fallback the codebase already relies on.

- **`supported_verbs` is only a guard, not a guarantee** — the type system does not prevent using
  an unsupported verb; it only allows a runtime check. The burden falls on the caller to remember
  to call `supports()`.

## Current Implementation

### Advantages

- **The verb is encoded in the type itself** — `EpApiV1InfraAaaLocalUsersDelete` cannot accidentally
  be used for a GET. The class name is self-documenting.

- **`rest_send.verb = ep.verb` is always correct by construction** — verb and path are bundled
  together, making mismatches impossible.

- **Pydantic validation** — field constraints (`min_length`, `max_length`, `validate_assignment`)
  are inherited throughout, catching bad inputs early.

- **`pydantic_compat.py` compatibility** — works in `ansible-test sanity` environments where
  Pydantic may be unavailable.

### Disadvantages

- More classes — verbose, though each is small, focused, and consistently named.
- Long class names — mitigated by the fact that names are descriptive and easily searchable.

## Summary

The reviewer optimizes for **fewer classes** and a resource-centric model. The current
implementation optimizes for **type safety** and **verb-path coupling**.

Given that this codebase already uses Pydantic validation, the `pydantic_compat` layer, and the
`rest_send.verb = ep.verb` usage pattern throughout, the current approach is more internally
consistent. The reviewer's proposal would require callers to both check `supports()` and
separately specify the verb — two responsibilities that the current design makes impossible to
get wrong.


Current

# The TYPE itself guarantees the verb
rest_send.verb = ep.verb  # Type checker KNOWS this is DELETE

Proposed

# The verb is NOW A FIELD, not part of the type
rest_send.verb = ep.verb  # This could be GET, POST, PUT, or DELETE
