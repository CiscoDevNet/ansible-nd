# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared template-input validation helpers used by ``nd_manage_policy`` and
``nd_manage_policy_group``.

Both consumers POST/PUT a ``templateInputs`` dict to the ND controller as
part of a policy or policy-group payload.  The dict's allowed keys and
per-value types are defined by the named config template, retrieved at run
time via::

    GET /api/v1/manage/configTemplates/<templateName>/parameters

The three behaviours (fetch-with-cache, schema-based validation,
system-key strip) are exposed as pure-functional helpers so both
``nd_manage_policy`` and ``nd_manage_policy_group`` can share identical
validation semantics through a single code path without taking a
cross-module dependency on each other's internals.  Each consumer wires
the helper into its own request callable, cache dict and logger.

Design rules:

- **No hidden state.**  Caches are caller-owned dicts.  The helper never
  imports a module-level singleton.
- **No Pydantic dependency.**  Inputs are plain dicts so this module is
  trivially unit-testable without the orchestrator stack.
- **No I/O coupling.**  ``fetch_template_params`` accepts the request
  callable, endpoint factory, and (optional) record-call callback as
  arguments.  Callers wire their own ``NDModule.request`` / orchestrator
  ``_request`` / etc. plumbing.
- **Validation is a pure function.**  ``validate_template_inputs`` takes the
  template-name, the user-supplied inputs dict and the raw ``parameters``
  list returned by the GET; it returns a list of human-readable error
  strings.  Empty list == valid.  Caller decides how to surface
  (``fail_json``, 207-style aggregation, etc.).

Note on the IP / MAC regex patterns -- they are intentionally **shape-only**
(``\\d{1,3}`` per octet, no per-octet 0-255 enforcement).  The controller's
own validation is authoritative; this layer catches typos and structural
errors so the user gets a clear pre-flight message rather than a generic
HTTP 400.

Note on case folding -- ``parameterType`` values are matched after
``.lower()`` so the same logic accepts ``"Integer"``, ``"INTEGER"`` and
``"integer"`` interchangeably.
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

import logging
import re
from typing import Any, Callable

# =============================================================================
# Module-level pre-compiled regex patterns
# =============================================================================
#
# Shape-only validators for soft type-checks of user-supplied template inputs.
# Compiled once at import time to avoid repeated parsing cost in tight loops.
# ``_MAC_RE`` accepts both the dotted-quad form (``xxxx.xxxx.xxxx``) and the
# colon-separated form (``xx:xx:xx:xx:xx:xx``) via a single alternation.

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV4_SUBNET_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$|^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


# =============================================================================
# Endpoint import (default factory)
# =============================================================================
#
# Imported at module level to keep callers from having to thread the endpoint
# class through every call site.  The caller can still override via the
# ``endpoint_factory`` kwarg to ``fetch_template_params`` (used by unit tests).
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_config_templates import (
    EpManageConfigTemplateParametersGet,
)

# =============================================================================
# Public helpers
# =============================================================================


def fetch_template_params(
    template_name: str,
    request_fn: Callable[..., Any],
    cache: dict,
    *,
    endpoint_factory: Callable[[], Any] = EpManageConfigTemplateParametersGet,
    endpoint_modifier_fn: Callable[[Any], None] | None = None,
    record_call_fn: Callable[[Any, dict | None], None] | None = None,
    logger: logging.Logger | None = None,
) -> list[dict]:
    """Fetch (with cache) the parameter definitions for a config template.

    On cache miss, builds an ``EpManageConfigTemplateParametersGet`` endpoint
    (or whatever ``endpoint_factory`` produces), gives the caller an
    optional pre-request hook to mutate the endpoint (e.g. set
    ``endpoint_params.cluster_name`` / ``ticket_id``), records the call
    (if a ``record_call_fn`` is supplied), and issues the GET.

    Args:
        template_name: ND config-template name (e.g. ``"switch_freeform"``).
        request_fn:    Callable that performs the HTTP GET, signature
                       ``(path, verb) -> response`` -- typically
                       ``NDModule.request`` or an orchestrator's ``_request``.
        cache:         Caller-owned dict used to memoise results.  The helper
                       reads and writes ``cache[template_name]``; the cache
                       key is intentionally just the template name so a
                       plain ``dict[str, list[dict]]`` can be shared across
                       multiple call sites with no per-caller adaptation.
        endpoint_factory:   Zero-arg callable that returns a fresh endpoint
                            instance.  Defaults to
                            ``EpManageConfigTemplateParametersGet``.
        endpoint_modifier_fn:  Optional callback invoked as
                               ``endpoint_modifier_fn(ep)`` after
                               ``ep.template_name`` is set and before
                               ``record_call_fn`` / ``request_fn`` run.  Use
                               this to forward orchestrator parameters such
                               as ``cluster_name`` onto the endpoint's
                               ``endpoint_params`` model.
        record_call_fn:  Optional callback invoked as
                         ``record_call_fn(ep, None)`` immediately before the
                         GET.  Use this to thread the call into a
                         caller-side audit trail (e.g.
                         ``Results.{path,verb}_current`` on
                         ``NDPolicyModule``).  Pass ``None`` (default) when
                         the caller does not need an audit hook (e.g. the
                         policy-group orchestrator).
        logger:        Optional ``logging.Logger``.  When supplied, ENTER /
                       EXIT / cache-hit / fetch-count debug lines and a
                       WARNING on fetch failure are emitted.  Pass ``None``
                       for silent operation.

    Returns:
        List of parameter dicts as returned by the GET (or an empty list on
        any error / missing-parameters response).  Returned by reference --
        callers must NOT mutate the returned list; if mutation is needed,
        copy first.

    Failure handling:
        Any exception from ``request_fn`` is swallowed, an empty list is
        cached against ``template_name`` (so subsequent calls do not re-hit
        the broken endpoint), and an empty list is returned.  Rationale:
        the controller's own validation is authoritative; if we cannot
        fetch the schema we degrade gracefully to "trust the controller"
        rather than fail the task on a transient GET issue.

    Examples:
        Policy module style (with caller-side audit and instance cache)::

            params = fetch_template_params(
                "switch_freeform",
                request_fn=self.nd.request,
                cache=self._template_params_cache,
                record_call_fn=self._record_call,
                logger=self.log,
            )

        Policy-group orchestrator style (with multi-cluster ``cluster_name``)::

            def _set_cluster(ep):
                if orchestrator.cluster_name:
                    ep.endpoint_params.cluster_name = orchestrator.cluster_name

            params = fetch_template_params(
                "switch_freeform",
                request_fn=orchestrator._request,
                cache=template_param_cache,
                endpoint_modifier_fn=_set_cluster,
                logger=log,
            )
    """
    if logger is not None:
        logger.debug(f"ENTER: fetch_template_params(template_name={template_name})")

    if template_name in cache:
        if logger is not None:
            logger.debug(f"Template params cache hit for '{template_name}': " f"{len(cache[template_name])} params")
        return cache[template_name]

    ep = endpoint_factory()
    ep.template_name = template_name
    if endpoint_modifier_fn is not None:
        endpoint_modifier_fn(ep)

    try:
        if record_call_fn is not None:
            record_call_fn(ep, None)
        data = request_fn(ep.path, ep.verb)
    except Exception as exc:  # noqa: BLE001
        if logger is not None:
            logger.warning(f"Failed to fetch template '{template_name}' parameters: {exc}. " "Skipping template input validation.")
        cache[template_name] = []
        return []

    # The response is a templateData object with 'parameters' key.
    # 'parameters' is a list of templateParameter objects.
    params = data.get("parameters") if isinstance(data, dict) else []
    if params is None:
        params = []

    cache[template_name] = params
    if logger is not None:
        logger.info(f"Fetched {len(params)} parameter definitions for template '{template_name}'")
        logger.debug(f"Template '{template_name}' param names: " f"{[p.get('name') for p in params]}")
        logger.debug("EXIT: fetch_template_params()")
    return params


def validate_template_inputs(
    template_name: str,
    template_inputs: dict[str, Any],
    params: list[dict],
    *,
    logger: logging.Logger | None = None,
) -> list[str]:
    """Validate user-provided ``templateInputs`` against a template schema.

    Pure function -- does NOT fetch, mutate, or log at WARN/ERROR level on
    error.  Returns a list of human-readable error strings; empty list means
    all inputs are valid.  Caller decides how to surface (``fail_json``,
    accumulate into a 207-style report, etc.).

    Three checks are performed in order:

    1. **Unknown keys** -- every key in ``template_inputs`` must correspond
       to a parameter ``name`` in ``params``, OR be an internal parameter
       (``annotations.IsInternal == "true"``) that the controller
       auto-populates (e.g. ``SERIAL_NUMBER``, ``POLICY_ID``, ``SOURCE``,
       ``FABRIC_NAME``).  Internal parameters are accepted silently and are
       NOT advertised in the "Valid keys" suggestion list shown for unknown
       keys -- users should never need to set them.

    2. **Missing required parameters** -- every parameter where
       ``optional`` is ``False`` AND ``defaultValue`` is empty / null /
       whitespace-only must be supplied by the user.

    3. **Basic type validation** -- soft format checks for the parameter
       types ND defines for templates:

       - ``boolean``   -> accepts ``"true"`` / ``"false"`` (case-insensitive)
       - ``integer``   -> int-parseable
       - ``long``      -> int-parseable
       - ``float``     -> float-parseable
       - ``ipv4address`` / ``ipaddress``  -> dotted-quad shape
       - ``ipv4addresswithsubnet``        -> dotted-quad/prefix shape
       - ``macaddress``                   -> XXXX.XXXX.XXXX or XX:XX:XX:XX:XX:XX
       - ``enum``                         -> ``metaProperties.validValues``
                                             (comma-separated list)

       ``parameterType`` matching is case-insensitive (the source string is
       ``.lower()`` -ed before comparison) so ``"Integer"``, ``"INTEGER"``
       and ``"integer"`` are interchangeable.

       Values that are empty strings or whitespace-only are treated as "not
       set" and skip type validation.  This matters for the
       ``gathered -> merged`` roundtrip where the controller returns ``""``
       for unset optional parameters.

    Args:
        template_name:    Template name (used in error messages only).
        template_inputs:  User-supplied ``templateInputs`` dict.  May contain
                          keys that should be stripped first (the
                          ``SYSTEM_INJECTED_TEMPLATE_KEYS`` set) -- caller
                          should call ``strip_system_injected_keys`` before
                          this function for any input sourced from the
                          ``gathered`` flow.
        params:           Raw parameter list as returned by
                          ``fetch_template_params``.  Each entry is a dict
                          with at minimum ``name`` / ``parameterType`` /
                          ``optional`` / ``defaultValue`` / (optional)
                          ``annotations.IsInternal`` / (optional)
                          ``metaProperties.validValues``.
        logger:           Optional logger for ENTER / EXIT / pass / fail
                          debug lines.  When supplied a WARNING line is
                          emitted summarising the error count on failure.

    Returns:
        List of error message strings.  Empty list means valid.
    """
    if logger is not None:
        logger.debug(f"ENTER: validate_template_inputs(template={template_name}, " f"input_keys={list(template_inputs.keys())})")

    if not params:
        if logger is not None:
            logger.debug("No template params available, skipping validation")
        return []

    errors: list[str] = []

    # Build lookup: param_name -> param_def
    # Filter out internal parameters (annotations.IsInternal == "true")
    # that the controller auto-populates (e.g., SERIAL_NUMBER, POLICY_ID,
    # SOURCE, FABRIC_NAME). Users should never need to set these.
    param_map: dict[str, dict] = {}
    internal_names: set = set()
    for p in params:
        name = p.get("name")
        if not name:
            continue
        annotations = p.get("annotations") or {}
        if str(annotations.get("IsInternal", "")).lower() == "true":
            internal_names.add(name)
        else:
            param_map[name] = p

    if logger is not None:
        logger.debug(f"Template '{template_name}': {len(param_map)} user params, " f"{len(internal_names)} internal params ({sorted(internal_names)})")

    # ------------------------------------------------------------------
    # Check 1: Unknown keys (skip internal params -- they are allowed
    # but not advertised to users)
    # ------------------------------------------------------------------
    valid_names = set(param_map.keys()) | internal_names
    user_facing_names = set(param_map.keys())
    for user_key in template_inputs:
        if user_key not in valid_names:
            errors.append(f"Unknown templateInput key '{user_key}' for template " f"'{template_name}'. Valid keys: {sorted(user_facing_names)}")

    # ------------------------------------------------------------------
    # Check 2: Missing required parameters
    # ------------------------------------------------------------------
    for pname, pdef in param_map.items():
        is_optional = pdef.get("optional", True)
        default_val = pdef.get("defaultValue")
        has_default = default_val is not None and str(default_val).strip() != ""

        if not is_optional and not has_default and pname not in template_inputs:
            errors.append(f"Required templateInput '{pname}' (type={pdef.get('parameterType', '?')}) " f"is missing for template '{template_name}'")

    # ------------------------------------------------------------------
    # Check 3: Basic type validation (soft checks)
    # Empty strings are treated as "not set" -- the controller accepts
    # them for optional fields, so we skip validation for them.  This is
    # especially important for the gathered -> merged roundtrip where
    # the controller returns "" for unset optional parameters.
    # ------------------------------------------------------------------
    for user_key, user_val in template_inputs.items():
        pdef = param_map.get(user_key)
        if not pdef:
            continue  # Already flagged as unknown above

        ptype = (pdef.get("parameterType") or "").lower()
        val_str = str(user_val)

        # Skip type validation for empty/blank values -- they mean "not set"
        if val_str.strip() == "":
            continue

        if ptype == "boolean":
            if val_str.lower() not in ("true", "false"):
                errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects boolean (true/false), got '{val_str}'")

        elif ptype == "integer":
            try:
                int(val_str)
            except ValueError:
                errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects integer, got '{val_str}'")

        elif ptype == "long":
            try:
                int(val_str)
            except ValueError:
                errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects long integer, got '{val_str}'")

        elif ptype == "float":
            try:
                float(val_str)
            except ValueError:
                errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects float, got '{val_str}'")

        elif ptype in ("ipv4address", "ipaddress"):
            # Basic IPv4 shape check (per-octet 0-255 enforcement is the
            # controller's job)
            if not _IPV4_RE.match(val_str):
                errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects IPv4 address (e.g., 192.168.1.1), got '{val_str}'")

        elif ptype == "ipv4addresswithsubnet":
            if not _IPV4_SUBNET_RE.match(val_str):
                errors.append(
                    f"templateInput '{user_key}' for template '{template_name}' " f"expects IPv4 address with subnet (e.g., 192.168.1.1/24), got '{val_str}'"
                )

        elif ptype == "macaddress":
            if not _MAC_RE.match(val_str):
                errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects MAC address, got '{val_str}'")

        elif ptype == "enum":
            # If metaProperties contains 'validValues', check against them
            meta = pdef.get("metaProperties") or {}
            valid_values_str = meta.get("validValues")
            if valid_values_str:
                # validValues format is typically "val1,val2,val3"
                valid_values = [v.strip() for v in valid_values_str.split(",")]
                if val_str not in valid_values:
                    errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects one of {valid_values}, got '{val_str}'")

    if logger is not None:
        if errors:
            logger.warning(f"Template input validation found {len(errors)} errors " f"for template '{template_name}': {errors}")
        else:
            logger.debug(f"Template input validation passed for template '{template_name}'")
        logger.debug("EXIT: validate_template_inputs()")
    return errors


def strip_system_injected_keys(
    template_name: str,
    raw_inputs: dict[str, Any],
    system_keys,
    *,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Remove ND-injected control keys from a ``templateInputs`` dict.

    Strips keys in ``system_keys`` (a ``frozenset`` / ``set`` / any
    iterable supporting ``in``) and returns a new dict with everything
    else preserved.

    This is the canonical pre-step for the ``gathered -> merged`` roundtrip:
    the controller's GET response embeds keys such as ``POLICY_ID``,
    ``FABRIC_ID``, ``SERIAL_NUMBER`` etc. inside ``templateInputs``; replaying
    them as user-supplied input would (a) fail ``validate_template_inputs``
    with an "unknown key" error (since those keys are NOT in the template's
    ``parameters`` list except as ``IsInternal``-annotated entries that may
    or may not always be present), and (b) leak controller-internal state
    into the diff.

    Args:
        template_name:  Template name (for logging context only).
        raw_inputs:     ``templateInputs`` dict to clean (typically from a
                        ``gathered`` response).
        system_keys:    Iterable of key names to strip.  Pass
                        ``SYSTEM_INJECTED_TEMPLATE_KEYS`` from
                        ``module_utils.constants`` for canonical behaviour.
        logger:         Optional logger for ENTER / EXIT / stripped-keys
                        debug lines.

    Returns:
        New dict with the system-injected keys removed.  ``raw_inputs`` is
        not mutated.
    """
    if logger is not None:
        logger.debug(f"ENTER: strip_system_injected_keys(template={template_name}, " f"keys={list(raw_inputs.keys())})")

    cleaned: dict[str, Any] = {}
    stripped_keys: list[str] = []
    for k, v in raw_inputs.items():
        if k in system_keys:
            stripped_keys.append(k)
        else:
            cleaned[k] = v

    if logger is not None:
        if stripped_keys:
            logger.debug(f"Stripped {len(stripped_keys)} system-injected keys: " f"{sorted(stripped_keys)}")
        logger.debug(f"EXIT: strip_system_injected_keys() -> {len(cleaned)} keys " f"(removed {len(raw_inputs) - len(cleaned)})")
    return cleaned


__all__ = (
    "_IPV4_RE",
    "_IPV4_SUBNET_RE",
    "_MAC_RE",
    "fetch_template_params",
    "validate_template_inputs",
    "strip_system_injected_keys",
)
