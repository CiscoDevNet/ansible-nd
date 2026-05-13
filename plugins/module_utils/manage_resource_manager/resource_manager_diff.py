# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_config_model import (
    ResourceManagerConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_response_model import ResourceManagerResponse
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_request_model import (
    FabricScope,
    DeviceScope,
    DeviceInterfaceScope,
    DevicePairScope,
    LinkScope,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.constants import (
    API_SCOPE_TYPE_TO_PLAYBOOK,
    POOL_SCOPE_MAP,
)

# =========================================================================
# Validation & Diff
# =========================================================================


class ResourceManagerDiffEngine:
    """Provide stateless validation and diff computation helpers."""

    @staticmethod
    def _normalize_pool_name(pool_name: str, log: logging.Logger) -> str | None:
        """Normalize pool_name to canonical constant form based on ``POOL_SCOPE_MAP`` keys.

        Converts API-style names like ``loopbackId`` to playbook constant names like
        ``LOOPBACK_ID`` when a token-equivalent key exists in ``POOL_SCOPE_MAP``.

        Args:
            pool_name: Raw pool name from config or API.
            log: Logger instance.

        Returns:
            Canonical pool constant when recognized, otherwise the stripped input value.
        """
        if pool_name is None:
            log.debug("_normalize_pool_name: pool_name is None, returning None")
            return None

        raw = str(pool_name).strip()
        if not raw:
            log.debug("_normalize_pool_name: pool_name stripped to empty string, returning ''")
            return raw

        token = "".join(ch.lower() for ch in raw if ch.isalnum())
        if not token:
            log.debug(
                "_normalize_pool_name: no alphanumeric chars in pool_name='%s', returning raw='%s'",
                pool_name,
                raw,
            )
            return raw

        canonical_by_token = {"".join(ch.lower() for ch in key if ch.isalnum()): key for key in POOL_SCOPE_MAP}
        result = canonical_by_token.get(token, raw)
        if result != raw:
            log.debug(
                "_normalize_pool_name: pool_name='%s' normalized to canonical='%s' (token='%s')",
                pool_name,
                result,
                token,
            )
        else:
            log.debug(
                "_normalize_pool_name: pool_name='%s' not found in POOL_SCOPE_MAP by token='%s', returning raw='%s'",
                pool_name,
                token,
                raw,
            )
        log.debug("Returning normalized pool_name='%s' from raw='%s' ", result, raw)
        return result

    @staticmethod
    def _normalize_entity_key(entity_name: str, log: logging.Logger) -> str:
        """Normalize entity_name for order-insensitive comparison.

        Args:
            entity_name: Raw entity name string.
            log: Logger instance.

        Returns:
            Tilde-separated string with parts sorted alphabetically.
        """
        normalize_entity_name = "~".join(sorted(entity_name.split("~")))
        log.debug("Returning normalized entity_name='%s' from raw='%s'", normalize_entity_name, entity_name)
        return normalize_entity_name

    @staticmethod
    def _resource_attr(resource, model_attr: str, dict_key: str | None = None):
        """Return a field from either a ResourceManagerResponse model or raw API dict."""
        if hasattr(resource, model_attr):
            return getattr(resource, model_attr)
        if isinstance(resource, dict):
            return resource.get(dict_key or model_attr)
        return None

    @staticmethod
    def _scope_details(resource):
        """Return scope details from either a model resource or raw API dict."""
        if hasattr(resource, "scope_details"):
            return getattr(resource, "scope_details", None)
        if isinstance(resource, dict):
            return resource.get("scopeDetails")
        return None

    @staticmethod
    def _dict_scope_key(attr_name: str) -> str:
        """Convert a snake_case scope attribute name to the ND API camelCase key."""
        parts = attr_name.split("_")
        return parts[0] + "".join(part.title() for part in parts[1:])

    @staticmethod
    def _extract_scope_switch_key_val(scope_details, switch_key, src_switch_key, log: logging.Logger) -> str | None:
        """Extract a switch identifier from a scope_details model using the correct attribute name.

        Selects between ``switch_key`` (for single-switch scopes: device, device_interface)
        and ``src_switch_key`` (for dual-switch scopes: device_pair, link).  Returns None
        for fabric-scoped resources which carry no switch identity.

        Args:
            scope_details: A scope model instance (FabricScope, DeviceScope,
                DeviceInterfaceScope, DevicePairScope, LinkScope) or None.
            switch_key: Attribute name to read for single-switch scopes
                (e.g. ``'switch_id'`` or ``'switch_ip'``).
            src_switch_key: Attribute name to read for dual-switch scopes
                (e.g. ``'src_switch_id'`` or ``'src_switch_ip'``).
            log: Logger instance.

        Returns:
            The switch identifier string, or None if the scope is fabric-level
            or ``scope_details`` is None.
        """
        if scope_details is None:
            log.debug("_extract_scope_switch_key_val: scope_details is None, returning None")
            return None
        if isinstance(scope_details, dict):
            scope_type = scope_details.get("scopeType")
            if scope_type == "fabric":
                log.debug("_extract_scope_switch_key_val: fabric scope dict has no switch identity, returning None")
                return None
            switch_dict_key = ResourceManagerDiffEngine._dict_scope_key(switch_key)
            src_switch_dict_key = ResourceManagerDiffEngine._dict_scope_key(src_switch_key)
            if scope_type in ("device", "deviceInterface"):
                value = scope_details.get(switch_dict_key)
                log.debug("_extract_scope_switch_key_val: dict %s scope, %s='%s'", scope_type, switch_dict_key, value)
                return value
            if scope_type in ("devicePair", "link"):
                value = scope_details.get(src_switch_dict_key)
                log.debug("_extract_scope_switch_key_val: dict %s scope, %s='%s'", scope_type, src_switch_dict_key, value)
                return value
            value = scope_details.get(switch_dict_key) or scope_details.get(src_switch_dict_key)
            log.debug("_extract_scope_switch_key_val: unknown dict scope type %s, fallback value='%s'", scope_type, value)
            return value
        if isinstance(scope_details, FabricScope):
            log.debug("_extract_scope_switch_key_val: FabricScope has no switch identity, returning None")
            return None
        if isinstance(scope_details, (DeviceScope, DeviceInterfaceScope)):
            value = getattr(scope_details, switch_key, None)
            log.debug("_extract_scope_switch_key_val: %s scope, %s='%s'", type(scope_details).__name__, switch_key, value)
            return value
        if isinstance(scope_details, (DevicePairScope, LinkScope)):
            value = getattr(scope_details, src_switch_key, None)
            log.debug("_extract_scope_switch_key_val: %s scope, %s='%s'", type(scope_details).__name__, src_switch_key, value)
            return value
        # Fallback: try common attribute names
        value = getattr(scope_details, switch_key, None) or getattr(scope_details, src_switch_key, None)
        log.debug("_extract_scope_switch_key_val: unknown scope type %s, fallback value='%s'", type(scope_details).__name__, value)
        return value

    @staticmethod
    def _extract_scope_type(scope_details, log: logging.Logger) -> str | None:
        """Extract and map the playbook-style scope_type from a scope_details model.

        Args:
            scope_details: A scope model instance.
            log: Logger instance.

        Returns:
            Playbook-style scope_type string (e.g. 'device_interface'), or None.
        """
        if scope_details is None:
            log.debug("_extract_scope_type: scope_details is None, returning None")
            return None
        if isinstance(scope_details, dict):
            raw = scope_details.get("scopeType")
        else:
            raw = getattr(scope_details, "scope_type", None)
        if not raw:
            log.debug("_extract_scope_type: no scope_type attribute on %s, returning None", type(scope_details).__name__)
            return None
        mapped = API_SCOPE_TYPE_TO_PLAYBOOK.get(raw, raw)
        log.debug("_extract_scope_type: raw='%s' mapped to '%s'", raw, mapped)
        return mapped

    @staticmethod
    def _compare_resource_values(have: str, want: str, log: logging.Logger) -> bool:
        """Compare resource values with IPv4/IPv6 network awareness.

        Args:
            have: Existing resource value from the API.
            want: Proposed resource value from the playbook.
            log: Logger instance

        Returns:
            True if the values are functionally equivalent, False otherwise.
        """
        if have is None and want is None:
            log.debug("_compare_resource_values: both have and want are None, returning True")
            return True
        if have is None or want is None:
            log.debug("_compare_resource_values: one of have or want is None (have=%s, want=%s), returning False", have, want)
            return False

        have = str(have).strip()
        want = str(want).strip()

        def _classify(val):
            if "/" in val:
                try:
                    parsed = ipaddress.ip_network(val, strict=False)
                    log.debug("_compare_resource_values: classified '%s' as network: %s", val, parsed)
                    return "network", parsed
                except ValueError:
                    log.debug("_compare_resource_values: failed to parse '%s' as network, continuing", val)
            try:
                parsed = ipaddress.ip_address(val)
                log.debug("_compare_resource_values: classified '%s' as address: %s", val, parsed)
                return "address", parsed
            except ValueError:
                log.debug("_compare_resource_values: failed to parse '%s' as address, classifying as raw", val)
                log.debug("_compare_resource_values: classified '%s' as raw string", val)
            return "raw", val

        th, vh = _classify(have)
        tw, vw = _classify(want)

        if th == tw == "address":
            result = vh.exploded == vw.exploded
            log.debug("_compare_resource_values: both are addresses (have=%s, want=%s), exploded comparison result=%s", vh.exploded, vw.exploded, result)
            return result
        if th == tw == "network":
            result = vh == vw
            log.debug("_compare_resource_values: both are networks (have=%s, want=%s), comparison result=%s", vh, vw, result)
            return result
        result = have == want
        log.debug("_compare_resource_values: raw string comparison (have='%s', want='%s'), result=%s", have, want, result)
        return result

    @staticmethod
    def _make_resource_key(
        entity_name: str | None,
        pool_name: str | None,
        scope_type: str | None,
        switch_ip: str | None,
        log: logging.Logger,
    ) -> tuple:
        """Build a normalized deduplication key for a resource entry.

        Args:
            entity_name: Resource entity name (will be tilde-normalized).
            pool_name: Pool name.
            scope_type: Playbook-style scope type.
            switch_ip: Switch IP, or None for fabric-scoped resources.
            log: Logger instance.

        Returns:
            Tuple used as a dict key for matching proposed vs existing.
        """
        norm_entity = ResourceManagerDiffEngine._normalize_entity_key(entity_name, log=log) if entity_name else None
        log.debug("_make_resource_key: entity_name provided %s, normalized to '%s'", entity_name, norm_entity)

        norm_pool = ResourceManagerDiffEngine._normalize_pool_name(pool_name, log=log)
        log.debug("_make_resource_key: pool_name='%s' normalized to '%s'", pool_name, norm_pool)

        # device_pair and link encode both endpoints in entity_name;
        # normalize switch to None so existing_index and proposed lookups align.
        if scope_type in ("device_pair", "link"):
            norm_switch = None
            log.debug("_make_resource_key: scope_type='%s' is multi-endpoint, setting norm_switch=None (original switch_ip='%s')", scope_type, switch_ip)
        else:
            norm_switch = switch_ip
            log.debug("_make_resource_key: scope_type='%s' is single-endpoint, keeping norm_switch='%s'", scope_type, norm_switch)

        key = (norm_entity, norm_pool, scope_type, norm_switch)
        log.debug(
            "_make_resource_key: built key=%s from entity_name='%s', pool_name='%s', scope_type='%s', switch_ip='%s'",
            key,
            entity_name,
            pool_name,
            scope_type,
            switch_ip,
        )

        return key

    @staticmethod
    def validate_configs(
        config: dict[str, Any] | list[dict[str, Any]],
        state: str,
        log: logging.Logger,
    ) -> list[ResourceManagerConfigModel]:
        """Validate raw module config and return typed resource configurations.

        Args:
            config: Raw config dict or list of dicts from module parameters.
            state: Requested module state.
            log: Logger instance.

        Returns:
            list of validated ``ResourceManagerConfigModel`` objects.
        """
        log.debug("ENTER: validate_configs()")

        configs_list = config if isinstance(config, list) else [config]
        log.debug("Normalized to %s configuration(s)", len(configs_list))

        validated_configs: list[ResourceManagerConfigModel] = []
        for idx, cfg in enumerate(configs_list):
            try:
                validated = ResourceManagerConfigModel.model_validate(cfg, context={"state": state})
                validated_configs.append(validated)
            except ValidationError as e:
                error_detail = e.errors() if hasattr(e, "errors") else str(e)
                error_msg = f"Configuration validation failed for config index {idx}: {error_detail}"
                log.error(error_msg)
                raise ValueError(error_msg) from e
            except Exception as e:
                error_msg = f"Configuration validation failed for config index {idx}: {str(e)}"
                log.error(error_msg)
                raise ValueError(error_msg) from e

        if not validated_configs:
            log.warning("No valid configurations found in input")
            return validated_configs

        # Duplicate check: (entity_name, pool_name, scope_type, frozenset(switch))
        seen_keys: set = set()
        duplicate_keys: set = set()
        log.debug(
            "validate_configs: starting duplicate check on %s validated config(s)",
            len(validated_configs),
        )
        for cfg_dup_idx, cfg in enumerate(validated_configs):
            key = (
                cfg.entity_name,
                cfg.pool_name,
                cfg.scope_type,
                frozenset(cfg.switches or []),
            )
            log.debug(
                "validate_configs: duplicate-check [%s] — entity_name='%s', pool_name='%s', scope_type='%s', switches=%s, key_seen_before=%s",
                cfg_dup_idx,
                cfg.entity_name,
                cfg.pool_name,
                cfg.scope_type,
                list(cfg.switches or []),
                key in seen_keys,
            )
            if key in seen_keys:
                log.warning(
                    "validate_configs: [%s] duplicate key detected — entity_name='%s', pool_name='%s', scope_type='%s'",
                    cfg_dup_idx,
                    cfg.entity_name,
                    cfg.pool_name,
                    cfg.scope_type,
                )
                duplicate_keys.add(key)
            else:
                log.debug(
                    "validate_configs: [%s] key is unique so far — entity_name='%s'",
                    cfg_dup_idx,
                    cfg.entity_name,
                )
            seen_keys.add(key)

        if duplicate_keys:
            error_msg = f"Duplicate config entries found: {[str(k) for k in duplicate_keys]}. Each resource must appear only once."
            log.error(error_msg)
            raise ValueError(error_msg)

        log.info(
            "Successfully validated %s configuration(s)",
            len(validated_configs),
        )
        log.debug("EXIT: validate_configs() -> %s configs", len(validated_configs))
        return validated_configs

    @staticmethod
    def compute_changes(
        proposed: list[ResourceManagerConfigModel],
        existing: list[ResourceManagerResponse],
        log: logging.Logger,
    ) -> dict[str, list]:
        """Compare proposed and existing resources and categorize changes.

        Uses ``ResourceManagerResponse`` fields (``entity_name``, ``pool_name``,
        ``scope_details``, ``resource_value``) to build a matching index and
        classify each proposed entry.

        Args:
            proposed: Validated ``ResourceManagerConfigModel`` objects
                representing desired state.
            existing: ``ResourceManagerResponse`` models from the ND API
                representing current state.
            log: Logger instance.

        Returns:
            dict mapping change buckets to item lists:
              - ``to_add``:     ``(ResourceManagerConfigModel, switch_ip)`` tuples
              - ``to_update``:  ``(ResourceManagerConfigModel, switch_ip)`` tuples
              - ``to_delete``:  ``ResourceManagerResponse`` items
              - ``idempotent``: ``(ResourceManagerConfigModel, switch_ip)`` tuples
        """
        log.debug("ENTER: compute_changes()")
        log.debug(
            "Comparing %s proposed vs %s existing resources",
            len(proposed),
            len(existing),
        )

        # Build index of existing resources keyed by
        # (normalized_entity, pool_name, playbook_scope_type, switch_id)
        existing_index: dict[tuple, ResourceManagerResponse] = {}
        for res in existing:
            entity = ResourceManagerDiffEngine._resource_attr(res, "entity_name", "entityName")
            pool = ResourceManagerDiffEngine._resource_attr(res, "pool_name", "poolName")
            scope_details = ResourceManagerDiffEngine._scope_details(res)
            scope_type = ResourceManagerDiffEngine._extract_scope_type(scope_details, log=log)
            switch_id = ResourceManagerDiffEngine._extract_scope_switch_key_val(scope_details, switch_key="switch_id", src_switch_key="src_switch_id", log=log)
            key = ResourceManagerDiffEngine._make_resource_key(entity, pool, scope_type, switch_id, log=log)
            existing_index[key] = res
            log.debug(
                "Existing index entry: entity=%s, pool=%s, scope_type=%s, switch_id=%s",
                entity,
                pool,
                scope_type,
                switch_id,
            )

        log.debug("Built existing index with %s entries", len(existing_index))

        changes: dict[str, list] = {
            "to_add": [],
            "to_update": [],
            "to_delete": [],
            "idempotent": [],
            "debugs": [],
        }

        # Build a secondary index keyed by normalised entity_name only.
        # Used to detect partial matches (same entity, different pool/scope/switch)
        # and populate the debugs bucket to mirror ND's mismatch logging.
        entity_only_index: dict[str, list[ResourceManagerResponse]] = {}
        for res in existing:
            entity_name = ResourceManagerDiffEngine._resource_attr(res, "entity_name", "entityName") or ""
            norm = ResourceManagerDiffEngine._normalize_entity_key(entity_name, log=log)
            entity_only_index.setdefault(norm, []).append(res)
            log.debug(
                "entity_only_index: added entity='%s' under norm_key='%s' (total under key: %s)",
                entity_name,
                norm,
                len(entity_only_index[norm]),
            )

        log.debug("Built entity_only_index with %s unique normalised key(s)", len(entity_only_index))

        # Track which existing keys matched at least one proposed entry
        matched_existing_keys: set = set()
        # Track partial-match diagnostics already emitted to avoid duplicates.
        seen_mismatch_keys: set = set()

        # Categorise proposed resources
        for cfg in proposed:
            scope_type = cfg.scope_type
            pool_name = cfg.pool_name
            entity_name = cfg.entity_name
            resource_value = cfg.resource

            log.debug(
                "Processing proposed cfg: entity=%s, pool=%s, scope=%s, resource=%s, switches=%s",
                entity_name,
                pool_name,
                scope_type,
                resource_value,
                cfg.switches,
            )

            # device_pair and link encode both endpoints in entity_name; one lookup covers the pair.
            if scope_type in ("device_pair", "link"):
                switches = [None]
                log.debug(
                    "scope_type='%s' is multi-endpoint — using single switch=None lookup for entity='%s'",
                    scope_type,
                    entity_name,
                )
            else:
                switches = cfg.switches if (scope_type != "fabric" and cfg.switches) else [None]
                log.debug(
                    "scope_type='%s' — resolved switches=%s for entity='%s'",
                    scope_type,
                    switches,
                    entity_name,
                )

            for sw in switches:
                key = ResourceManagerDiffEngine._make_resource_key(entity_name, pool_name, scope_type, sw, log=log)
                log.debug(
                    "Lookup key=%s for entity='%s', pool='%s', scope='%s', switch=%s",
                    key,
                    entity_name,
                    pool_name,
                    scope_type,
                    sw,
                )
                existing_res = existing_index.get(key)

                if existing_res is None:
                    log.info(
                        "Resource (entity=%s, pool=%s, scope=%s, switch=%s) not found in existing — marking to_add",
                        entity_name,
                        pool_name,
                        scope_type,
                        sw,
                    )
                    changes["to_add"].append((cfg, sw, None))

                    # GAP-7: Partial-match detection — same entity_name, different
                    # pool_name / scope_type / switch_ip.  Mirrors ND's
                    # nd_rm_get_mismatched_values() / changed_dict["debugs"] logic.
                    norm = ResourceManagerDiffEngine._normalize_entity_key(entity_name, log=log)
                    partials = entity_only_index.get(norm, [])
                    log.debug(
                        "Partial-match scan for entity='%s' (norm='%s'): %s candidate(s)",
                        entity_name,
                        norm,
                        len(partials),
                    )
                    for partial in partials:
                        partial_resource_id = ResourceManagerDiffEngine._resource_attr(partial, "resource_id", "resourceId")
                        mismatch_key = (
                            entity_name,
                            partial_resource_id,
                        )
                        if mismatch_key in seen_mismatch_keys:
                            log.debug(
                                "compute_changes: skipping duplicate partial match for entity='%s', resource_id=%s",
                                entity_name,
                                ResourceManagerDiffEngine._resource_attr(partial, "resource_id", "resourceId"),
                            )
                            continue
                        seen_mismatch_keys.add(mismatch_key)

                        partial_scope_details = ResourceManagerDiffEngine._scope_details(partial)
                        partial_pool = ResourceManagerDiffEngine._normalize_pool_name(
                            ResourceManagerDiffEngine._resource_attr(partial, "pool_name", "poolName"),
                            log=log,
                        )
                        desired_pool = ResourceManagerDiffEngine._normalize_pool_name(pool_name, log=log)
                        partial_scope = ResourceManagerDiffEngine._extract_scope_type(partial_scope_details, log=log)
                        partial_sw = ResourceManagerDiffEngine._extract_scope_switch_key_val(
                            partial_scope_details, switch_key="switch_ip", src_switch_key="src_switch_ip", log=log
                        )
                        partial_resource_value = ResourceManagerDiffEngine._resource_attr(partial, "resource_value", "resourceValue")
                        existing_values = {
                            "resource_id": partial_resource_id,
                            "pool_name": partial_pool,
                            "scope_type": partial_scope,
                            "switch_ip": partial_sw,
                            "resource_value": partial_resource_value,
                        }
                        mismatch = {
                            "resource_id": partial_resource_id,
                            "have_pool_name": partial_pool,
                            "want_pool_name": desired_pool,
                            "have_scope_type": partial_scope,
                            "want_scope_type": scope_type,
                            "have_switch_ip": partial_sw,
                            "have_resource_value": partial_resource_value,
                            "want_resource_value": resource_value,
                        }
                        log.debug(
                            "compute_changes: partial match for entity='%s': existing=%s mismatch=%s",
                            entity_name,
                            existing_values,
                            mismatch,
                        )
                        changes["debugs"].append(
                            {
                                "Entity Name": entity_name,
                                "EXISTING_VALUES": existing_values,
                                "MISMATCHED_VALUES": mismatch,
                            }
                        )
                else:
                    log.debug(
                        "Resource (entity=%s, pool=%s, scope=%s, switch=%s) found in existing — resource_id=%s, existing_value='%s'",
                        entity_name,
                        pool_name,
                        scope_type,
                        sw,
                        ResourceManagerDiffEngine._resource_attr(existing_res, "resource_id", "resourceId"),
                        ResourceManagerDiffEngine._resource_attr(existing_res, "resource_value", "resourceValue"),
                    )
                    matched_existing_keys.add(key)
                    existing_value = ResourceManagerDiffEngine._resource_attr(existing_res, "resource_value", "resourceValue")

                    if ResourceManagerDiffEngine._compare_resource_values(existing_value, resource_value, log=log):
                        log.debug(
                            "Resource (entity=%s, pool=%s, scope=%s, switch=%s) is idempotent (value=%s)",
                            entity_name,
                            pool_name,
                            scope_type,
                            sw,
                            existing_value,
                        )
                        changes["idempotent"].append((cfg, sw, existing_res))
                    else:
                        log.info(
                            "Resource (entity=%s, pool=%s, scope=%s, switch=%s) value differs (existing=%s, desired=%s) — marking to_update",
                            entity_name,
                            pool_name,
                            scope_type,
                            sw,
                            existing_value,
                            resource_value,
                        )
                        changes["to_update"].append((cfg, sw, existing_res))

        log.debug(
            "Proposed scan complete — matched_existing_keys=%s, total existing_index keys=%s",
            len(matched_existing_keys),
            len(existing_index),
        )

        # Resources in existing but not matched by any proposed entry → to_delete
        for key, res in existing_index.items():
            if key not in matched_existing_keys:
                log.info(
                    "Existing resource (entity=%s, pool=%s) not in proposed — marking to_delete",
                    ResourceManagerDiffEngine._resource_attr(res, "entity_name", "entityName"),
                    ResourceManagerDiffEngine._resource_attr(res, "pool_name", "poolName"),
                )
                changes["to_delete"].append(res)
            else:
                log.debug(
                    "Existing resource (entity=%s, pool=%s, key=%s) was matched by a proposed entry — skipping to_delete",
                    ResourceManagerDiffEngine._resource_attr(res, "entity_name", "entityName"),
                    ResourceManagerDiffEngine._resource_attr(res, "pool_name", "poolName"),
                    key,
                )

        log.info(
            "Compute changes summary: to_add=%s, to_update=%s, to_delete=%s, idempotent=%s, debugs=%s",
            len(changes["to_add"]),
            len(changes["to_update"]),
            len(changes["to_delete"]),
            len(changes["idempotent"]),
            len(changes["debugs"]),
        )
        log.debug("EXIT: compute_changes()")
        return changes

    @staticmethod
    def validate_resource_api_fields(
        nd: NDModule,
        resource_cfg: ResourceManagerConfigModel,
        api_resource: ResourceManagerResponse,
        context: str,
        log: logging.Logger,
    ) -> None:
        """Validate user-supplied resource fields against the ND API response.

        Only fields that are non-None in ``resource_cfg`` are validated.
        Fields omitted by the user are silently accepted from the API response.
        Uses ``ResourceManagerResponse`` model attributes directly for
        field access (``entity_name``, ``pool_name``, ``resource_value``,
        ``scope_details``).

        Args:
            nd: ND module wrapper used for failure handling.
            resource_cfg: Validated resource config from the playbook.
            api_resource: Matching ``ResourceManagerResponse`` from the ND API.
            log: Logger instance.
            context: Label used in error messages (e.g. ``"Resource"``).

        Returns:
            None.

        Raises:
            ValueError: When any provided field does not match the API response.
        """
        mismatches: list[str] = []

        # entity_name: tilde-order-insensitive comparison
        if resource_cfg.entity_name is not None:
            cfg_norm = ResourceManagerDiffEngine._normalize_entity_key(resource_cfg.entity_name, log=log)
            api_norm = ResourceManagerDiffEngine._normalize_entity_key(api_resource.entity_name, log=log) if api_resource.entity_name else None

            log.debug(
                "validate_resource_api_fields: checking entity_name — cfg_norm='%s', api_norm='%s'",
                cfg_norm,
                api_norm,
            )
            if cfg_norm != api_norm:
                log.debug(
                    "validate_resource_api_fields: entity_name MISMATCH — provided='%s', API='%s'",
                    resource_cfg.entity_name,
                    api_resource.entity_name,
                )
                mismatches.append(f"entity_name: provided '{resource_cfg.entity_name}', API reports '{api_resource.entity_name}'")
            else:
                log.debug(
                    "validate_resource_api_fields: entity_name OK — '%s' matches API",
                    resource_cfg.entity_name,
                )
        else:
            log.debug(
                "validate_resource_api_fields: entity_name not provided in cfg — skipping check (api_entity_name='%s')",
                api_resource.entity_name,
            )

        # pool_name: exact match
        if resource_cfg.pool_name is not None:
            cfg_pool_norm = ResourceManagerDiffEngine._normalize_pool_name(resource_cfg.pool_name, log=log)
            api_pool_norm = ResourceManagerDiffEngine._normalize_pool_name(api_resource.pool_name, log=log)
            log.debug(
                "validate_resource_api_fields: checking pool_name — cfg='%s' (norm='%s'), api='%s' (norm='%s')",
                resource_cfg.pool_name,
                cfg_pool_norm,
                api_resource.pool_name,
                api_pool_norm,
            )
            if cfg_pool_norm != api_pool_norm:
                log.debug(
                    "validate_resource_api_fields: pool_name MISMATCH — provided='%s', API='%s'",
                    resource_cfg.pool_name,
                    api_resource.pool_name,
                )
                mismatches.append(f"pool_name: provided '{resource_cfg.pool_name}', API reports '{api_resource.pool_name}'")
            else:
                log.debug(
                    "validate_resource_api_fields: pool_name OK — '%s' matches API",
                    resource_cfg.pool_name,
                )
        else:
            log.debug(
                "validate_resource_api_fields: pool_name not provided in cfg — skipping check (api_pool_name='%s')",
                api_resource.pool_name,
            )

        # resource vs resource_value: IPv4/v6-aware comparison
        if resource_cfg.resource is not None:
            log.debug(
                "validate_resource_api_fields: checking resource value — cfg='%s', api='%s'",
                resource_cfg.resource,
                api_resource.resource_value,
            )
            if not ResourceManagerDiffEngine._compare_resource_values(api_resource.resource_value, resource_cfg.resource, log=log):
                log.debug(
                    "validate_resource_api_fields: resource value MISMATCH — provided='%s', API='%s'",
                    resource_cfg.resource,
                    api_resource.resource_value,
                )
                mismatches.append(f"resource: provided '{resource_cfg.resource}', API reports '{api_resource.resource_value}'")
            else:
                log.debug(
                    "validate_resource_api_fields: resource value OK — '%s' matches API '%s'",
                    resource_cfg.resource,
                    api_resource.resource_value,
                )
        else:
            log.debug(
                "validate_resource_api_fields: resource not provided in cfg — skipping check (api_resource_value='%s')",
                api_resource.resource_value,
            )

        if mismatches:
            raise ValueError(
                f"{context} field mismatch for entity '{resource_cfg.entity_name}'. "
                f"The following provided values do not match the API data:\n\n".join(f"  - {m}" for m in mismatches)
            )

        log.debug(
            "validate_resource_api_fields: all provided fields match API for entity='%s', pool='%s'",
            resource_cfg.entity_name,
            resource_cfg.pool_name,
        )
