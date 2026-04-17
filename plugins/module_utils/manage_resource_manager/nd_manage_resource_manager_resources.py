# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import copy
import ipaddress
import logging
from typing import Any, Optional, Tuple, Union

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_config_model import (
    ResourceManagerConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_response_model import ResourceManagerResponse
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.remove_resource_by_id_request_model import (
    RemoveResourcesByIdsRequest,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.remove_resource_by_id_response_model import (
    RemoveResourcesByIdsResponse,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_request_model import (
    ResourceManagerBatchRequest,
    ResourceManagerRequest,
    FabricScope,
    DeviceScope,
    DeviceInterfaceScope,
    DevicePairScope,
    LinkScope,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_response_model import (
    ResourcesManagerBatchResponse,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_resources import (
    EpManageFabricResourcesGet,
    EpManageFabricResourcesPost,
    EpManageFabricResourcesActionsRemovePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.switchs_response_model import (
    GetAllSwitchesResponse,
    SwitchRecord,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
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
    def _normalize_pool_name(pool_name: str, log: logging.Logger) -> Optional[str]:
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
        normalis_entity_name = "~".join(sorted(entity_name.split("~")))
        log.debug("Returning normalized entity_name='%s' from raw='%s'", normalis_entity_name, entity_name)
        return normalis_entity_name

    @staticmethod
    def _extract_scope_switch_key_val(scope_details, switch_key, src_switch_key, log: logging.Logger) -> Optional[str]:
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
    def _extract_scope_type(scope_details, log: logging.Logger) -> Optional[str]:
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
        entity_name: Optional[str],
        pool_name: Optional[str],
        scope_type: Optional[str],
        switch_ip: Optional[str],
        log: logging.Logger,
    ) -> Tuple:
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
        log.debug("_make_resource_key: built key=%s from entity_name='%s', pool_name='%s', scope_type='%s', switch_ip='%s'", key, entity_name, pool_name, scope_type, switch_ip)
        return key

    @staticmethod
    def validate_configs(
        config: Union[dict[str, Any], list[dict[str, Any]]],
        state: str,
        nd: NDModule,
        log: logging.Logger,
    ) -> list[ResourceManagerConfigModel]:
        """Validate raw module config and return typed resource configurations.

        Args:
            config: Raw config dict or list of dicts from module parameters.
            state: Requested module state.
            nd: ND module wrapper used for failure handling.
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
                frozenset(cfg.switch or []),
            )
            log.debug(
                "validate_configs: duplicate-check [%s] — entity_name='%s', pool_name='%s', scope_type='%s', switch=%s, key_seen_before=%s",
                cfg_dup_idx,
                cfg.entity_name,
                cfg.pool_name,
                cfg.scope_type,
                list(cfg.switch or []),
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
        log.debug(
            "Comparing proposed : %s  vs  existing : %s existing resources",
            proposed,
            existing,
        )

        # Build index of existing resources keyed by
        # (normalized_entity, pool_name, playbook_scope_type, switch_id)
        existing_index: dict[Tuple, ResourceManagerResponse] = {}
        for res in existing:
            entity = res.entity_name
            pool = res.pool_name
            scope_type = ResourceManagerDiffEngine._extract_scope_type(res.scope_details, log=log)
            switch_id = ResourceManagerDiffEngine._extract_scope_switch_key_val(res.scope_details, switch_key="switch_id", src_switch_key="src_switch_id", log=log)
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
            norm = ResourceManagerDiffEngine._normalize_entity_key(res.entity_name or "", log=log)
            entity_only_index.setdefault(norm, []).append(res)
            log.debug(
                "entity_only_index: added entity='%s' under norm_key='%s' (total under key: %s)",
                res.entity_name,
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
                "Processing proposed cfg: entity=%s, pool=%s, scope=%s, resource=%s, switch=%s",
                entity_name,
                pool_name,
                scope_type,
                resource_value,
                cfg.switch,
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
                switches = cfg.switch if (scope_type != "fabric" and cfg.switch) else [None]
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
                        mismatch_key = (
                            entity_name,
                            getattr(partial, "resource_id", None),
                        )
                        if mismatch_key in seen_mismatch_keys:
                            log.debug(
                                "compute_changes: skipping duplicate partial match for entity='%s', resource_id=%s",
                                entity_name,
                                getattr(partial, "resource_id", None),
                            )
                            continue
                        seen_mismatch_keys.add(mismatch_key)

                        partial_pool = ResourceManagerDiffEngine._normalize_pool_name(partial.pool_name, log=log)
                        desired_pool = ResourceManagerDiffEngine._normalize_pool_name(pool_name, log=log)
                        partial_scope = ResourceManagerDiffEngine._extract_scope_type(partial.scope_details, log=log)
                        partial_sw = ResourceManagerDiffEngine._extract_scope_switch_key_val(partial.scope_details, switch_key="switch_ip", src_switch_key="src_switch_ip", log=log)
                        partial_resource_value = getattr(partial, "resource_value", None)
                        existing_values = {
                            "resource_id": getattr(partial, "resource_id", None),
                            "pool_name": partial_pool,
                            "scope_type": partial_scope,
                            "switch_ip": partial_sw,
                            "resource_value": partial_resource_value,
                        }
                        mismatch = {
                            "resource_id": getattr(partial, "resource_id", None),
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
                        getattr(existing_res, "resource_id", None),
                        existing_res.resource_value,
                    )
                    matched_existing_keys.add(key)
                    existing_value = existing_res.resource_value

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
                    res.entity_name,
                    res.pool_name,
                )
                changes["to_delete"].append(res)
            else:
                log.debug(
                    "Existing resource (entity=%s, pool=%s, key=%s) was matched by a proposed entry — skipping to_delete",
                    res.entity_name,
                    res.pool_name,
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
                f"The following provided values do not match the API data:\n"
                + "\n".join(f"  - {m}" for m in mismatches)
            )

        log.debug(
            "validate_resource_api_fields: all provided fields match API for entity='%s', pool='%s'",
            resource_cfg.entity_name,
            resource_cfg.pool_name,
        )


class NDResourceManagerModule:
    """
    Manage resources in Cisco Nexus Dashboard via the ND Manage v1 API.

    Uses pydantic models for input validation and smart endpoints for path/verb generation.
    Preserves the same business logic as nd_manage_resource_manager.py.
    """

    def __init__(
        self,
        nd: NDModule,
        results: Results,
        log: Optional[logging.Logger] = None,
    ):
        """Initialise the module, resolve fabric/state from ND params, and pre-fetch all resources.

        Queries the ND Manage API for all existing resources in ``fabric`` at construction
        time and caches the result in ``self._all_resources``.  The cached list is used as
        the ``existing`` baseline for diff computation in both merged and deleted states,
        avoiding repeated GET requests during the same module run.

        Args:
            nd: Initialised ``NDModule`` wrapper that holds the Ansible module params
                and the underlying ``RestSend`` HTTP client.
            results: ``Results`` instance used to accumulate API call results and
                build the final module output.
            log: Optional external logger.  If not provided a module-level logger
                (``logging.getLogger("nd.NDResourceManagerModule")``) is used.
        """
        self.nd = nd
        self.results = results
        self.log = log if log is not None else logging.getLogger("nd.NDResourceManagerModule")
        self.fabric = nd.params["fabric"]
        self.state = nd.params["state"]
        self.config = nd.params.get("config") or []

        # ND-compatible tracking dicts
        self.changed_dict = [{"merged": [], "deleted": [], "gathered": [], "debugs": []}]
        self.api_responses = []

        # Cached GET results — resources
        self._all_resources = []
        self._resources_fetched = False

        # Cached GET results — switches
        self._all_switches: list[SwitchRecord] = []
        self._switches_fetched = False
        self._switch_ip_to_id: dict[str, str] = {}

        # Get All resources for the given fabric and cache them for matching during merged/deleted operations
        self._get_all_resources()

        # Get all switches and build IP→switchId map; translate config switch lists
        self._get_all_switches()
        self._build_switch_ip_to_id_map()
        self.config = self._resolve_switch_ids_in_config(self.config)

        # Resource collections — existing/previous snapshot at init, proposed populated in manage_state
        self.existing: list[ResourceManagerResponse] = list(self._all_resources)
        self.previous: list[ResourceManagerResponse] = list(self._all_resources)
        self.proposed: list[ResourceManagerConfigModel] = []

        # NDOutput for building consistent Ansible output across all states
        self.output: NDOutput = NDOutput(output_level=nd.params.get("output_level", "normal"))

        self.log.info(
            "NDResourceManagerModule initialized: fabric=%s, state=%s, config_count=%s",
            self.fabric,
            self.state,
            len(self.config),
        )

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    def _validate_resource_params(self, item):
        """Validate that the combination of pool_type, pool_name, and scope_type is allowed.

        Maps pool_type to an internal check_key (the pool_name for ID pools, 'IP_POOL' for
        IP pools, 'SUBNET' for subnet pools), then looks up the allowed scope_type list in
        ``POOL_SCOPE_MAP``.  Fails fast with an informative message if the
        combination is not permitted by the ND Manage API.

        Args:
            item: A single config dict from the playbook ``config`` list, expected to
                contain ``pool_type``, ``pool_name``, and ``scope_type`` keys.

        Returns:
            Tuple ``(True, '')`` when validation passes.
            Tuple ``(False, error_message)`` when an invalid combination is detected.
        """
        pool_type = item.get("pool_type")
        pool_name = item.get("pool_name")
        scope_type = item.get("scope_type")

        self.log.debug(
            "Validating resource params: pool_type=%s, pool_name=%s, scope_type=%s",
            pool_type,
            pool_name,
            scope_type,
        )

        if pool_type == "ID":
            self.log.debug("pool_type is 'ID', using pool_name as check_key: %s", pool_name)
            check_key = pool_name
        elif pool_type == "IP":
            self.log.debug("pool_type is 'IP', using check_key='IP_POOL'")
            check_key = "IP_POOL"
        elif pool_type == "SUBNET":
            self.log.debug("pool_type is 'SUBNET', using check_key='SUBNET'")
            check_key = "SUBNET"
        else:
            msg = "Given pool type = '{0}' is invalid, Allowed pool types = ['ID', 'IP', 'SUBNET']".format(pool_type)
            self.log.warning("Validation failed: %s", msg)
            return False, msg

        allowed_scopes = POOL_SCOPE_MAP.get(check_key)
        if allowed_scopes is None:
            msg = "Given pool name '{0}' is not valid".format(pool_name)
            self.log.warning("Validation failed: %s", msg)
            return False, msg

        if scope_type not in allowed_scopes:
            msg = "Given scope type '{0}' is not valid for pool name = '{1}', Allowed scope_types = {2}".format(scope_type, pool_name, allowed_scopes)
            self.log.warning("Validation failed: %s", msg)
            return False, msg

        self.log.debug(
            "Validation passed: pool_name=%s, scope_type=%s, allowed_scopes=%s",
            pool_name,
            scope_type,
            allowed_scopes,
        )
        return True, ""

    def _validate_input(self):
        """Validate all playbook config items against the requirements of the current state.

        For ``merged`` and ``deleted`` states, ensures that ``config`` is provided and that
        every item carries the four mandatory fields (``entity_name``, ``pool_type``,
        ``pool_name``, ``scope_type``).  Also verifies that ``switch`` is present for any
        non-fabric scope type, runs pool_type/pool_name/scope_type compatibility checks via
        ``_validate_resource_params``, and performs pydantic cross-field validation via
        ``ResourceManagerConfigModel.from_config``.

        For ``gathered`` state, mandatory field checks are skipped so that partial filter
        criteria (e.g. only ``pool_name`` or only ``switch``) are accepted.

        Raises:
            ValueError: On any validation failure.
        """
        self.log.info(
            "Validating input: state=%s, config_count=%s",
            self.state,
            len(self.config),
        )

        if not self.config:
            if self.state in ("merged", "deleted"):
                self.log.error(
                    "'config' is mandatory for state '%s' but was not provided",
                    self.state,
                )
                raise ValueError("'config' element is mandatory for state '{0}'".format(self.state))
            return

        for item in self.config:
            self.log.debug(
                "Validating config item: entity_name=%s, pool_name=%s, scope_type=%s, pool_type=%s",
                item.get("entity_name"),
                item.get("pool_name"),
                item.get("scope_type"),
                item.get("pool_type"),
            )
            if self.state != "gathered":
                # Mandatory parameter checks
                for field in ("scope_type", "pool_type", "pool_name", "entity_name"):
                    if item.get(field) is None:
                        self.log.error(
                            "Mandatory parameter '%s' is missing in config item: %s",
                            field,
                            item,
                        )
                        raise ValueError("Mandatory parameter '{0}' missing".format(field))
                    else:
                        self.log.debug("Mandatory parameter '%s' present: %s", field, item.get(field))

                # Switch required for non-fabric scopes
                if item.get("scope_type") != "fabric" and not item.get("switch"):
                    self.log.error(
                        "'switch' is required for scope_type='%s' but is missing in config item: %s",
                        item.get("scope_type"),
                        item,
                    )
                    raise ValueError("switch : Required parameter not found")
                elif item.get("scope_type") != "fabric":
                    self.log.debug(
                        "'switch' provided for scope_type='%s': %s",
                        item.get("scope_type"),
                        item.get("switch"),
                    )

            # Validate pool_name / scope_type combination (only when pool_type is provided)
            if item.get("pool_type") is not None:
                self.log.debug(
                    "Running pool_type/pool_name/scope_type compatibility check for: pool_type=%s, pool_name=%s, scope_type=%s",
                    item.get("pool_type"),
                    item.get("pool_name"),
                    item.get("scope_type"),
                )
                rc, mesg = self._validate_resource_params(item)
                if not rc:
                    self.log.error("Pool/scope compatibility check failed: %s", mesg)
                    raise ValueError(mesg)
                else:
                    self.log.debug("Pool/scope compatibility check passed")

            # Pydantic cross-field validation for merged/deleted
            if self.state != "gathered":
                try:
                    ResourceManagerConfigModel.from_config(item)
                    self.log.debug(
                        "Pydantic validation passed for entity_name=%s",
                        item.get("entity_name"),
                    )
                except Exception as exc:
                    self.log.error(
                        "Pydantic validation failed for entity_name=%s: %s",
                        item.get("entity_name"),
                        exc,
                    )
                    raise ValueError("Invalid parameters in playbook: {0}".format(str(exc)))

    # ------------------------------------------------------------------
    # ND API interaction helpers
    # ------------------------------------------------------------------

    def _get_all_resources(self):
        """Fetch all existing resources for the fabric from the ND Manage API and cache them.

        Issues a single GET request to the fabric resources endpoint.  The response is
        normalised to a flat list of ``ResourceManagerResponse`` model instances (or raw
        dicts when model parsing fails) and stored in ``self._all_resources``.  Subsequent
        calls return immediately without hitting the API again (``self._resources_fetched``
        flag).

        A 404 response is treated as an empty fabric (no resources allocated yet) rather
        than an error.  Any other ``NDModuleError`` is re-raised to the caller.
        """
        if self._resources_fetched:
            self.log.debug(
                "Resources already cached for fabric=%s: %s resource(s)",
                self.fabric,
                len(self._all_resources),
            )
            return

        self.log.info("Fetching all resources for fabric=%s", self.fabric)

        ep = EpManageFabricResourcesGet(fabric_name=self.fabric)
        try:
            data = self.nd.request(ep.path, ep.verb)
        except NDModuleError as exc:
            if exc.status == 404:
                # Fabric has no resources yet — that is valid
                self.log.info(
                    "No resources found (404) for fabric=%s, treating as empty",
                    self.fabric,
                )
                self._resources_fetched = True
                return
            raise

        # The ND API may return a list directly or {"resources": [...], "meta": {...}}
        if isinstance(data, list):
            self.log.debug("API returned a list with %s item(s)", len(data))
            raw_list = data
        elif isinstance(data, dict) and "resources" in data:
            self.log.debug(
                "API returned dict with 'resources' key, %s resource(s)",
                len(data["resources"]),
            )
            raw_list = data["resources"]
        elif isinstance(data, dict) and data:
            self.log.debug("API returned a non-empty dict without 'resources' key, wrapping in list")
            raw_list = [data]
        else:
            self.log.debug("API returned empty or unexpected data, treating as empty list")
            raw_list = []

        for raw in raw_list:
            try:
                resource_model = ResourceManagerResponse.from_response(raw)
                self.log.debug(
                    "Parsed resource: entity_name=%s, pool_name=%s",
                    getattr(resource_model, "entity_name", None),
                    getattr(resource_model, "pool_name", None),
                )
                self._all_resources.append(resource_model)
            except Exception as exc:
                # If parsing fails, keep the raw dict so we can still match on it
                self.log.warning(
                    "Failed to parse resource into ResourceManagerResponse (keeping raw): %s | raw=%s",
                    exc,
                    raw,
                )
                self._all_resources.append(raw)

        self._resources_fetched = True
        self.log.info(
            "Fetched %s resource(s) for fabric=%s",
            len(self._all_resources),
            self.fabric,
        )

    def _get_all_switches(self):
        """Fetch all switches for the fabric from the ND Manage API and cache them.

        Issues a single GET request to the fabric switches endpoint using
        ``EpManageFabricSwitchesGet``.  The response is parsed into a
        ``GetAllSwitchesResponse`` model and the individual ``SwitchRecord`` items are
        stored in ``self._all_switches``.  Subsequent calls return immediately without
        hitting the API again (``self._switches_fetched`` flag).

        A 404 response is treated as an empty fabric (no switches found) rather than an
        error.  Any other ``NDModuleError`` is re-raised to the caller.
        """
        if self._switches_fetched:
            self.log.debug(
                "_get_all_switches: Switches already cached for fabric=%s: %s switch(es)",
                self.fabric,
                len(self._all_switches),
            )
            return

        self.log.info("_get_all_switches: Fetching all switches for fabric=%s", self.fabric)

        ep = EpManageFabricSwitchesGet(fabric_name=self.fabric)
        self.log.debug(
            "_get_all_switches: querying path='%s' for fabric='%s'",
            ep.path,
            self.fabric,
        )

        try:
            data = self.nd.request(ep.path, ep.verb)
        except NDModuleError as exc:
            if exc.status == 404:
                self.log.info(
                    "_get_all_switches: No switches found (404) for fabric=%s, treating as empty",
                    self.fabric,
                )
                self._switches_fetched = True
                return
            raise

        self.log.debug(
            "_get_all_switches: received response type=%s",
            type(data).__name__,
        )

        parsed = GetAllSwitchesResponse.from_response(data)
        self._all_switches = parsed.switches

        self._switches_fetched = True
        total = parsed.meta.counts.total if (parsed.meta and parsed.meta.counts) else len(self._all_switches)
        self.log.info(
            "_get_all_switches: Fetched %s switch(es) for fabric=%s (API total=%s)",
            len(self._all_switches),
            self.fabric,
            total,
        )

    def _build_switch_ip_to_id_map(self):
        """Build the ``fabricManagementIp → switchId`` lookup map from cached switch records.

        Iterates ``self._all_switches`` (populated by ``_get_all_switches``) and populates
        ``self._switch_ip_to_id``.  Records that are missing either ``fabric_management_ip``
        or ``switch_id`` are skipped with a debug log entry.
        """
        self.log.debug(
            "_build_switch_ip_to_id_map: building map from %s cached switch record(s)",
            len(self._all_switches),
        )

        for idx, sw in enumerate(self._all_switches):
            switch_id = sw.switch_id
            switch_ip = sw.fabric_management_ip
            self.log.debug(
                "_build_switch_ip_to_id_map: [%s] switchId='%s', fabricManagementIp='%s'",
                idx,
                switch_id,
                switch_ip,
            )
            if switch_id and switch_ip:
                self._switch_ip_to_id[str(switch_ip).strip()] = switch_id
                self.log.debug(
                    "_build_switch_ip_to_id_map: [%s] mapped ip='%s' -> switchId='%s' (map_size=%s)",
                    idx,
                    switch_ip,
                    switch_id,
                    len(self._switch_ip_to_id),
                )
            else:
                self.log.debug(
                    "_build_switch_ip_to_id_map: [%s] skipping — missing switch_id='%s' or fabric_management_ip='%s'",
                    idx,
                    switch_id,
                    switch_ip,
                )

        self.log.info(
            "_build_switch_ip_to_id_map: map complete — %s entry/entries",
            len(self._switch_ip_to_id),
        )

    def _resolve_switch_ids_in_config(self, config):
        """Translate management IPs in config ``switch`` lists to switchId values.

        Returns a deep copy of ``config`` with each entry's ``switch`` list translated
        from management IP strings (e.g. ``'192.168.10.150'``) to the corresponding
        ``switchId`` values (e.g. ``'9H1Q6YOL08G'``) using ``self._switch_ip_to_id``.

        IPs that are not found in the map are passed through unchanged so the caller can
        decide how to handle unresolved entries (the ND API will reject them with an
        appropriate error).

        Args:
            config: Raw config list from ``nd.params["config"]``. Not mutated.

        Returns:
            A deep copy of ``config`` with switch IPs replaced by switchId values.
        """
        self.log.debug(
            "_resolve_switch_ids_in_config: translating %s config item(s) using map of %s entry/entries",
            len(config or []),
            len(self._switch_ip_to_id),
        )

        config_copy = copy.deepcopy(config or [])

        for idx, item in enumerate(config_copy):
            raw_switch_list = item.get("switch") or []
            entity_name = item.get("entity_name")
            scope_type = item.get("scope_type")

            self.log.debug(
                "_resolve_switch_ids_in_config: [%s] entity='%s', scope_type='%s', raw_switch_list=%s",
                idx,
                entity_name,
                scope_type,
                raw_switch_list,
            )

            if not raw_switch_list:
                self.log.debug(
                    "_resolve_switch_ids_in_config: [%s] entity='%s' — no switch list present, skipping translation",
                    idx,
                    entity_name,
                )
                continue

            resolved = []
            for sw_ip in raw_switch_list:
                sw_key = str(sw_ip).strip()
                sw_id = self._switch_ip_to_id.get(sw_key, sw_key)
                if sw_id != sw_key:
                    self.log.debug(
                        "_resolve_switch_ids_in_config: [%s] entity='%s' switch '%s' -> resolved switchId='%s'",
                        idx,
                        entity_name,
                        sw_ip,
                        sw_id,
                    )
                else:
                    self.log.debug(
                        "_resolve_switch_ids_in_config: [%s] entity='%s' switch '%s' not found in map — passing through unchanged",
                        idx,
                        entity_name,
                        sw_ip,
                    )
                resolved.append(sw_id)

            item["switch"] = resolved
            self.log.debug(
                "_resolve_switch_ids_in_config: [%s] entity='%s' final switch list: %s -> %s",
                idx,
                entity_name,
                raw_switch_list,
                resolved,
            )

        self.log.debug(
            "_resolve_switch_ids_in_config: completed, returning %s translated config item(s)",
            len(config_copy),
        )
        return config_copy

    # ------------------------------------------------------------------
    # Resource attribute accessors (handle both ResourceManagerResponse and raw dict)
    # ------------------------------------------------------------------

    def _attr(self, resource, model_attr, dict_key):
        """Return a field value from a resource that may be a model instance or a raw dict.

        Tries to read ``model_attr`` from the resource via ``getattr`` first (for typed
        ``ResourceManagerResponse`` instances), then falls back to ``resource.get(dict_key)``
        for raw dict responses returned when model parsing failed at fetch time.

        Args:
            resource: A ``ResourceManagerResponse`` model instance or a plain dict.
            model_attr: Attribute name to access on a model instance (snake_case).
            dict_key: Key to access on a raw dict (camelCase, e.g. ``'entityName'``).

        Returns:
            The field value, or None if neither path resolves.
        """
        if hasattr(resource, model_attr):
            value = getattr(resource, model_attr)
            self.log.debug("_attr: resolved '%s' from model: %s", model_attr, value)
            return value
        if isinstance(resource, dict):
            value = resource.get(dict_key)
            self.log.debug("_attr: resolved '%s' from dict: %s", dict_key, value)
            return value
        self.log.debug("_attr: could not resolve '%s'/'%s' from resource type %s", model_attr, dict_key, type(resource))
        return None

    def _get_entity_name(self, resource):
        """Return the entity_name field from a resource model or raw dict."""
        return self._attr(resource, "entity_name", "entityName")

    def _get_pool_name(self, resource):
        """Return the pool_name field from a resource model or raw dict."""
        return self._attr(resource, "pool_name", "poolName")

    def _get_resource_id(self, resource):
        """Return the resource_id field from a resource model or raw dict."""
        return self._attr(resource, "resource_id", "resourceId")

    def _get_resource_value(self, resource):
        """Return the resource_value field from a resource model or raw dict."""
        return self._attr(resource, "resource_value", "resourceValue")

    def _get_scope_type(self, resource):
        """Return the playbook-style scope_type string for a resource.

        Reads the raw ND API ``scopeType`` value from either the model's
        ``scope_details.scope_type`` attribute or the ``scopeDetails.scopeType`` key of a
        raw dict, then maps it from the API camelCase format (e.g. ``'deviceInterface'``)
        to the playbook format (e.g. ``'device_interface'``) using
        ``API_SCOPE_TYPE_TO_PLAYBOOK``.

        Args:
            resource: A ``ResourceManagerResponse`` model instance or a plain dict.

        Returns:
            Playbook-style scope_type string, or None if the resource type is unrecognised.
        """
        if hasattr(resource, "scope_details") and resource.scope_details:
            raw = getattr(resource.scope_details, "scope_type", None)
            self.log.debug("_get_scope_type: from model scope_details, raw=%s", raw)
        elif isinstance(resource, dict):
            sd = resource.get("scopeDetails") or {}
            raw = sd.get("scopeType")
            self.log.debug("_get_scope_type: from dict scopeDetails, raw=%s", raw)
        else:
            self.log.debug("_get_scope_type: unrecognised resource type %s, returning None", type(resource))
            return None
        mapped = API_SCOPE_TYPE_TO_PLAYBOOK.get(raw, raw) if raw else None
        self.log.debug("_get_scope_type: mapped API scope '%s' -> playbook scope '%s'", raw, mapped)
        return mapped

    def _get_switch_ip(self, resource):
        """Return the primary switch IP/ID from scopeDetails (src switch for device_pair/link).

        Delegates to ResourceManagerDiffEngine._extract_scope_switch_key_val for model
        instances so that all scope types are handled uniformly:
          - fabric              → None
          - device / device_interface → switch_ip
          - device_pair / link  → src_switch_ip
        """
        if hasattr(resource, "scope_details") and resource.scope_details:
            value = ResourceManagerDiffEngine._extract_scope_switch_key_val(resource.scope_details, switch_key="switch_ip", src_switch_key="src_switch_ip", log=self.log)
            self.log.debug("_get_switch_ip: from model scope_details, switch_ip=%s", value)
            return value
        if isinstance(resource, dict):
            sd = resource.get("scopeDetails") or {}
            # device/deviceInterface use "switchIp"; device_pair/link use "srcSwitchIp"
            value = sd.get("switchIp") or sd.get("srcSwitchIp")
            self.log.debug("_get_switch_ip: from dict scopeDetails, switch_ip=%s", value)
            return value
        self.log.debug("_get_switch_ip: unrecognised resource type %s, returning None", type(resource))
        return None

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------

    def _entity_names_match(self, e1, e2):
        """Compare two entity names in a tilde-order-insensitive way.

        Splits each name on ``'~'``, sorts the resulting parts alphabetically, and
        compares the sorted lists.  This ensures that a device_pair entity such as
        ``'SER1~SER2~label'`` matches ``'SER2~SER1~label'`` regardless of the order
        in which the serial numbers appear in the playbook vs the ND API response.

        Args:
            e1: First entity name string.
            e2: Second entity name string.

        Returns:
            True if both names are non-None and their sorted tilde-parts are equal,
            False otherwise.
        """
        if e1 is None or e2 is None:
            self.log.debug(
                "_entity_names_match: one or both entity names are None (e1=%s, e2=%s), returning False",
                e1,
                e2,
            )
            return False
        result = sorted(e1.split("~")) == sorted(e2.split("~"))
        self.log.debug(
            "_entity_names_match: e1='%s', e2='%s', sorted_e1=%s, sorted_e2=%s, match=%s",
            e1,
            e2,
            sorted(e1.split("~")),
            sorted(e2.split("~")),
            result,
        )
        return result

    # ------------------------------------------------------------------
    # API payload builders
    # ------------------------------------------------------------------

    def _build_scope_details(self, scope_type, switch_ip=None, entity_name=None):
        """Build the scopeDetails Pydantic model for the ND Manage API.

        ``switch_ip`` is the translated switchId (serial number) of the source switch
        from the playbook ``switch`` list.  The entity_name encodes the full topology
        (src and dst) as tilde-separated fields — the server uses it to resolve
        additional context, so we only need to supply srcSwitchId for multi-switch
        scopes (device_pair, link) and let the server derive dst from entityName.

          - fabric:           FabricScope(fabricName)
          - device:           DeviceScope(switchId)
          - device_interface: DeviceInterfaceScope(switchId, interfaceName)
          - device_pair:      DevicePairScope(srcSwitchId)  — dst derived by server from entityName
          - link:             LinkScope(srcSwitchId, srcInterfaceName)  — dst derived by server from entityName
        """
        self.log.debug(
            "_build_scope_details: scope_type=%s, switch_ip=%s, entity_name=%s, fabric=%s",
            scope_type,
            switch_ip,
            entity_name,
            self.fabric,
        )

        if scope_type == "fabric":
            self.log.debug(
                "_build_scope_details: fabric scope -> fabricName=%s",
                self.fabric,
            )
            result = FabricScope(fabric_name=self.fabric)

        elif scope_type == "device":
            self.log.debug(
                "_build_scope_details: device scope -> switchId=%s",
                switch_ip,
            )
            result = DeviceScope(switch_id=switch_ip)

        elif scope_type == "device_interface":
            # entity_name format: <serialNumber>~<interfaceName>
            # switch_ip is already the translated switchId (serial number)
            parts = (entity_name or "").split("~", 1)
            if_name = parts[1] if len(parts) > 1 else None
            self.log.debug(
                "_build_scope_details: device_interface scope -> switchId=%s, interfaceName=%s (interfaceName parsed from entity_name='%s')",
                switch_ip,
                if_name,
                entity_name,
            )
            if not if_name:
                self.log.warning(
                    "_build_scope_details: device_interface scope: could not parse interfaceName from entity_name='%s'",
                    entity_name,
                )
            result = DeviceInterfaceScope(switch_id=switch_ip, interface_name=if_name)

        elif scope_type == "device_pair":
            # entity_name format: <srcSN>~<dstSN>[~<label>]
            # Both srcSwitchId and dstSwitchId must be sent — the server does not derive
            # dstSwitchId from entityName and returns "JSONObject["dstSwitchId"] not found."
            # if it is missing.
            parts = (entity_name or "").split("~")
            src_sn = parts[0] if len(parts) > 0 else None
            dst_sn = parts[1] if len(parts) > 1 else None
            self.log.debug(
                "_build_scope_details: device_pair scope -> srcSwitchId=%s, dstSwitchId=%s (parsed from entity_name='%s')",
                src_sn,
                dst_sn,
                entity_name,
            )
            result = DevicePairScope(src_switch_id=src_sn, dst_switch_id=dst_sn)

        elif scope_type == "link":
            # entity_name format: <srcSN>~<srcIF>~<dstSN>~<dstIF>
            # All four fields must be supplied — the server does not derive dst context
            # from entityName alone.
            parts = (entity_name or "").split("~")
            src_sn = parts[0] if len(parts) > 0 else None
            src_if = parts[1] if len(parts) > 1 else None
            dst_sn = parts[2] if len(parts) > 2 else None
            dst_if = parts[3] if len(parts) > 3 else None
            self.log.debug(
                "_build_scope_details: link scope -> srcSwitchId=%s, srcInterfaceName=%s, dstSwitchId=%s, dstInterfaceName=%s (parsed from entity_name='%s')",
                src_sn,
                src_if,
                dst_sn,
                dst_if,
                entity_name,
            )
            result = LinkScope(
                src_switch_id=src_sn,
                src_interface_name=src_if,
                dst_switch_id=dst_sn,
                dst_interface_name=dst_if,
            )

        else:
            self.log.warning(
                "_build_scope_details: unrecognised scope_type='%s', falling back to generic DeviceScope payload",
                scope_type,
            )
            result = DeviceScope(switch_id=switch_ip)

        self.log.debug("_build_scope_details: result=%s", result)
        return result

    def _build_create_payload(self, cfg, switch_ip=None):
        """Build the POST body for a single resource creation request.

        Accepts either a typed ``ResourceManagerConfigModel`` instance or a legacy dict
        (backward-compatible path).  Delegates scope construction to
        ``_build_scope_details`` and serialises the complete request via
        ``ResourceManagerRequest.to_payload()``.

        Args:
            cfg: A ``ResourceManagerConfigModel`` instance or a dict with keys
                ``scope_type``, ``entity_name``, ``pool_name``, ``pool_type``,
                and optionally ``resource``.
            switch_ip: The resolved switchId (serial number) for the primary switch,
                or None for fabric-scoped resources.

        Returns:
            A plain dict payload ready to be sent to the ND Manage API POST endpoint.
        """
        if isinstance(cfg, ResourceManagerConfigModel):
            scope_type = cfg.scope_type
            entity_name = cfg.entity_name
            pool_name = cfg.pool_name
            pool_type = cfg.pool_type
            resource_value = cfg.resource
        else:
            # Legacy dict path (kept for backward-compat with any callers not yet refactored)
            scope_type = cfg["scope_type"]
            entity_name = cfg["entity_name"]
            pool_name = cfg["pool_name"]
            pool_type = cfg.get("pool_type")
            resource_value = cfg.get("resource")

        self.log.debug(
            "_build_create_payload: pool_name=%s, pool_type=%s, entity_name=%s, scope_type=%s, switch_ip=%s, resource=%s",
            pool_name,
            pool_type,
            entity_name,
            scope_type,
            switch_ip,
            resource_value,
        )

        scope = self._build_scope_details(scope_type, switch_ip, entity_name=entity_name)

        request = ResourceManagerRequest(
            pool_name=pool_name,
            pool_type=pool_type,
            entity_name=entity_name,
            scope_details=scope,
            is_pre_allocated=True,
            resource_value=str(resource_value) if resource_value is not None else None,
        )

        if resource_value is not None:
            self.log.debug(
                "_build_create_payload: adding resourceValue='%s' to payload",
                resource_value,
            )
        else:
            self.log.debug("_build_create_payload: no resource value provided, omitting resourceValue field")

        payload = request.to_payload()
        self.log.debug("_build_create_payload: final payload=%s", payload)
        return payload

    # ------------------------------------------------------------------
    # Gathered results translation
    # ------------------------------------------------------------------

    def _determine_pool_type(self, resource_value):
        """Infer the pool_type from a resource value string.

        Attempts to parse the value as an IP network (returns ``'SUBNET'``), then as an
        IP address (returns ``'IP'``), and falls back to ``'ID'`` for plain integer or
        string identifiers.  Used when translating raw API responses back into the playbook
        config format during gathered-state output.

        Args:
            resource_value: The raw resource value string from the ND API response,
                e.g. ``'101'``, ``'10.1.1.1'``, or ``'10.1.1.0/24'``.  May be None.

        Returns:
            One of ``'ID'``, ``'IP'``, or ``'SUBNET'``.
        """
        self.log.debug(
            "_determine_pool_type: evaluating resource_value='%s'",
            resource_value,
        )
        if not resource_value:
            self.log.debug("_determine_pool_type: resource_value is None/empty — returning 'ID'")
            return "ID"
        val = str(resource_value).strip()
        if "/" in val:
            self.log.debug(
                "_determine_pool_type: value='%s' contains '/' — attempting ip_network parse",
                val,
            )
            try:
                ipaddress.ip_network(val, strict=False)
                self.log.debug(
                    "_determine_pool_type: '%s' is a valid IP network — returning 'SUBNET'",
                    val,
                )
                return "SUBNET"
            except ValueError:
                self.log.debug(
                    "_determine_pool_type: '%s' failed ip_network parse — falling through to ip_address check",
                    val,
                )
        else:
            self.log.debug(
                "_determine_pool_type: value='%s' has no '/' — skipping ip_network check",
                val,
            )
        try:
            ipaddress.ip_address(val)
            self.log.debug(
                "_determine_pool_type: '%s' is a valid IP address — returning 'IP'",
                val,
            )
            return "IP"
        except ValueError:
            self.log.debug(
                "_determine_pool_type: '%s' is not an IP address — returning 'ID'",
                val,
            )
        return "ID"

    def translate_gathered_results(self, resources):
        """Translate raw API resource items to the merged-state config format.

        Converts each resource from the ND API response shape
        (camelCase keys, nested scopeDetails) into the playbook ``config``
        format used by ``state: merged``:
          entity_name, pool_type, pool_name, scope_type, resource[, switch].
        """
        translated = []
        self.log.debug(
            "translate_gathered_results: translating %s resource(s) to playbook config format",
            len(resources),
        )
        for res_idx, res in enumerate(resources):
            entity_name = self._get_entity_name(res)
            pool_name = self._get_pool_name(res)
            resource_value = self._get_resource_value(res)
            scope_type = self._get_scope_type(res)
            switch_ip = self._get_switch_ip(res)
            pool_type = self._determine_pool_type(resource_value)
            self.log.debug(
                "translate_gathered_results: [%s] resolved fields — "
                "entity_name='%s', pool_name='%s', scope_type='%s', "
                "pool_type='%s', resource_value='%s', switch_ip='%s'",
                res_idx,
                entity_name,
                pool_name,
                scope_type,
                pool_type,
                resource_value,
                switch_ip,
            )

            item = {
                "entity_name": entity_name,
                "pool_type": pool_type,
                "pool_name": pool_name,
                "scope_type": scope_type,
                "resource": resource_value,
            }
            if scope_type != "fabric" and switch_ip:
                item["switch"] = [switch_ip]
                self.log.debug(
                    "translate_gathered_results: [%s] entity='%s' — non-fabric scope ('%s'), adding switch=['%s'] to item",
                    res_idx,
                    entity_name,
                    scope_type,
                    switch_ip,
                )
            else:
                self.log.debug(
                    "translate_gathered_results: [%s] entity='%s' — scope_type='%s', switch_ip='%s' — no switch field added",
                    res_idx,
                    entity_name,
                    scope_type,
                    switch_ip,
                )

            translated.append(item)
            self.log.debug(
                "translate_gathered_results: [%s] appended item=%s",
                res_idx,
                item,
            )
        self.log.debug(
            "translate_gathered_results: completed — %s item(s) translated (before switch merge)",
            len(translated),
        )

        # Merge entries that share the same (entity_name, pool_name, pool_type,
        # scope_type, resource) key — only their switch IPs differ.  Fabric-scoped
        # resources (no 'switch' key) are passed through unchanged.
        merged: dict = {}
        for item in translated:
            key = (
                item.get("entity_name"),
                item.get("pool_name"),
                item.get("pool_type"),
                item.get("scope_type"),
                item.get("resource"),
            )
            if key in merged:
                # Accumulate switch IPs for matching entries (deduplicate, preserve order)
                sw_list = item.get("switch") or []
                for sw in sw_list:
                    if sw not in merged[key].get("switch", []):
                        merged[key]["switch"].append(sw)
                        self.log.debug(
                            "translate_gathered_results: merged switch ip='%s' into existing entry for key=%s",
                            sw,
                            key,
                        )
            else:
                merged[key] = item

        translated = list(merged.values())
        self.log.debug(
            "translate_gathered_results: after switch merge — %s item(s) returned",
            len(translated),
        )
        return translated

    def manage_merged(self):
        """Create or update resources to match the desired state defined in the playbook.

        Delegates diff computation to ``ResourceManagerDiffEngine.compute_changes`` to
        classify each proposed resource as ``to_add`` (new) or ``to_update`` (value
        changed).  Idempotent resources (already matching) are skipped.

        In check mode, logs what would be created without issuing any API calls.
        Otherwise, sends a single batch POST request containing all pending payloads and
        validates each item in the response against the sent config via
        ``ResourceManagerDiffEngine.validate_resource_api_fields``.

        Raises:
            NDModuleError: Propagated from ``self.nd.request`` on API failure.
        """
        self.log.info(
            "manage_merged: Processing %s config item(s) for fabric=%s",
            len(self.config),
            self.fabric,
        )

        # Use compute_changes as the canonical diff engine.
        changes = ResourceManagerDiffEngine.compute_changes(self.proposed, self.existing, log=self.log)

        # Propagate partial-match mismatch diagnostics to the output diff (GAP-7).
        self.changed_dict[0]["debugs"].extend(changes["debugs"])

        # Resources that need to be created: new (to_add) or value changed (to_update).
        pending_items: list[tuple[ResourceManagerConfigModel, str, ResourceManagerResponse]] = changes["to_add"] + changes["to_update"]

        if not pending_items:
            self.log.debug("manage_merged: No resources to create (all idempotent).")
            return

        # Build payload list alongside a cfg reference for post-create validation (GAP-5).
        pending_payloads = []
        for cfg, sw, _existing in pending_items:
            payload = self._build_create_payload(cfg, switch_ip=sw)
            pending_payloads.append((cfg, payload))
            self.log.debug(
                "manage_merged: Queuing resource for batch create: entity_name=%s, pool_name=%s, scope_type=%s, switch_ip=%s",
                cfg.entity_name,
                cfg.pool_name,
                cfg.scope_type,
                sw,
            )

        # Track diff BEFORE the API call so --check mode also shows what would change (GAP-3).
        self.changed_dict[0]["merged"].extend(p for _cfg, p in pending_payloads)

        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: would create %s resource(s) for fabric=%s",
                len(pending_payloads),
                self.fabric,
            )
            return

        self.log.info(
            "manage_merged: Making batch API call with %s resource(s) for fabric=%s",
            len(pending_payloads),
            self.fabric,
        )

        payloads_only = [p for _cfg, p in pending_payloads]
        batch = ResourceManagerBatchRequest.model_validate({"resources": payloads_only})
        ep = EpManageFabricResourcesPost(fabric_name=self.fabric)
        resp_data = self.nd.request(ep.path, ep.verb, data=batch.to_payload())

        # Parse batch response.
        batch_response = ResourcesManagerBatchResponse.from_response(resp_data)
        self.log.debug(
            "manage_merged: Batch API response parsed — %s item(s) returned",
            len(batch_response.resources),
        )

        # Build a normalised entity_name → cfg lookup for GAP-5 field validation.
        # If two items share a normalised name (unusual), the last one wins; that is
        # acceptable because validate_resource_api_fields uses order-insensitive comparison.
        cfg_by_entity: dict[str, ResourceManagerConfigModel] = {
            ResourceManagerDiffEngine._normalize_entity_key(cfg.entity_name, log=self.log): cfg for cfg, _payload in pending_payloads
        }

        for resp_item in batch_response.resources:
            self.api_responses.append({"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)})
            # GAP-5: Validate that the API response fields match what we sent.
            if resp_item.entity_name is not None:
                norm_key = ResourceManagerDiffEngine._normalize_entity_key(resp_item.entity_name, log=self.log)
                matched_cfg = cfg_by_entity.get(norm_key)
                if matched_cfg is not None:
                    ResourceManagerDiffEngine.validate_resource_api_fields(self.nd, matched_cfg, resp_item, "Resource", log=self.log)

        self.log.info(
            "manage_merged: Batch create successful — %s resource(s) created for fabric=%s",
            len(pending_payloads),
            self.fabric,
        )

    def manage_deleted(self):
        """Delete resources that are listed in the playbook config and exist in the fabric.

        Uses ``ResourceManagerDiffEngine.compute_changes`` to identify which proposed
        resources are present in the ND fabric (``idempotent`` or ``to_update`` buckets).
        Only explicitly listed resources are deleted; unrelated existing resources are
        left untouched, matching the ND nd_rm_get_diff_deleted() behaviour.

        In check mode, records which resource IDs would be removed without issuing any
        API calls.  Otherwise, sends a batch remove POST request with the collected
        resource IDs.

        Raises:
            NDModuleError: Propagated from ``self.nd.request`` on API failure.
        """
        self.log.info(
            "manage_deleted: Processing %s config item(s) for fabric=%s",
            len(self.config),
            self.fabric,
        )

        # Use compute_changes as the canonical diff engine.
        changes = ResourceManagerDiffEngine.compute_changes(self.proposed, self.existing, log=self.log)

        # Propagate partial-match mismatch diagnostics to the output diff (GAP-7).
        self.changed_dict[0]["debugs"].extend(changes["debugs"])

        # Collect resource IDs for entries that exist in the fabric.
        # idempotent  → resource exists with the same value   → still delete it.
        # to_update   → resource exists but with a different value → still delete it.
        # to_add      → resource does not exist               → nothing to delete.
        # to_delete   → "override" bucket (unmatched existing) → ignored; deleted state
        #               only removes what is explicitly listed in the playbook config,
        #               matching ND's nd_rm_get_diff_deleted() behaviour.
        resource_ids = []
        for _cfg, _sw, existing_res in changes["idempotent"] + changes["to_update"]:
            rid = self._get_resource_id(existing_res)
            if rid is not None and rid not in resource_ids:
                self.log.debug(
                    "manage_deleted: Queuing resource ID '%s' for deletion (entity_name=%s, pool_name=%s, switch_ip=%s)",
                    rid,
                    _cfg.entity_name,
                    _cfg.pool_name,
                    _sw,
                )
                resource_ids.append(rid)
            elif rid is not None:
                self.log.debug(
                    "manage_deleted: Resource ID '%s' already queued, skipping duplicate",
                    rid,
                )
            else:
                self.log.debug(
                    "manage_deleted: Matched resource has no resource ID, skipping: %s",
                    existing_res,
                )

        if not resource_ids:
            # Nothing to delete — idempotent
            self.log.info(
                "manage_deleted: No matching resources found to delete for fabric=%s, nothing to do",
                self.fabric,
            )
            return

        self.log.info(
            "manage_deleted: Collected %s resource ID(s) to delete: %s",
            len(resource_ids),
            resource_ids,
        )

        self.changed_dict[0]["deleted"].extend(str(r) for r in resource_ids)

        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: would delete %s resource(s): %s",
                len(resource_ids),
                resource_ids,
            )
            self.api_responses.append({"RETURN_CODE": 200, "DATA": {"resourceIds": resource_ids}})
            return

        ep = EpManageFabricResourcesActionsRemovePost(fabric_name=self.fabric)
        remove_req = RemoveResourcesByIdsRequest(resource_ids=resource_ids)
        resp_data = self.nd.request(ep.path, ep.verb, data=remove_req.to_payload())

        remove_response = RemoveResourcesByIdsResponse.from_response(resp_data)

        self.log.debug(
            "manage_deleted: Delete API response parsed — %s item(s) returned",
            len(remove_response.resources),
        )

        for resp_item in remove_response.resources:
            self.api_responses.append({"RETURN_CODE": 200, "DATA": resp_item.model_dump(by_alias=True, exclude_none=True)})

        self.log.info(
            "manage_deleted: Successfully deleted %s resource(s): %s",
            len(resource_ids),
            resource_ids,
        )

    def manage_gathered(self):
        """Return resources from the ND fabric, optionally filtered by config criteria.

        When no ``config`` is provided, all resources cached in ``self._all_resources`` are
        translated to the playbook format and returned.  When ``config`` is provided, each
        filter item is processed in sequence; a resource must satisfy every non-None
        criterion in the filter (``entity_name``, ``pool_name``, ``switch``) to be
        included.  Deduplication is applied across filter items using the resource ID so
        that a resource matching multiple filters appears only once in the output.

        Results are stored in ``self.changed_dict[0]['gathered']`` and
        ``self.api_responses``.
        """
        config_count = len(self.config) if self.config else 0
        self.log.info(
            "manage_gathered: Gathering resources for fabric=%s, filter_count=%s",
            self.fabric,
            config_count,
        )

        if not self.config:
            # No filters — return everything translated to merged format
            results = self.translate_gathered_results(self._all_resources)
            self.log.info(
                "manage_gathered: No filter criteria provided, returning all %s resource(s)",
                len(results),
            )
            self.api_responses.extend(results)
            self.changed_dict[0]["gathered"].extend(results)
            return

        seen_ids = set()
        results = []

        for filter_item in self.config:
            filter_entity = filter_item.get("entity_name")
            filter_pool = filter_item.get("pool_name")
            filter_switches = filter_item.get("switch") or []

            # Skip filter items with no active criteria to avoid matching all resources
            if not filter_entity and not filter_pool and not filter_switches:
                self.log.debug(
                    "manage_query: Skipping filter item with no active criteria (entity_name=%s, pool_name=%s, switches=%s)",
                    filter_entity,
                    filter_pool,
                    filter_switches,
                )
                continue

            self.log.debug(
                "manage_query: Applying filter: entity_name=%s, pool_name=%s, switches=%s",
                filter_entity,
                filter_pool,
                filter_switches,
            )

            for res in self._all_resources:
                rid = self._get_resource_id(res)

                # Deduplicate across filter criteria
                if rid is not None and rid in seen_ids:
                    self.log.debug(
                        "manage_query: Skipping resource id='%s' (already included via previous filter)",
                        rid,
                    )
                    continue

                res_entity = self._get_entity_name(res)
                res_pool = self._get_pool_name(res)
                # Use switchId (serial number) from scopeDetails to match playbook switch config values
                if hasattr(res, "scope_details") and res.scope_details:
                    res_sw = ResourceManagerDiffEngine._extract_scope_switch_key_val(res.scope_details, switch_key="switch_id", src_switch_key="src_switch_id", log=self.log)
                elif isinstance(res, dict):
                    sd = res.get("scopeDetails") or {}
                    res_sw = sd.get("switchId") or sd.get("srcSwitchId")
                else:
                    res_sw = None

                # Apply entity_name filter
                if filter_entity and not self._entity_names_match(res_entity, filter_entity):
                    self.log.debug(
                        "manage_query: Skipping resource id='%s', entity_name mismatch: resource='%s' vs filter='%s'",
                        rid,
                        res_entity,
                        filter_entity,
                    )
                    continue

                # Apply pool_name filter
                if filter_pool and res_pool != filter_pool:
                    self.log.debug(
                        "manage_query: Skipping resource id='%s', pool_name mismatch: resource='%s' vs filter='%s'",
                        rid,
                        res_pool,
                        filter_pool,
                    )
                    continue

                # Apply switch filter: match switchId (serial number) from scopeDetails;
                # fabric-scoped resources (no switchId) are correctly excluded
                if filter_switches and res_sw not in filter_switches:
                    self.log.debug(
                        "manage_query: Skipping resource id='%s', switchId not in filter: resource_switch='%s', filter_switches=%s",
                        rid,
                        res_sw,
                        filter_switches,
                    )
                    continue

                self.log.debug(
                    "manage_query: Resource id='%s' matched all filters (entity_name='%s', pool_name='%s', switch_ip='%s')",
                    rid,
                    res_entity,
                    res_pool,
                    res_sw,
                )
                result_dict = self.translate_gathered_results([res])[0]
                results.append(result_dict)
                if rid is not None:
                    seen_ids.add(rid)

        self.log.info(
            "manage_gathered: Gather complete, %s resource(s) matched filters",
            len(results),
        )
        self.api_responses.extend(results)
        self.changed_dict[0]["gathered"].extend(results)

    def manage_state(self):
        """Validate input and dispatch to the appropriate state handler.

        Runs ``_validate_input`` on the raw config, then converts the config list to
        typed ``ResourceManagerConfigModel`` objects via
        ``ResourceManagerDiffEngine.validate_configs`` (skipped for ``gathered`` state).
        Dispatches to ``manage_merged``, ``manage_deleted``, or
        ``manage_gathered`` depending on ``self.state``.
        """
        self.log.info("manage_state: Dispatching to state handler: state=%s", self.state)
        self._validate_input()

        if self.config and self.state != "gathered":
            self.proposed = ResourceManagerDiffEngine.validate_configs(self.config, self.state, self.nd, log=self.log)
            self.output.assign(proposed_configs=[cfg.model_dump(by_alias=True, exclude_none=True) for cfg in self.proposed])
        if self.state == "merged":
            self.log.info("manage_state: Dispatching to manage_merged()")
            self.manage_merged()
        elif self.state == "deleted":
            self.log.info("manage_state: Dispatching to manage_deleted()")
            self.manage_deleted()
        elif self.state == "gathered":
            self.log.info("manage_state: Dispatching to manage_gathered()")
            self.manage_gathered()

        self.log.info("manage_state: State handler completed for state=%s", self.state)

    def exit_module(self):
        """Build the final module result and call ``exit_json`` to return it to Ansible.

        For ``gathered`` state, passes the gathered list through ``NDOutput.format``
        so the output always includes the ``output_level`` key.
        For all other states, computes the ``changed`` flag from whether any resources
        were merged or deleted, re-queries the ND API to capture post-operation state
        (unless in check mode), assigns ``previous``/``current`` snapshots via
        ``self.output.assign``, and calls ``self.output.format`` before
        ``self.nd.module.exit_json``.
        """
        # gathered state: return gathered list via NDOutput so output_level is always present
        if self.state == "gathered":
            self.log.info(
                "exit_module: gathered state, returning %s resource(s)",
                len(self.changed_dict[0]["gathered"]),
            )
            self.output.assign(current=self.translate_gathered_results(self.existing))
            result = self.output.format(
                changed=False,
                gathered=self.changed_dict[0]["gathered"],
            )
            self.nd.module.exit_json(**result)
            return

        changed = len(self.changed_dict[0]["merged"]) > 0 or len(self.changed_dict[0]["deleted"]) > 0
        if self.nd.module.check_mode:
            self.log.info(
                "exit_module: check_mode is enabled, overriding changed=False (would have been changed=%s)",
                changed,
            )
            changed = False

        self.log.info(
            "exit_module: merged=%s, deleted=%s, gathered=%s, changed=%s, check_mode=%s",
            len(self.changed_dict[0]["merged"]),
            len(self.changed_dict[0]["deleted"]),
            len(self.changed_dict[0]["gathered"]),
            changed,
            self.nd.module.check_mode,
        )

        # Re-query to capture post-operation state for current snapshot
        if not self.nd.module.check_mode and changed:
            self._resources_fetched = False
            self._all_resources = []
            self._get_all_resources()
            self.existing = list(self._all_resources)

        self.output.assign(
            previous=self.translate_gathered_results(self.previous),
            current=self.translate_gathered_results(self.existing),
        )
        result = self.output.format(
            changed=changed,
            diff=self.changed_dict,
            response=self.api_responses,
        )
        self.nd.module.exit_json(**result)
