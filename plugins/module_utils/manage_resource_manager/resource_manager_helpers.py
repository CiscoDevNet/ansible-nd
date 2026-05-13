# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import ipaddress

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_config_model import (
    ResourceManagerConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_request_model import (
    ResourceManagerRequest,
    FabricScope,
    DeviceScope,
    DeviceInterfaceScope,
    DevicePairScope,
    LinkScope,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.resource_manager_diff import ResourceManagerDiffEngine


class ResourceManagerResourceHelpersMixin:
    """Shared resource access, payload, translation, and gathered-filter helpers."""

    # ------------------------------------------------------------------
    # Resource attribute accessors (handle both ResourceManagerResponse and raw dict)
    # ------------------------------------------------------------------

    def _attr(self, resource, model_attr, dict_key):
        """Return a field value from a resource that may be a model instance or a raw dict.

        Delegates to ``ResourceManagerDiffEngine._resource_attr`` so diffing,
        gathered output, and filtering share the same model/dict access behavior.

        Args:
            resource: A ``ResourceManagerResponse`` model instance or a plain dict.
            model_attr: Attribute name to access on a model instance (snake_case).
            dict_key: Key to access on a raw dict (camelCase, e.g. ``'entityName'``).

        Returns:
            The field value, or None if neither path resolves.
        """
        value = ResourceManagerDiffEngine._resource_attr(resource, model_attr, dict_key)
        self.log.debug("_attr: resolved '%s'/'%s' from %s: %s", model_attr, dict_key, type(resource).__name__, value)
        return value

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
        scope_details = ResourceManagerDiffEngine._scope_details(resource)
        if scope_details is None:
            self.log.debug("_get_scope_type: unrecognised resource type %s, returning None", type(resource))
            return None
        mapped = ResourceManagerDiffEngine._extract_scope_type(scope_details, log=self.log)
        self.log.debug("_get_scope_type: mapped scope to playbook scope '%s'", mapped)
        return mapped

    def _get_switch_ip(self, resource):
        """Return the primary switch IP/ID from scopeDetails (src switch for device_pair/link).

        Delegates to ResourceManagerDiffEngine._extract_scope_switch_key_val for model
        instances so that all scope types are handled uniformly:
          - fabric              → None
          - device / device_interface → switch_ip
          - device_pair / link  → src_switch_ip
        """
        scope_details = ResourceManagerDiffEngine._scope_details(resource)
        if scope_details is not None:
            value = ResourceManagerDiffEngine._extract_scope_switch_key_val(
                scope_details, switch_key="switch_ip", src_switch_key="src_switch_ip", log=self.log
            )
            self.log.debug("_get_switch_ip: from scope_details, switch_ip=%s", value)
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

    def _build_fabric_scope(self, _switch_id=None, _entity_name=None):
        """Build fabric-level scope details."""
        return FabricScope(fabric_name=self.fabric)

    def _build_device_scope(self, switch_id=None, _entity_name=None):
        """Build device-level scope details."""
        return DeviceScope(switch_id=switch_id)

    def _build_device_interface_scope(self, switch_id=None, entity_name=None):
        """Build device-interface scope details from ``entity_name``."""
        parts = (entity_name or "").split("~", 1)
        interface_name = parts[1] if len(parts) > 1 else None
        if not interface_name:
            self.log.warning(
                "_build_device_interface_scope: could not parse interfaceName from entity_name='%s'",
                entity_name,
            )
        return DeviceInterfaceScope(switch_id=switch_id, interface_name=interface_name)

    def _build_device_pair_scope(self, _switch_id=None, entity_name=None):
        """Build device-pair scope details from ``entity_name``."""
        parts = (entity_name or "").split("~")
        src_switch_id = parts[0] if len(parts) > 0 else None
        dst_switch_id = parts[1] if len(parts) > 1 else None
        return DevicePairScope(src_switch_id=src_switch_id, dst_switch_id=dst_switch_id)

    def _build_link_scope(self, _switch_id=None, entity_name=None):
        """Build link scope details from ``entity_name``."""
        parts = (entity_name or "").split("~")
        src_switch_id = parts[0] if len(parts) > 0 else None
        src_interface_name = parts[1] if len(parts) > 1 else None
        dst_switch_id = parts[2] if len(parts) > 2 else None
        dst_interface_name = parts[3] if len(parts) > 3 else None
        return LinkScope(
            src_switch_id=src_switch_id,
            src_interface_name=src_interface_name,
            dst_switch_id=dst_switch_id,
            dst_interface_name=dst_interface_name,
        )

    def _build_scope_details(self, scope_type, switch_ip=None, entity_name=None):
        """Build the scopeDetails model for the ND Manage API.

        ``switch_ip`` is the translated switchId (serial number) of the source switch
        from the playbook ``switch`` list.  The entity_name encodes the full topology
        (src and dst) as tilde-separated fields for multi-switch scopes.

          - fabric:           FabricScope(fabricName)
          - device:           DeviceScope(switchId)
          - device_interface: DeviceInterfaceScope(switchId, interfaceName)
          - device_pair:      DevicePairScope(srcSwitchId, dstSwitchId)
          - link:             LinkScope(src/dst switch and interface details)
        """
        self.log.debug(
            "_build_scope_details: scope_type=%s, switch_ip=%s, entity_name=%s, fabric=%s",
            scope_type,
            switch_ip,
            entity_name,
            self.fabric,
        )

        scope_builders = {
            "fabric": self._build_fabric_scope,
            "device": self._build_device_scope,
            "device_interface": self._build_device_interface_scope,
            "device_pair": self._build_device_pair_scope,
            "link": self._build_link_scope,
        }
        builder = scope_builders.get(scope_type)
        if builder is None:
            raise ValueError("Unsupported scope_type '{0}' while building scope details".format(scope_type))

        result = builder(switch_ip, entity_name)
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
          entity_name, pool_type, pool_name, scope_type, resource[, switches].
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
                item["switches"] = [switch_ip]
                self.log.debug(
                    "translate_gathered_results: [%s] entity='%s' — non-fabric scope ('%s'), adding switches=['%s'] to item",
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
        # resources (no 'switches' key) are passed through unchanged.
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
                sw_list = item.get("switches") or []
                for sw in sw_list:
                    if sw not in merged[key].get("switches", []):
                        merged[key]["switches"].append(sw)
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

    def _get_switch_id(self, resource):
        """Return the primary switch ID from scopeDetails for gathered filtering."""
        scope_details = ResourceManagerDiffEngine._scope_details(resource)
        if scope_details is None:
            return None
        return ResourceManagerDiffEngine._extract_scope_switch_key_val(
            scope_details,
            switch_key="switch_id",
            src_switch_key="src_switch_id",
            log=self.log,
        )

    @staticmethod
    def _filter_has_active_criteria(filter_item):
        """Return True when a gathered filter item has at least one criterion."""
        return bool(filter_item.get("entity_name") or filter_item.get("pool_name") or filter_item.get("switches"))

    def _resource_matches_filter(self, resource, filter_item):
        """Return True when a resource matches one gathered filter item."""
        resource_id = self._get_resource_id(resource)
        resource_entity = self._get_entity_name(resource)
        resource_pool = self._get_pool_name(resource)
        resource_switch_id = self._get_switch_id(resource)

        filter_entity = filter_item.get("entity_name")
        filter_pool = filter_item.get("pool_name")
        filter_switches = filter_item.get("switches") or []

        if filter_entity and not self._entity_names_match(resource_entity, filter_entity):
            self.log.debug(
                "manage_gathered: skipping resource id='%s', entity_name mismatch: resource='%s' vs filter='%s'",
                resource_id,
                resource_entity,
                filter_entity,
            )
            return False

        if filter_pool and resource_pool != filter_pool:
            self.log.debug(
                "manage_gathered: skipping resource id='%s', pool_name mismatch: resource='%s' vs filter='%s'",
                resource_id,
                resource_pool,
                filter_pool,
            )
            return False

        if filter_switches and resource_switch_id not in filter_switches:
            self.log.debug(
                "manage_gathered: skipping resource id='%s', switchId not in filter: resource_switch='%s', filter_switches=%s",
                resource_id,
                resource_switch_id,
                filter_switches,
            )
            return False

        self.log.debug(
            "manage_gathered: resource id='%s' matched filter (entity_name='%s', pool_name='%s', switch_id='%s')",
            resource_id,
            resource_entity,
            resource_pool,
            resource_switch_id,
        )
        return True

    def _apply_gathered_filters(self):
        """Apply gathered config filters to cached resources and return translated results."""
        seen_ids = set()
        results = []

        for filter_item in self.config:
            if not self._filter_has_active_criteria(filter_item):
                self.log.debug(
                    "manage_gathered: skipping empty filter item (entity_name=%s, pool_name=%s, switches=%s)",
                    filter_item.get("entity_name"),
                    filter_item.get("pool_name"),
                    filter_item.get("switches") or [],
                )
                continue

            self.log.debug(
                "manage_gathered: applying filter: entity_name=%s, pool_name=%s, switches=%s",
                filter_item.get("entity_name"),
                filter_item.get("pool_name"),
                filter_item.get("switches") or [],
            )

            for resource in self._all_resources:
                resource_id = self._get_resource_id(resource)
                if resource_id is not None and resource_id in seen_ids:
                    self.log.debug(
                        "manage_gathered: skipping resource id='%s' already included by an earlier filter",
                        resource_id,
                    )
                    continue

                if not self._resource_matches_filter(resource, filter_item):
                    continue

                translated = self.translate_gathered_results([resource])
                if translated:
                    results.append(translated[0])
                if resource_id is not None:
                    seen_ids.add(resource_id)

        return results
