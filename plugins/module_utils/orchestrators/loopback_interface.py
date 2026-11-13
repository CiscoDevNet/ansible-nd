# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Loopback interface orchestrator for Nexus Dashboard (NX-OS and IOS-XE managed loopbacks).

All CRUD (create, update, delete, bulk create, bulk delete, query_one, query_all) comes from the shared templates on
`NDBaseInterfaceOrchestrator`. This module contributes the wire `interfaceType`, the managed policy set, the IOS-XE delete preflight
and the canonical IOS-XE loopback name used on the delete-side queues.
"""

from __future__ import annotations

import re
from typing import ClassVar, Sequence

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import GatheredLuceneSpec
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    LoopbackPolicyTypeEnum,
    XeLoopbackPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    parse_controller_version,
)


class LoopbackInterfaceOrchestrator(NDBaseInterfaceOrchestrator[LoopbackInterfaceModel]):  # pylint: disable=too-few-public-methods
    """
    # Summary

    Orchestrator for loopback interfaces on Nexus Dashboard. CRUD comes from `NDBaseInterfaceOrchestrator`; this class contributes the wire
    `interfaceType` (`query_interface_type`), the managed policy set (`_managed_policy_types`), the IOS-XE delete preflight (`preflight_delete`,
    `_check_overridden_removals_discovered`) and the canonical IOS-XE name helper (`_canonical_xe_loopback_name`, used by the `_delete_side_name` hook).

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist or is owned by
      another controller.
    - For mutation states, also if the fabric is in deployment-freeze mode.
    - Read-only gathered operations remain permitted during deployment freeze.
    - Via `preflight_safety` if a `csrLoopback` would be created or transitioned to on an ND 4.3.1-or-later controller.
    """

    _MANAGED_POLICY_TYPES: ClassVar[frozenset[str]] = frozenset(
        {policy_type.value for policy_type in LoopbackPolicyTypeEnum} | {policy_type.value for policy_type in XeLoopbackPolicyTypeEnum}
    )
    model_class: ClassVar[type[NDBaseModel]] = LoopbackInterfaceModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_full_modify: ClassVar[bool] = True
    supports_bulk_modify_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    interface_type: ClassVar[str] = "loopback"
    staged_delete_echo_interface_types: ClassVar[frozenset[str]] = frozenset({"loopback"})
    query_interface_type: ClassVar[str] = "loopback"
    interface_mode: ClassVar[str] = "managed"
    # TODO(4.2.1) ios-xe-loopback-remove-case: Recheck whether ND removal
    # accepts lowercase names and still generates device-side deletion.
    # IOS-XE needs the switch-canonical Loopback<N> spelling on the removal wire.
    # Lowercase removal drops intent without generating `no interface Loopback<N>`.
    xe_removal_requires_discovery: ClassVar[bool] = True
    supports_gathered_server_filtering: ClassVar[bool] = True
    gathered_lucene_spec: ClassVar[GatheredLuceneSpec] = GatheredLuceneSpec(
        base_terms=(("interfaceType", "loopback"),),
        field_map={
            ("interface_name",): "interfaceName",
        },
    )

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() uses bulk remove
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesPost
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = EpManageInterfacesRemove

    # First ND release whose request gateway rejects the `csrLoopback` policy; see `_check_csr_loopback_writable`.
    CSR_LOOPBACK_REJECTED_FROM: ClassVar[tuple[int, int, int]] = (4, 3, 1)

    def preflight_delete(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """Check IOS-XE delete spelling, ownership, and discovery before removal."""
        pairs = []
        for model_instance in model_instances:
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            self._switch_interfaces(switch_id)
            self._canonical_xe_loopback_name(model_instance.interface_name, switch_id)
            pairs.append((model_instance.interface_name, switch_id))
        self._check_xe_removal_discovered(pairs)

    def _check_overridden_removals_discovered(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """Apply the same IOS-XE delete checks to managed loopbacks removed by override."""
        if self.rest_send.params.get("state") != "overridden":
            return
        proposed = {(model.switch_ip, model.interface_name.strip().lower()) for model in model_instances}
        switch_map = self.fabric_context.switch_map
        pairs = []
        for iface in self.query_all() or []:
            switch_ip = iface.get("switchIp")
            name = str(iface.get("interfaceName") or "")
            if switch_ip in switch_map and (switch_ip, name.strip().lower()) not in proposed:
                switch_id = switch_map[switch_ip]
                self._canonical_xe_loopback_name(name, switch_id)
                pairs.append((name, switch_id))
        self._check_xe_removal_discovered(pairs)

    def _canonical_xe_loopback_name(self, name: str, switch_id: str) -> str:
        """Use canonical IOS-XE spelling so ND queues an actual switch-side remove."""
        # Normal state planning and the delete preflight have already loaded
        # the complete switch inventory. Do not add a GET during queueing.
        record = self._switch_interfaces_cache.get(switch_id, {}).get(name.strip().lower())
        if not isinstance(record, dict) or record.get("interfaceType") != "loopback":
            return name
        config_data = record.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        if network_os.get("networkOSType") != "ios-xe":
            return name
        if config_data.get("mode") == "unknown" and not network_os.get("policy"):
            raise RuntimeError(
                f"Cannot delete IOS-XE loopback {name} on {switch_id}: "
                "Nexus Dashboard has only an operational-only row and no policy from which to generate a device removal."
            )
        if not network_os.get("policy"):
            raise RuntimeError(f"Cannot delete IOS-XE loopback {name} on {switch_id}: managed policy is missing")
        match = re.fullmatch(r"loopback([0-9]+)", name.strip(), flags=re.IGNORECASE)
        if match is None:
            raise RuntimeError(f"Cannot safely canonicalize IOS-XE loopback name {name!r} on {switch_id}")
        return f"Loopback{match.group(1)}"

    def preflight_safety(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """
        # Summary

        Local safety checks for the proposed loopbacks: the shared switch-resolution and platform checks, then the `csrLoopback`
        release check (`_check_csr_loopback_writable`). This is the path both execution modes share: `NDStateMachine.manage_state`
        and the workflow executor reach it through the inherited `preflight`, and the workflow planner calls it directly for a
        check-mode plan, so a dry run reports the refusal a normal run would hit. The release check adds no request: the controller
        version is cached on the connection and the interface inventory is the one `query_all` already loaded.

        ## Raises

        ### RuntimeError

        - Propagated from `NDBaseInterfaceOrchestrator.preflight_safety`.
        - Propagated from `_check_csr_loopback_writable`.
        """
        super().preflight_safety(model_instances)
        self._check_csr_loopback_writable(model_instances)

    def _check_csr_loopback_writable(self, model_instances: Sequence[LoopbackInterfaceModel]) -> None:
        """
        # Summary

        Refuse, before any write, a `csrLoopback` that would be created or transitioned to on an ND 4.3.1-or-later controller.
        "Would be" means the proposed item carries `policyType: csrLoopback` and the switch's interface inventory (already cached by
        `query_all`, so this adds no request) either lacks the interface or holds it under another policy type. A `csrLoopback` that
        already exists as such is left alone: re-stating it issues no write. Releases below 4.3.1, and an unknown controller version,
        skip the check.

        ## Raises

        ### RuntimeError

        - If one or more interfaces would become `csrLoopback` on a controller at or above `CSR_LOOPBACK_REJECTED_FROM`.
        - Via `_resolve_switch_id` if no switch matches a model's `switch_ip` in the fabric.
        - Via `_switch_interfaces` if the interface-list request fails.
        """
        # TODO(4.3.1) csr-loopback-read-schema-name-drift
        # ND 4.3.1 validates the IOS-XE loopback policy against both halves of an inconsistent schema: the per-branch enum demands
        # `csrIntLoopback` while the discriminator mapping only accepts `csrLoopback`, so every typed csrLoopback POST and PUT is
        # rejected with HTTP 400 (4.2.1 accepts `csrLoopback`). The module cannot write the policy on 4.3.1 at all; fail here with the
        # cause instead of surfacing ND's opaque "Request validation failed". Tracked as CiscoDevNet/ansible-nd#632.
        raw_version = self.rest_send.controller_version
        version = parse_controller_version(raw_version)
        if version is None or version < self.CSR_LOOPBACK_REJECTED_FROM:
            return
        csr_value = XeLoopbackPolicyTypeEnum.CSR_LOOPBACK.value
        becoming: list[str] = []
        for model_instance in model_instances:
            if self._desired_policy_type(model_instance) != csr_value:
                continue
            switch_id = self._resolve_switch_id(model_instance.switch_ip)
            existing = self._switch_interfaces(switch_id).get(model_instance.interface_name.strip().lower()) or {}
            existing_policy = ((existing.get("configData") or {}).get("networkOS") or {}).get("policy") or {}
            if existing_policy.get("policyType") == csr_value:
                continue
            becoming.append(f"{model_instance.interface_name} ({model_instance.switch_ip})")
        if not becoming:
            return
        raise RuntimeError(
            f"ND {raw_version} rejects the csrLoopback loopback policy on create and update (its schema enum and discriminator "
            f"mapping disagree on the policy name; CiscoDevNet/ansible-nd#632), so csrLoopback cannot be configured on ND "
            f"{'.'.join(str(part) for part in self.CSR_LOOPBACK_REJECTED_FROM)} or later. Affected: {', '.join(becoming)}. "
            "Use another IOS-XE loopback policy type, or a controller release below 4.3.1."
        )

    def _delete_side_name(self, model_instance: LoopbackInterfaceModel) -> str:
        """
        # Summary

        Return the canonical IOS-XE spelling of the loopback name for the delete-side queues, via `_canonical_xe_loopback_name`. The switch is already
        resolved (and cached) by the base `delete`, so this makes no request.

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id` if no switch matches the model's `switch_ip` in the fabric.
        - Via `_canonical_xe_loopback_name` if the IOS-XE loopback has no managed policy or its name cannot be canonicalized.
        """
        return self._canonical_xe_loopback_name(model_instance.interface_name, self._resolve_switch_id(model_instance.switch_ip))

    def _managed_policy_types(self) -> set[str]:
        """
        # Summary

        Return the loopback policy types this module manages - the union of NX-OS (`loopback`, `ipfmLoopback`, `mplsLoopback` - see
        `LoopbackPolicyTypeEnum`) and IOS-XE (`iosXeLoopback`, `iosXeLoopbackShutNoshut`, `iosXeUnderlayLoopback`, `iosXeInternalLoopback`,
        `csrLoopback`, `csr1kvLoopback` - see `XeLoopbackPolicyTypeEnum`) policy types. The `csrLoopback` branch's wire name is lab-verified
        (2026-07-18): the ND 4.2.1 OpenAPI READ schema lists it as `csrIntLoopback`, but the wire echoes `csrLoopback` on reads too (drift recorded
        in the bug-tracker vault).

        IOS-XE's `iosXeUnderlayLoopback` is user-creatable (unlike NX-OS's `underlayLoopback`, which is system-provisioned) and is therefore
        included in the managed set. System-provisioned loopbacks (e.g. NX-OS Loopback0 routing, Loopback1 VTEP with
        `policyType: "underlayLoopback"`) and the `userDefined` policy type are excluded - those are out of scope for this module.

        ## Raises

        None
        """
        return {policy_type.value for policy_type in LoopbackPolicyTypeEnum} | {policy_type.value for policy_type in XeLoopbackPolicyTypeEnum}

    @staticmethod
    def _is_managed_loopback(interface: object) -> bool:
        """
        Return whether a controller response represents a loopback policy
        managed by this module.
        """
        if not isinstance(interface, dict):
            return False

        if interface.get("interfaceType") != "loopback":
            return False

        config_data = interface.get("configData")
        if not isinstance(config_data, dict):
            return False

        network_os = config_data.get("networkOS")
        if not isinstance(network_os, dict):
            return False

        policy = network_os.get("policy")
        if not isinstance(policy, dict):
            return False

        return policy.get("policyType") in LoopbackInterfaceOrchestrator._MANAGED_POLICY_TYPES

    def _configure_lucene_endpoint(self, api_endpoint) -> None:
        """
        Include the complete config in Lucene results for local filtering.
        """
        api_endpoint.endpoint_params.config_only = False

    def query_all(
        self,
        model_instance: NDBaseModel | None = None,
        gathered_filters: list[dict] | None = None,
        **kwargs,
    ) -> ResponseType:
        """
        # Summary

        Validate the fabric context and query interfaces, filtering for the loopback policy types managed by this
        module - the union of NX-OS (`loopback`, `ipfmLoopback`, `mplsLoopback` - see `LoopbackPolicyTypeEnum`) and
        IOS-XE (`iosXeLoopback`, `iosXeLoopbackShutNoshut`, `iosXeUnderlayLoopback`, `iosXeInternalLoopback`,
        `csrLoopback`, `csr1kvLoopback` - see `XeLoopbackPolicyTypeEnum`) policy types. The `csrLoopback` branch's
        wire name is lab-verified (2026-07-18): the ND 4.2.1 OpenAPI READ schema lists it as `csrIntLoopback`, but
        the wire echoes `csrLoopback` on reads too (drift recorded in the bug-tracker vault).

        IOS-XE's `iosXeUnderlayLoopback` is user-creatable (unlike NX-OS's `underlayLoopback`, which is
        system-provisioned) and is therefore included in the managed set above. System-provisioned loopbacks (e.g.
        NX-OS Loopback0 routing, Loopback1 VTEP with `policyType: "underlayLoopback"`) and the `userDefined` policy
        type are excluded - those are out of scope for this module.

        For gathered state, switch and interface-name criteria reduce the endpoint query scope; all other criteria
        are applied by the generic local gathered filter.

        Runs `validate_prerequisites` before querying. Gathered operations require a
        readable fabric and remain permitted during deployment freeze; management
        states require a modifiable fabric and remain blocked by deployment freeze.

        Each returned interface dict is enriched with a `switch_ip` field so that `LoopbackInterfaceModel` can be constructed
        with the composite identifier `(switch_ip, interface_name)`.

        ## Raises

        ### RuntimeError

        - If the fabric does not exist on the target ND node.
        - If the fabric is in deployment-freeze mode for a management state.
        - If the query API request fails.
        """
        try:
            self.validate_prerequisites()
            if gathered_filters is None:
                return self._query_all_for_management_states()
            return self._query_all_for_gathered(gathered_filters)

        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e

    def _query_all_for_management_states(self) -> list[dict]:
        """
        Return managed loopbacks for merged, replaced, overridden, and deleted
        states, reusing the shared per-switch interface inventory cache.
        """
        candidates_by_switch: list[tuple[str, list[dict]]] = []

        for switch_ip, switch_id in self._switches_to_query().items():
            candidates = list(self._switch_interfaces(switch_id).values())
            candidates_by_switch.append((switch_ip, candidates))

        return self._collect_managed_loopbacks(candidates_by_switch)

    def _query_all_for_gathered(self, gathered_filters: list[dict]) -> list[dict]:
        """Run server-filtered gathered requests."""
        candidates_by_switch: list[tuple[str, list[dict]]] = []

        query_plan = self._build_gathered_query_plan(gathered_filters)

        for switch_ip, (switch_id, expressions) in query_plan.items():
            switch_candidates = []

            for expression in sorted(expressions):
                switch_candidates.extend(
                    self._query_interfaces_with_lucene(
                        switch_id=switch_id,
                        expression=expression,
                    )
                )

            candidates_by_switch.append((switch_ip, switch_candidates))

        return self._collect_managed_loopbacks(candidates_by_switch)

    def _collect_managed_loopbacks(
        self,
        candidates_by_switch: list[tuple[str, list[dict]]],
    ) -> list[dict]:
        """Validate, enrich, and deduplicate responses."""
        all_loopbacks = []
        seen_identifiers: set[tuple[str, str]] = set()

        for switch_ip, candidates in candidates_by_switch:
            for interface in candidates:
                if not self._is_managed_loopback(interface):
                    continue

                interface_name = interface.get("interfaceName")
                if not interface_name:
                    continue

                identifier = (switch_ip, interface_name)

                if identifier in seen_identifiers:
                    continue

                enriched = dict(interface)
                enriched["switchIp"] = switch_ip

                seen_identifiers.add(identifier)
                all_loopbacks.append(enriched)

        return all_loopbacks
