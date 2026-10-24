# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone NX-OS Ethernet dot1q-tunnel host orchestration."""

from __future__ import annotations

from copy import deepcopy
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    MemberPolicyDisposition,
    classify_member_policy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class EthernetDot1qTunnelHostInterfaceOrchestrator(EthernetBaseOrchestrator):
    """Manage only NX-OS ``dot1qTunnelHost`` Ethernet policy assignments.

    The base retains fabric ownership, protected-member, bulk create,
    physical reset, and exact-target deployment safeguards. Dot1q member
    policies are deliberately outside this module's managed scope.
    """

    model_class: ClassVar[type[NDBaseModel]] = EthernetDot1qTunnelHostInterfaceModel
    MEMBER_FAMILY: ClassVar[str] = ""
    # Workflow bulk modify is deferred until the workflow family is added and
    # its dot1q full-policy request/partial-outcome contract is live-qualified.
    supports_bulk_full_modify: ClassVar[bool] = False

    def _managed_policy_types(self) -> set[str]:
        """Select host policies, never dot1q port-channel or vPC members."""
        return {"dot1qTunnelHost"}

    def _prepare_member_intent(self, model_instance: NDBaseModel, existing_data: dict | None) -> bool:
        """Refuse every member policy with a dot1q-host-specific explanation."""
        policy_type = self._existing_policy_type(existing_data)
        if classify_member_policy(policy_type) != MemberPolicyDisposition.NOT_MEMBER:
            raise RuntimeError(
                f"Interface {model_instance.interface_name} uses member policy '{policy_type}'; "
                "the dot1q-tunnel host module does not manage port-channel members."
            )
        return False

    @staticmethod
    def _without_empty_description(data: dict | None) -> dict | None:
        """Prepare a 4.3.1 retry only for explicit empty dot1q descriptions."""
        if not isinstance(data, dict):
            return None
        retry = deepcopy(data)
        interfaces = retry.get("interfaces")
        rows = interfaces if isinstance(interfaces, list) else [retry]
        found = False
        for row in rows:
            if not isinstance(row, dict):
                continue
            policy = ((row.get("configData") or {}).get("networkOS") or {}).get("policy")
            if isinstance(policy, dict) and policy.get("policyType") == "dot1qTunnelHost" and policy.get("description") == "":
                policy.pop("description")
                found = True
        return retry if found else None

    def _request(
        self,
        path: str,
        verb: HttpVerbEnum,
        data: dict | None = None,
        not_found_ok: bool = False,
        operation_type: OperationType = OperationType.QUERY,
    ) -> ResponseType:
        """Retry only ND's exact empty-description 400 with the field omitted.

        The first request preserves 4.2.1's explicit-empty clearing behavior.
        ND 4.3.1 rejects that body but clears an omitted description on PUT.
        No timeout, transport error, or partial 207 is retried.
        """
        retry = self._without_empty_description(data) if verb in (HttpVerbEnum.POST, HttpVerbEnum.PUT) else None
        if retry is None:
            return super()._request(path, verb, data, not_found_ok, operation_type)
        response_count = self.rest_send.response_count
        try:
            return super()._request(path, verb, data, not_found_ok, operation_type)
        except Exception:
            if not self._rejected_empty_description(response_count):
                raise
            return super()._request(path, verb, retry, not_found_ok, operation_type)
