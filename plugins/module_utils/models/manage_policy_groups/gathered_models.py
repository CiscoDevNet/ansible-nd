# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Read-model for ``state=gathered`` output of policy groups.

``GatheredPolicyGroup`` is a lightweight model that represents a policy group
as returned by the ND API, keyed by ``policyId``.  It is used exclusively
by the gathered state handler for:

    - Deserialising raw API response dicts via ``from_api_response()``
    - De-duplicating policy groups via ``NDConfigCollection`` (keyed by ``policy_id``)
    - Serialising to playbook-compatible config via ``to_gathered_config()``

This model is separate from ``PolicyGroupCreate`` because:

    - It uses ``policy_id`` as the single identifier (unique per policy group),
      whereas ``PolicyGroupCreate`` uses a composite key for write operations.
    - It carries read-only fields (``policy_id``) that are not part of the
      create/update payload.
    - The ``to_gathered_config()`` output format matches the playbook
      ``config[]`` schema for copy-paste round-trips.
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

import json
import logging
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.constants import SYSTEM_INJECTED_TEMPLATE_KEYS
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

log = logging.getLogger("nd.GatheredPolicyGroup")


class GatheredPolicyGroup(NDBaseModel):
    """Read-model for a policy group returned by the ND API.

    Keyed by ``policy_id`` for ``NDConfigCollection`` dedup.

    Fields mirror the ND policy group response keys (camelCase aliases)
    needed for gathered output.  Extra API response keys are silently
    dropped by ``model_config.extra = "ignore"`` inherited from ``NDBaseModel``.
    """

    # --- NDBaseModel ClassVars ---
    identifiers: ClassVar[list[str]] = ["policy_id"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    exclude_from_diff: ClassVar[set] = set()

    # --- Fields ---
    policy_id: str = Field(
        ...,
        alias="policyId",
        description="Controller-assigned policy group ID (e.g., POLICY-GROUP-143310)",
    )
    switch_ids: list[str] = Field(
        default_factory=list,
        alias="switchIds",
        description="List of switch serial numbers",
    )
    template_name: str = Field(
        default="",
        alias="templateName",
        description="Name of the policy template",
    )
    description: str | None = Field(
        default="",
        description="Policy group description",
    )
    priority: int | None = Field(
        default=500,
        description="Policy group priority (1-2000)",
    )
    entity_type: str | None = Field(
        default=None,
        alias="entityType",
        description="Entity type (switch, configProfile, interface)",
    )
    entity_name: str | None = Field(
        default=None,
        alias="entityName",
        description="Entity name",
    )
    source: str | None = Field(
        default=None,
        description="Policy source",
    )
    template_inputs: dict[str, Any] | None = Field(
        default=None,
        alias="templateInputs",
        description="Template input parameters",
    )

    @classmethod
    def from_api_policy_group(cls, group: dict[str, Any]) -> "GatheredPolicyGroup":
        """Create a GatheredPolicyGroup from a raw ND API policy group dict.

        Handles ``templateInputs`` which may be a JSON-encoded string in the
        API response.

        Args:
            group: Raw policy group dict from the ND API.

        Returns:
            A validated ``GatheredPolicyGroup`` instance.
        """
        data = dict(group)

        # Normalise templateInputs: may be a JSON string or absent
        raw_inputs = data.get("templateInputs") or data.get("nvPairs") or {}
        if isinstance(raw_inputs, str):
            try:
                raw_inputs = json.loads(raw_inputs)
            except (json.JSONDecodeError, ValueError):
                log.warning(
                    "Failed to parse templateInputs for %s: %r",
                    data.get("policyId", "?"),
                    raw_inputs,
                )
                raw_inputs = {}
        data["templateInputs"] = raw_inputs

        return cls.from_response(data)

    def to_gathered_config(self) -> dict[str, Any]:
        """Convert to the playbook-compatible gathered config format.

        The output dict matches what ``state=merged`` expects so the user
        can copy-paste gathered output directly into a playbook.

        Output keys:
            - name: template name
            - policy_id: controller-assigned policy group ID
            - description: policy group description
            - switch_ids: list of switch serial numbers
            - priority: policy group priority
            - template_inputs: template input parameters

        Returns:
            Dict in playbook config format.
        """
        # Resolve effective priority: the controller may store the user-set
        # priority inside templateInputs.PRIORITY (e.g. for switch_freeform)
        # and reset the top-level priority to 0.  Prefer templateInputs.PRIORITY
        # when available so gathered output is round-trip compatible.
        #
        # IMPORTANT: do NOT substitute a "500" default when the server returns
        # ``priority=0``.  The controller uses 0 as the server-side "use default"
        # sentinel and will keep returning 0 on the next GET; emitting 500 here
        # would break idempotency on round-trip (the want model would be 500,
        # the next have would be 0).
        effective_priority = self.priority if self.priority is not None else 0
        if self.template_inputs and "PRIORITY" in self.template_inputs:
            try:
                effective_priority = int(self.template_inputs["PRIORITY"])
            except (ValueError, TypeError):
                pass  # Fall back to top-level priority

        config = {
            "name": self.template_name,
            "policy_id": self.policy_id,
            "description": self.description or "",
            "switch_ids": self.switch_ids or [],
            "priority": effective_priority,
        }

        if self.template_inputs:
            cleaned_ti = {k: v for k, v in self.template_inputs.items() if k not in SYSTEM_INJECTED_TEMPLATE_KEYS}
            if cleaned_ti:
                config["template_inputs"] = cleaned_ti
        return config
