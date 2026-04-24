# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Read-model for ``state=gathered`` output.

``GatheredPolicy`` is a lightweight model that represents a policy as
returned by the ND API, keyed by ``policyId``.  It is used exclusively
by ``_handle_gathered_state()`` for:

    - Deserialising raw API response dicts via ``from_response()``
    - De-duplicating policies via ``NDConfigCollection`` (keyed by ``policy_id``)
    - Serialising to playbook-compatible config via ``to_gathered_config()``

This model is separate from ``PolicyCreate`` because:

    - It uses ``policy_id`` as the single identifier (unique per policy),
      whereas ``PolicyCreate`` uses a composite key for write operations.
    - It carries read-only fields (``policy_id``) that are not part of the
      create/update payload.
    - The ``to_gathered_config()`` output format must match the playbook
      ``config[]`` schema exactly for copy-paste round-trips.
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

import json
import logging
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

log = logging.getLogger("nd.GatheredPolicy")


class GatheredPolicy(NDBaseModel):
    """Read-model for a policy returned by the ND API.

    Keyed by ``policy_id`` for ``NDConfigCollection`` dedup.

    Fields mirror the ND policy response keys (camelCase aliases)
    that are needed for gathered output.  Extra API response keys
    (``generatedConfig``, ``markDeleted``, ``createTimestamp``, etc.)
    are silently dropped by ``model_config.extra = "ignore"`` inherited
    from ``NDBaseModel``.
    """

    # --- NDBaseModel ClassVars ---
    identifiers: ClassVar[list[str]] = ["policy_id"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    exclude_from_diff: ClassVar[set[str]] = set()

    # Fields excluded from config output (internal / not user-facing)
    config_exclude_fields: ClassVar[set[str]] = {
        "entity_type",
        "entity_name",
        "source",
        "secondary_entity_name",
        "secondary_entity_type",
    }

    # --- Fields ---
    policy_id: str = Field(
        ...,
        alias="policyId",
        description="Controller-assigned policy ID (e.g., POLICY-28440)",
    )
    switch_id: str = Field(
        ...,
        alias="switchId",
        description="Switch serial number",
    )
    template_name: str = Field(
        default="",
        alias="templateName",
        description="Name of the policy template",
    )
    description: str | None = Field(
        default="",
        description="Policy description",
    )
    priority: int | None = Field(
        default=500,
        description="Policy priority (1-2000)",
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
    secondary_entity_name: str | None = Field(
        default=None,
        alias="secondaryEntityName",
    )
    secondary_entity_type: str | None = Field(
        default=None,
        alias="secondaryEntityType",
    )

    @classmethod
    def from_api_policy(cls, policy: dict[str, Any]) -> GatheredPolicy:
        """Create a GatheredPolicy from a raw ND API policy dict.

        Handles the ``templateInputs`` field which may be a JSON-encoded
        string in the API response.  Parses it into a dict before model
        validation.

        Also handles the ``nvPairs`` alias that some API responses use
        instead of ``templateInputs``.

        Args:
            policy: Raw policy dict from the ND API.

        Returns:
            A validated ``GatheredPolicy`` instance.
        """
        data = dict(policy)

        # Normalise templateInputs: may be a JSON string or absent
        raw_inputs = data.get("templateInputs") or data.get("nvPairs") or {}
        if isinstance(raw_inputs, str):
            try:
                raw_inputs = json.loads(raw_inputs)
            except (json.JSONDecodeError, ValueError):
                log.warning("Failed to parse templateInputs for %s: %r", data.get("policyId", "?"), raw_inputs)
                raw_inputs = {}
        data["templateInputs"] = raw_inputs

        # Ensure switchId is present (some responses use serialNumber)
        if "switchId" not in data and "serialNumber" in data:
            data["switchId"] = data["serialNumber"]

        return cls.from_response(data)

    def to_gathered_config(self) -> dict[str, Any]:
        """Convert to the playbook-compatible gathered config format.

        The output dict matches what ``state=merged`` expects so the user
        can copy-paste gathered output directly into a playbook.

        Output keys:
            - name: template name
            - policy_id: controller-assigned policy ID
            - switch: [{serial_number: ...}]
            - description: policy description
            - priority: policy priority
            - template_inputs: cleaned template inputs
            - create_additional_policy: always False for gathered

        Returns:
            Dict in playbook config format.
        """
        return {
            "name": self.template_name,
            "policy_id": self.policy_id,
            "switch": [{"serial_number": self.switch_id}],
            "description": self.description or "",
            "priority": self.priority or 500,
            "template_inputs": self.template_inputs or {},
            "create_additional_policy": False,
        }
