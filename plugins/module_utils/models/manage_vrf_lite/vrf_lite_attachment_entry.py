# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from copy import deepcopy
from typing import ClassVar, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLiteConnectionModel,
)


class VrfLiteAttachmentEntry(NDBaseModel):
    """Flat per-switch VRF Lite attachment row used by the state machine.

    Represents one (vrf_name, switch_ip) attachment row. The state machine
    diffs proposed entries against existing entries at this granularity, so
    classification into create / update / delete happens generically and the
    orchestrator only needs to build a single attachment row per call.
    """

    identifiers: ClassVar[list[str]] = ["vrf_name", "switch_ip"]
    identifier_strategy: ClassVar[Literal["composite"]] = "composite"
    exclude_from_diff: ClassVar[set[str]] = {"deploy"}

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    vrf_name: str = Field(alias="vrf_name", min_length=1, max_length=64)
    switch_ip: str = Field(alias="switch_ip", min_length=1, max_length=128)
    vlan_id: Optional[int] = Field(default=None, alias="vlan_id", ge=1, le=4094)
    deploy: Optional[bool] = Field(default=None, alias="deploy")
    import_evpn_rt: Optional[str] = Field(default=None, alias="import_evpn_rt")
    export_evpn_rt: Optional[str] = Field(default=None, alias="export_evpn_rt")
    extensions: Optional[list[VrfLiteConnectionModel]] = Field(default=None, alias="extensions")

    @field_validator("import_evpn_rt", "export_evpn_rt")
    @classmethod
    def _coerce_empty_string_to_none(cls, value: Optional[str]) -> Optional[str]:
        """Normalize empty-string EVPN RT values to None.

        The query layer may return '' for absent EVPN RT fields on a switch.
        Coercing to None ensures they are excluded from diff comparisons via
        exclude_none=True in to_diff_dict, preventing false 'changed'
        classifications on replace/override states.
        """
        if value is not None and not str(value).strip():
            return None
        return value

    def merge(self, other: "VrfLiteAttachmentEntry") -> "VrfLiteAttachmentEntry":
        """Merge another entry into this one.

        Custom behavior:
        - scalar fields follow NDBaseModel merge semantics (only explicitly set
          fields on ``other`` are applied)
        - ``extensions`` list is merged by ``interface`` so merged-state runs
          preserve existing extensions that the user did not mention
        """
        if not isinstance(other, type(self)):
            raise TypeError("VrfLiteAttachmentEntry.merge requires both models to be the same type")

        merged_data = self.model_dump(by_alias=False, exclude_none=False)
        incoming_data = other.model_dump(by_alias=False, exclude_none=False, exclude_unset=True)

        for field, value in incoming_data.items():
            if field == "extensions":
                continue
            if value is None:
                continue
            merged_data[field] = value

        if "extensions" in incoming_data and incoming_data.get("extensions") is not None:
            current_extensions = self.extensions or []
            incoming_extensions = other.extensions or []

            merged_extensions: dict[str, VrfLiteConnectionModel] = {}
            for item in current_extensions:
                key = str(item.interface).strip().lower()
                merged_extensions[key] = deepcopy(item)

            for item in incoming_extensions:
                key = str(item.interface).strip().lower()
                existing_item = merged_extensions.get(key)
                if existing_item is None:
                    merged_extensions[key] = deepcopy(item)
                else:
                    merged_extensions[key] = existing_item.merge(item)

            merged_data["extensions"] = [
                item.model_dump(by_alias=False, exclude_none=False)
                for _key, item in sorted(merged_extensions.items(), key=lambda kv: kv[0])
            ]

        return type(self).model_validate(merged_data, by_name=True, by_alias=True)
