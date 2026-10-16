# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Identifier-only payload for the bulk Smart Switch deboarding action."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field


class SmartSwitchDeboardEntry(BaseModel):
    """Deboard one association without sending onboarding-only metadata."""

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=False, extra="forbid")
    switch_id: str = Field(alias="switchId", min_length=1, strict=True)


class SmartSwitchDeboardRequestModel(BaseModel):
    """Model the smartSwitchIntegrationBodyDeboard OpenAPI wrapper."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    smart_switch_integrations: list[SmartSwitchDeboardEntry] = Field(alias="smartSwitchIntegrations", strict=True)
