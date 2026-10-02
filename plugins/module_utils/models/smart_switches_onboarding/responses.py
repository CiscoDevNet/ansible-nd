# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Typed onboarding success/failure envelope with a shared entry schema."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field


class SmartSwitchOnboardingResultEntry(BaseModel):
    """Both result lists share this schema; name is required for correlation.

    OpenAPI does not require status/message or enumerate status values. Preserve
    them as controller evidence; list membership determines the known outcome.
    """

    model_config = ConfigDict(str_strip_whitespace=False)
    name: str = Field(strict=True, min_length=1)
    status: str | None = Field(default=None, strict=True)
    message: str | None = Field(default=None, strict=True)


class SmartSwitchOnboardingResultsModel(BaseModel):
    """Model smartSwitchOnboardingResultsType and validate each typed list."""

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=False)
    success_results: list[SmartSwitchOnboardingResultEntry] = Field(default_factory=list, alias="successResults", strict=True)
    failure_results: list[SmartSwitchOnboardingResultEntry] = Field(default_factory=list, alias="failureResults", strict=True)
