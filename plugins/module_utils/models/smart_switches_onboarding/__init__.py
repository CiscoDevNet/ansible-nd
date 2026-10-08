# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Smart Switch association, request and controller-response models."""

from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding.association import SmartSwitchOnboardingModel
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding.requests import SmartSwitchDeboardEntry, SmartSwitchDeboardRequestModel
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding.responses import (
    SmartSwitchOnboardingResultEntry,
    SmartSwitchOnboardingResultsModel,
)

__all__ = [
    "SmartSwitchOnboardingModel",
    "SmartSwitchDeboardEntry",
    "SmartSwitchDeboardRequestModel",
    "SmartSwitchOnboardingResultEntry",
    "SmartSwitchOnboardingResultsModel",
]
