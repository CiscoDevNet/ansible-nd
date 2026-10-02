# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Small synthetic models shared by planning and outcome contract tests."""

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection


class PlanModel(NDBaseModel):
    identifiers: ClassVar[list[str]] = ["name"]
    identifier_strategy: ClassVar[str] = "single"
    replacement_preserve_fields: ClassVar[set[str]] = {"dynamic"}
    name: str
    value: str = "default"
    dynamic: str | None = None
    is_unsupported_policy: bool = False

    def describe_unsupported_policy(self):
        return "Unsupported object"


def collection(*items):
    return NDConfigCollection(PlanModel, list(items))
