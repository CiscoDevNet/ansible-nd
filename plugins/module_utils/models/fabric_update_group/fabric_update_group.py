# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic model for a fabric update group on Nexus Dashboard.

A fabric update group ties together a set of switches in a fabric with the image / package install plan
and orchestration knobs (execution mode, contingency, analysis, maintenance, reports) used by the
Fabric Software Management workflow. Identifier: `update_group_name` (single, fabric-scoped).
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)


class InstallImageDataModel(NDNestedModel):
    """
    # Summary

    Install image data sub-block of a fabric update group.

    Wire shape (under `installImageData`):

    ```json
    {
      "epldImageName": "n9000-epld.9.3.13.img",
      "nosImageName": "nxos.9.3.13.bin",
      "installPackageNames": ["nxos.CSC...rpm"],
      "uninstallPackage": true
    }
    ```

    ## Raises

    None
    """

    nos_image_name: str | None = Field(default=None, alias="nosImageName")
    epld_image_name: str | None = Field(default=None, alias="epldImageName")
    install_package_names: list[str] | None = Field(default=None, alias="installPackageNames")
    uninstall_package: bool | None = Field(default=None, alias="uninstallPackage")


class UpdateReportCheckModel(NDNestedModel):
    """
    # Summary

    Item in the `updateReportChecks` list. Each item names a pre / post upgrade report check.

    Wire shape:

    ```json
    { "reportCheckName": "sh_version" }
    ```

    ## Raises

    None
    """

    # `report_check_name` is optional on the MODEL so a GET that returns an item lacking it cannot abort
    # the whole module run (NDStateMachine validates every existing group via from_response). ND's own
    # embedded `updateGroup.updateReportChecks` item schema does NOT mark reportCheckName required
    # (verified live, ND 4.2.1), so we must not be stricter than ND on read. User INPUT is still
    # required: the argument spec sets `report_check_name` required=True, which validates before the
    # model is built, so a user must always supply a name.
    report_check_name: str | None = Field(default=None, alias="reportCheckName")


# Enum literal aliases for readability
ExecutionLiteral = Literal["parallel", "serial"]
ContingencyLiteral = Literal["continue", "pause"]
AnalysisLiteral = Literal["snapshot", "noAnalysis", "fullAnalysis", "usePreExistingAnalysis"]
ReportSelectionLiteral = Literal["noReport", "basic", "advanced"]
ReportsLiteral = Literal[
    "noReport",
    "usePreExistingReports",
    "useDefaultPreAndPostReports",
    "useAdvancePreAndPostReports",
]


class FabricUpdateGroupModel(NDBaseModel):
    """
    # Summary

    Fabric update group configuration for Nexus Dashboard.

    Identifier: `update_group_name` (single). Fabric scope is supplied externally by the orchestrator,
    not stored on the model.

    ## Raises

    None
    """

    identifiers: ClassVar[list[str] | None] = ["update_group_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    # --- Gathered Filtering Configuration ---
    supports_gathered_filtering: ClassVar[bool] = True
    gathered_filter_properties: ClassVar[tuple[str, ...]] = (
        "update_group_name",
        "execution",
        "contingency",
        "analysis",
        "is_maintenance",
        "is_disruptive_update",
    )
    # TODO(4.2.1) ND silently drops `installationOrderDevices` on the updateGroups create/update endpoints.
    # The POST/PUT accept the field without error, but GET (single and list) never echoes it back. We still
    # send it (ND may consume it during the actual upgrade run), but it must be excluded from the idempotency
    # diff - otherwise a re-applied, unchanged config is perpetually reported as `changed` because the wire
    # state never carries the field. Observed on ND 4.2.1, fabric SITE1.
    #
    # `force_created` is an attachGroup-only operational flag (whether ND forces past pre-flight switch
    # warnings), not a field of the `updateGroup` resource. It is excluded from the diff so it never
    # produces a false `changed`, and from the payload so it never leaks into the settings PUT body.
    exclude_from_diff: ClassVar[set] = {"installation_order_devices", "force_created"}
    payload_exclude_fields: ClassVar[set] = {"force_created"}

    # --- Fields ---

    update_group_name: str = Field(alias="updateGroupName")
    execution: ExecutionLiteral | None = Field(default=None, alias="execution")
    contingency: ContingencyLiteral | None = Field(default=None, alias="contingency")
    analysis: AnalysisLiteral | None = Field(default=None, alias="analysis")
    is_maintenance: bool | None = Field(default=None, alias="isMaintenance")
    is_disruptive_update: bool | None = Field(default=None, alias="isDisruptiveUpdate")
    update_group_switches: list[str] | None = Field(default=None, alias="updateGroupSwitches")
    force_created: bool = Field(default=False)
    install_image_data: InstallImageDataModel | None = Field(default=None, alias="installImageData")
    installation_order_devices: list[str] | None = Field(default=None, alias="installationOrderDevices")
    recommended_version: str | None = Field(default=None, alias="recommendedVersion")
    latest_recommended_version: str | None = Field(default=None, alias="latestRecommendedVersion")
    report_selection: ReportSelectionLiteral | None = Field(default=None, alias="reportSelection")
    reports: ReportsLiteral | None = Field(default=None, alias="reports")
    update_report_checks: list[UpdateReportCheckModel] | None = Field(default=None, alias="updateReportChecks")

    # --- Validators (Deserialization) ---

    @model_validator(mode="before")
    @classmethod
    def _drop_unwanted_top_level_keys(cls, data: Any) -> Any:
        """
        # Summary

        Strip keys that ND may echo back in a GET response but that we do not store on the model.

        ## Raises

        None
        """
        if isinstance(data, dict):
            for key in ("fabricName", "createTime", "modifyTime"):
                data.pop(key, None)
        return data

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                options=dict(
                    update_group_name=dict(type="str", required=False),
                    execution=dict(type="str", choices=["parallel", "serial"]),
                    contingency=dict(type="str", choices=["continue", "pause"]),
                    analysis=dict(
                        type="str",
                        choices=[
                            "snapshot",
                            "noAnalysis",
                            "fullAnalysis",
                            "usePreExistingAnalysis",
                        ],
                    ),
                    is_maintenance=dict(type="bool"),
                    is_disruptive_update=dict(type="bool"),
                    update_group_switches=dict(type="list", elements="str"),
                    force_created=dict(type="bool"),
                    install_image_data=dict(
                        type="dict",
                        options=dict(
                            nos_image_name=dict(type="str"),
                            epld_image_name=dict(type="str"),
                            install_package_names=dict(type="list", elements="str"),
                            uninstall_package=dict(type="bool"),
                        ),
                    ),
                    installation_order_devices=dict(type="list", elements="str"),
                    recommended_version=dict(type="str"),
                    latest_recommended_version=dict(type="str"),
                    report_selection=dict(type="str", choices=["noReport", "basic", "advanced"]),
                    reports=dict(
                        type="str",
                        choices=[
                            "noReport",
                            "usePreExistingReports",
                            "useDefaultPreAndPostReports",
                            "useAdvancePreAndPostReports",
                        ],
                    ),
                    update_report_checks=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            report_check_name=dict(type="str", required=True),
                        ),
                    ),
                ),
            ),
            auto_assign=dict(type="str", choices=["roleBased", "evenOdd"]),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted", "gathered"],
            ),
        )
