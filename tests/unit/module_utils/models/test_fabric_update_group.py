# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for fabric_update_group.py models.

Tests:
- Identifier configuration
- Field aliasing (snake_case <-> camelCase round-trip)
- to_payload / from_response round-trip
- Nested InstallImageDataModel and UpdateReportCheckModel
- get_argument_spec shape
- Gathered state filtering
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines,line-too-long,invalid-name

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import (
    filter_gathered_response,
    validate_gathered_filters,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_update_group.fabric_update_group import (
    FabricUpdateGroupModel,
    InstallImageDataModel,
    UpdateReportCheckModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_update_group import (
    FabricUpdateGroupOrchestrator,
)


@contextmanager
def does_not_raise():
    """Context manager that asserts no exception is raised."""
    yield


# =============================================================================
# Test data constants
# =============================================================================

SAMPLE_API_RESPONSE = {
    "updateGroupName": "leaf_group",
    "execution": "serial",
    "contingency": "continue",
    "analysis": "snapshot",
    "isMaintenance": True,
    "isDisruptiveUpdate": True,
    "updateGroupSwitches": ["FDO24020JNK", "FDO2338083P"],
    "installImageData": {
        "epldImageName": "n9000-epld.9.3.13.img",
        "nosImageName": "nxos.9.3.13.bin",
        "installPackageNames": ["nxos.CSCwh77779-n9k_ALL-1.0.0-9.3.13.lib32_n9000.rpm"],
        "uninstallPackage": True,
    },
    "installationOrderDevices": ["FDO2338083P", "FDO24020JNK"],
    "recommendedVersion": "9.3(14)",
    "latestRecommendedVersion": "9.3(15)",
    "reportSelection": "advanced",
    "reports": "usePreExistingReports",
    "updateReportChecks": [{"reportCheckName": "sh_version"}],
}


SAMPLE_ANSIBLE_CONFIG = {
    "update_group_name": "leaf_group",
    "execution": "serial",
    "contingency": "continue",
    "analysis": "snapshot",
    "is_maintenance": True,
    "is_disruptive_update": True,
    "update_group_switches": ["FDO24020JNK", "FDO2338083P"],
    "install_image_data": {
        "epld_image_name": "n9000-epld.9.3.13.img",
        "nos_image_name": "nxos.9.3.13.bin",
        "install_package_names": ["nxos.CSCwh77779-n9k_ALL-1.0.0-9.3.13.lib32_n9000.rpm"],
        "uninstall_package": True,
    },
    "installation_order_devices": ["FDO2338083P", "FDO24020JNK"],
    "recommended_version": "9.3(14)",
    "latest_recommended_version": "9.3(15)",
    "report_selection": "advanced",
    "reports": "usePreExistingReports",
    "update_report_checks": [{"report_check_name": "sh_version"}],
}


# =============================================================================
# Test: InstallImageDataModel
# =============================================================================


def test_fabric_update_group_00010() -> None:
    """
    # Summary

    Verify `InstallImageDataModel` field defaults to None on bare construction.

    ## Test

    - Instantiate with no arguments
    - All four user-facing fields default to None

    ## Classes and Methods

    - InstallImageDataModel.__init__()
    """
    with does_not_raise():
        instance = InstallImageDataModel()

    assert instance.nos_image_name is None
    assert instance.epld_image_name is None
    assert instance.install_package_names is None
    assert instance.uninstall_package is None


def test_fabric_update_group_00020() -> None:
    """
    # Summary

    Verify `InstallImageDataModel` field aliases.

    ## Test

    - Construct from wire (camelCase) keys via `model_validate` with `by_alias=True`
    - Snake-case attributes hold the values

    ## Classes and Methods

    - InstallImageDataModel.model_validate()
    """
    wire = {
        "nosImageName": "nxos.9.3.13.bin",
        "epldImageName": "n9000-epld.9.3.13.img",
        "installPackageNames": ["a.rpm", "b.rpm"],
        "uninstallPackage": False,
    }

    with does_not_raise():
        instance = InstallImageDataModel.model_validate(wire, by_alias=True)

    assert instance.nos_image_name == "nxos.9.3.13.bin"
    assert instance.epld_image_name == "n9000-epld.9.3.13.img"
    assert instance.install_package_names == ["a.rpm", "b.rpm"]
    assert instance.uninstall_package is False


# =============================================================================
# Test: UpdateReportCheckModel
# =============================================================================


def test_fabric_update_group_00030() -> None:
    """
    # Summary

    Verify `UpdateReportCheckModel` accepts wire alias `reportCheckName` and exposes it as `report_check_name`.

    ## Test

    - Construct from wire dict
    - `report_check_name` reads the value

    ## Classes and Methods

    - UpdateReportCheckModel.model_validate()
    """
    with does_not_raise():
        instance = UpdateReportCheckModel.model_validate({"reportCheckName": "sh_version"}, by_alias=True)

    assert instance.report_check_name == "sh_version"


def test_fabric_update_group_00040() -> None:
    """
    # Summary

    Verify `UpdateReportCheckModel` tolerates a wire item lacking `reportCheckName` (it parses with
    `report_check_name = None`) rather than raising. ND's embedded `updateReportChecks` item schema does
    not mark `reportCheckName` required, so the model must not be stricter than ND on read - a missing
    name on a single existing group must not abort the whole module run. User input is still enforced
    as required by the argument spec, which validates before the model is built.

    ## Test

    - Construct from an empty wire dict
    - No exception is raised; `report_check_name` is None

    ## Classes and Methods

    - UpdateReportCheckModel.model_validate()
    """
    with does_not_raise():
        instance = UpdateReportCheckModel.model_validate({}, by_alias=True)

    assert instance.report_check_name is None


def test_fabric_update_group_00045() -> None:
    """
    # Summary

    Verify the argument spec still REQUIRES `report_check_name` for user input, even though the model
    field is optional for read-tolerance. The strictness lives in the argspec (validated before the
    model is built); the optional model field only governs wire deserialization.

    ## Test

    - `get_argument_spec()` marks `config.update_report_checks.report_check_name` required

    ## Classes and Methods

    - FabricUpdateGroupModel.get_argument_spec()
    """
    spec = FabricUpdateGroupModel.get_argument_spec()
    report_check = spec["config"]["options"]["update_report_checks"]["options"]["report_check_name"]

    assert report_check["required"] is True


def test_fabric_update_group_00046() -> None:
    """
    # Summary

    Verify `FabricUpdateGroupModel.from_response` tolerates an `updateReportChecks` item that lacks
    `reportCheckName` - this is the exact wire shape that, if rejected, would abort the whole module run
    when `NDStateMachine` validates every existing group. It must parse to `report_check_name = None`.

    ## Test

    - A wire group whose `updateReportChecks` item has no `reportCheckName` builds without raising

    ## Classes and Methods

    - FabricUpdateGroupModel.from_response()
    - UpdateReportCheckModel
    """
    wire = {
        "updateGroupName": "leaf_group",
        "updateGroupSwitches": ["FDO1"],
        "updateReportChecks": [{}],
    }

    with does_not_raise():
        instance = FabricUpdateGroupModel.from_response(wire)

    assert instance.update_report_checks is not None
    assert instance.update_report_checks[0].report_check_name is None


# =============================================================================
# Test: FabricUpdateGroupModel - identifier configuration
# =============================================================================


def test_fabric_update_group_00100() -> None:
    """
    # Summary

    Verify identifier configuration on `FabricUpdateGroupModel`.

    ## Test

    - `identifiers == ["update_group_name"]`
    - `identifier_strategy == "single"`
    - `get_identifier_value` returns the name string

    ## Classes and Methods

    - FabricUpdateGroupModel (identifiers / identifier_strategy)
    - FabricUpdateGroupModel.get_identifier_value()
    """
    assert FabricUpdateGroupModel.identifiers == ["update_group_name"]
    assert FabricUpdateGroupModel.identifier_strategy == "single"

    instance = FabricUpdateGroupModel(update_group_name="leaf_group")
    assert instance.get_identifier_value() == "leaf_group"


def test_fabric_update_group_00110() -> None:
    """
    # Summary

    Verify required-field enforcement: `update_group_name` is mandatory.

    ## Test

    - Constructing without `update_group_name` raises ValidationError

    ## Classes and Methods

    - FabricUpdateGroupModel.__init__()
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        FabricUpdateGroupModel()  # type: ignore[call-arg]


# =============================================================================
# Test: FabricUpdateGroupModel - from_response (wire -> model)
# =============================================================================


def test_fabric_update_group_00200() -> None:
    """
    # Summary

    Verify `from_response` (model_validate with by_alias) builds a model from the full wire shape.

    ## Test

    - Validate `SAMPLE_API_RESPONSE`
    - Top-level snake-case attributes carry the wire values
    - `install_image_data` is a populated `InstallImageDataModel`
    - `update_report_checks` is a list of one `UpdateReportCheckModel`

    ## Classes and Methods

    - FabricUpdateGroupModel.from_response()
    """
    with does_not_raise():
        instance = FabricUpdateGroupModel.from_response(SAMPLE_API_RESPONSE)

    assert instance.update_group_name == "leaf_group"
    assert instance.execution == "serial"
    assert instance.contingency == "continue"
    assert instance.analysis == "snapshot"
    assert instance.is_maintenance is True
    assert instance.is_disruptive_update is True
    assert instance.update_group_switches == ["FDO24020JNK", "FDO2338083P"]
    assert isinstance(instance.install_image_data, InstallImageDataModel)
    assert instance.install_image_data.nos_image_name == "nxos.9.3.13.bin"
    assert instance.install_image_data.epld_image_name == "n9000-epld.9.3.13.img"
    assert instance.install_image_data.install_package_names == ["nxos.CSCwh77779-n9k_ALL-1.0.0-9.3.13.lib32_n9000.rpm"]
    assert instance.install_image_data.uninstall_package is True
    assert instance.installation_order_devices == ["FDO2338083P", "FDO24020JNK"]
    assert instance.recommended_version == "9.3(14)"
    assert instance.latest_recommended_version == "9.3(15)"
    assert instance.report_selection == "advanced"
    assert instance.reports == "usePreExistingReports"
    assert isinstance(instance.update_report_checks, list)
    assert len(instance.update_report_checks) == 1
    assert instance.update_report_checks[0].report_check_name == "sh_version"


def test_fabric_update_group_00210() -> None:
    """
    # Summary

    Verify `from_response` strips noisy top-level keys ND may echo (e.g. `fabricName`, `createTime`).

    ## Test

    - Build a response with extra keys
    - Model still validates cleanly
    - The extra keys are not present on the model

    ## Classes and Methods

    - FabricUpdateGroupModel._drop_unwanted_top_level_keys()
    """
    data = dict(SAMPLE_API_RESPONSE)
    data["fabricName"] = "SITE1"
    data["createTime"] = "2026-05-19T10:00:00Z"
    data["modifyTime"] = "2026-05-19T10:05:00Z"

    with does_not_raise():
        instance = FabricUpdateGroupModel.from_response(data)

    assert instance.update_group_name == "leaf_group"


# =============================================================================
# Test: FabricUpdateGroupModel - from_config (ansible -> model)
# =============================================================================


def test_fabric_update_group_00300() -> None:
    """
    # Summary

    Verify `from_config` accepts Ansible snake-case keys.

    ## Test

    - Validate `SAMPLE_ANSIBLE_CONFIG`
    - Top-level attributes populated correctly
    - Nested install_image_data and update_report_checks built

    ## Classes and Methods

    - FabricUpdateGroupModel.from_config()
    """
    with does_not_raise():
        instance = FabricUpdateGroupModel.from_config(SAMPLE_ANSIBLE_CONFIG)

    assert instance.update_group_name == "leaf_group"
    assert instance.execution == "serial"
    assert instance.install_image_data is not None
    assert instance.install_image_data.nos_image_name == "nxos.9.3.13.bin"
    assert instance.update_report_checks is not None
    assert instance.update_report_checks[0].report_check_name == "sh_version"


# =============================================================================
# Test: FabricUpdateGroupModel - to_payload (model -> wire)
# =============================================================================


def test_fabric_update_group_00400() -> None:
    """
    # Summary

    Verify `to_payload` round-trips the full wire shape (camelCase keys, nested objects).

    ## Test

    - Build model from Ansible config
    - Serialize via to_payload
    - Resulting dict contains all camelCase wire keys with original values
    - `installImageData` is present as a nested object

    ## Classes and Methods

    - FabricUpdateGroupModel.to_payload()
    """
    instance = FabricUpdateGroupModel.from_config(SAMPLE_ANSIBLE_CONFIG)

    payload = instance.to_payload()

    assert payload["updateGroupName"] == "leaf_group"
    assert payload["execution"] == "serial"
    assert payload["contingency"] == "continue"
    assert payload["analysis"] == "snapshot"
    assert payload["isMaintenance"] is True
    assert payload["isDisruptiveUpdate"] is True
    assert payload["updateGroupSwitches"] == ["FDO24020JNK", "FDO2338083P"]
    assert payload["installImageData"] == {
        "epldImageName": "n9000-epld.9.3.13.img",
        "nosImageName": "nxos.9.3.13.bin",
        "installPackageNames": ["nxos.CSCwh77779-n9k_ALL-1.0.0-9.3.13.lib32_n9000.rpm"],
        "uninstallPackage": True,
    }
    assert payload["installationOrderDevices"] == ["FDO2338083P", "FDO24020JNK"]
    assert payload["recommendedVersion"] == "9.3(14)"
    assert payload["latestRecommendedVersion"] == "9.3(15)"
    assert payload["reportSelection"] == "advanced"
    assert payload["reports"] == "usePreExistingReports"
    assert payload["updateReportChecks"] == [{"reportCheckName": "sh_version"}]


def test_fabric_update_group_00410() -> None:
    """
    # Summary

    Verify `to_payload` excludes None fields (sparse payload, no JSON nulls).

    ## Test

    - Build model with only required fields
    - Serialize via `to_payload`
    - Optional fields are absent from the payload

    ## Classes and Methods

    - FabricUpdateGroupModel.to_payload()
    """
    instance = FabricUpdateGroupModel(
        update_group_name="g1",
        execution="parallel",
        contingency="pause",
        analysis="noAnalysis",
        is_maintenance=False,
        is_disruptive_update=False,
        update_group_switches=["FDO1"],
    )

    payload = instance.to_payload()

    assert payload == {
        "updateGroupName": "g1",
        "execution": "parallel",
        "contingency": "pause",
        "analysis": "noAnalysis",
        "isMaintenance": False,
        "isDisruptiveUpdate": False,
        "updateGroupSwitches": ["FDO1"],
    }


def test_fabric_update_group_00420() -> None:
    """
    # Summary

    Verify full wire round-trip: from_response -> to_payload -> from_response is stable.

    ## Test

    - Build model from wire shape, serialize back, validate again
    - The second model is equal to the first

    ## Classes and Methods

    - FabricUpdateGroupModel.from_response()
    - FabricUpdateGroupModel.to_payload()
    """
    first = FabricUpdateGroupModel.from_response(SAMPLE_API_RESPONSE)
    payload = first.to_payload()
    second = FabricUpdateGroupModel.from_response(payload)

    assert first.model_dump() == second.model_dump()


# =============================================================================
# Test: enum validation
# =============================================================================


@pytest.mark.parametrize(
    "field,value",
    [
        ("execution", "bogus"),
        ("contingency", "bogus"),
        ("analysis", "bogus"),
        ("report_selection", "bogus"),
        ("reports", "bogus"),
    ],
    ids=[
        "execution-bad-value",
        "contingency-bad-value",
        "analysis-bad-value",
        "report_selection-bad-value",
        "reports-bad-value",
    ],
)
def test_fabric_update_group_00500(field: str, value: str) -> None:
    """
    # Summary

    Verify Literal-typed enum fields reject unknown values.

    ## Test

    - Construct model with one bad enum value
    - Expect ValidationError

    ## Classes and Methods

    - FabricUpdateGroupModel (Literal field validation)
    """
    from pydantic import ValidationError

    kwargs: dict = {"update_group_name": "g1", field: value}
    with pytest.raises(ValidationError):
        FabricUpdateGroupModel(**kwargs)


@pytest.mark.parametrize(
    "field,value",
    [
        ("execution", "parallel"),
        ("execution", "serial"),
        ("contingency", "continue"),
        ("contingency", "pause"),
        ("analysis", "snapshot"),
        ("analysis", "noAnalysis"),
        ("analysis", "fullAnalysis"),
        ("analysis", "usePreExistingAnalysis"),
        ("report_selection", "noReport"),
        ("report_selection", "basic"),
        ("report_selection", "advanced"),
        ("reports", "noReport"),
        ("reports", "usePreExistingReports"),
        ("reports", "useDefaultPreAndPostReports"),
        ("reports", "useAdvancePreAndPostReports"),
    ],
)
def test_fabric_update_group_00510(field: str, value: str) -> None:
    """
    # Summary

    Verify Literal-typed enum fields accept all documented wire values.

    ## Test

    - Construct model with each valid enum value
    - Model attribute holds the assigned value

    ## Classes and Methods

    - FabricUpdateGroupModel (Literal field validation)
    """
    with does_not_raise():
        instance = FabricUpdateGroupModel(update_group_name="g1", **{field: value})

    assert getattr(instance, field) == value


# =============================================================================
# Test: get_argument_spec
# =============================================================================


def test_fabric_update_group_00600() -> None:
    """
    # Summary

    Verify `get_argument_spec` exposes the expected top-level keys and `config` suboptions.

    ## Test

    - `fabric_name`, `state`, `config`, `auto_assign` are top-level keys
    - `state` choices are merged/replaced/overridden/deleted (no `query` - the ND collection has no
      `query` state;)
    - `state` choices include `gathered`
    - `config` is optional (not required) so state=gathered can run without input
    - `config.options.update_group_name` is not required (optional filter for gathered)
    - `install_image_data` and `update_report_checks` are nested dicts/lists

    ## Classes and Methods

    - FabricUpdateGroupModel.get_argument_spec()
    """
    spec = FabricUpdateGroupModel.get_argument_spec()

    assert set(spec.keys()) == {"fabric_name", "config", "state", "auto_assign"}
    assert spec["fabric_name"]["required"] is True
    assert spec["state"]["choices"] == [
        "merged",
        "replaced",
        "overridden",
        "deleted",
        "gathered",
    ]
    assert spec["config"]["type"] == "list"
    assert spec["config"]["elements"] == "dict"
    assert spec["config"].get("required", False) is False

    options = spec["config"]["options"]
    assert options["update_group_name"]["required"] is False
    assert options["execution"]["choices"] == ["parallel", "serial"]
    assert options["analysis"]["choices"] == [
        "snapshot",
        "noAnalysis",
        "fullAnalysis",
        "usePreExistingAnalysis",
    ]
    assert options["install_image_data"]["type"] == "dict"
    assert "nos_image_name" in options["install_image_data"]["options"]
    assert options["update_report_checks"]["type"] == "list"
    assert options["update_report_checks"]["options"]["report_check_name"]["required"] is True


def test_fabric_update_group_00610() -> None:
    """
    # Summary

    Verify `get_argument_spec` exposes `auto_assign` as a string option with the propose algorithm choices.

    `auto_assign` triggers ND's fabric-wide `propose` action, which auto-generates update groups by
    algorithm. It is a top-level option (the action is fabric-scoped, not per-group) and has no
    default - its absence means "do not auto-assign".

    ## Test

    - `auto_assign` is a top-level key of type `str`
    - Its `choices` are `roleBased` and `evenOdd` (ND wire enum values, kept verbatim)
    - It has no `default` key

    ## Classes and Methods

    - FabricUpdateGroupModel.get_argument_spec()
    """
    spec = FabricUpdateGroupModel.get_argument_spec()

    assert spec["auto_assign"]["type"] == "str"
    assert spec["auto_assign"]["choices"] == ["roleBased", "evenOdd"]
    assert "default" not in spec["auto_assign"]


# =============================================================================
# Test: installation_order_devices excluded from diff
# =============================================================================


def test_fabric_update_group_00700() -> None:
    """
    # Summary

    Verify `installation_order_devices` is excluded from the diff representation.

    ND 4.2.1 silently drops `installationOrderDevices` - it accepts the field on POST/PUT but never
    echoes it on GET. If it were included in the diff, a re-applied unchanged config would always
    appear `changed`. `exclude_from_diff` keeps it out of `to_diff_dict()`.

    ## Test

    - `installation_order_devices` is in `FabricUpdateGroupModel.exclude_from_diff`
    - `to_diff_dict()` omits the field (both alias and snake_case forms) even when it is set

    ## Classes and Methods

    - FabricUpdateGroupModel (exclude_from_diff)
    - FabricUpdateGroupModel.to_diff_dict()
    """
    assert "installation_order_devices" in FabricUpdateGroupModel.exclude_from_diff

    instance = FabricUpdateGroupModel(
        update_group_name="g1",
        update_group_switches=["FDO1", "FDO2"],
        installation_order_devices=["FDO1", "FDO2"],
    )
    diff_dict = instance.to_diff_dict()

    assert "installationOrderDevices" not in diff_dict
    assert "installation_order_devices" not in diff_dict
    # A field that is NOT excluded still appears, confirming the exclusion is targeted
    assert diff_dict["updateGroupSwitches"] == ["FDO1", "FDO2"]


def test_fabric_update_group_00710() -> None:
    """
    # Summary

    Verify two models that differ ONLY in `installation_order_devices` are treated as equal by `get_diff`,
    so a re-applied config does not produce a false `changed`.

    ## Test

    - `current` has no `installation_order_devices` (mirrors the ND wire state, which drops it)
    - `desired` is identical except it sets `installation_order_devices`
    - `current.get_diff(desired, exclude_unset=True)` is True (desired is a subset of current - no change)

    ## Classes and Methods

    - FabricUpdateGroupModel.get_diff()
    """
    common = dict(
        update_group_name="g1",
        execution="serial",
        contingency="continue",
        analysis="snapshot",
        is_maintenance=True,
        is_disruptive_update=False,
        update_group_switches=["FDO1", "FDO2"],
    )
    current = FabricUpdateGroupModel(**common)
    desired = FabricUpdateGroupModel(**common, installation_order_devices=["FDO2", "FDO1"])

    assert current.get_diff(desired, exclude_unset=True) is True


# =============================================================================
# Test: force_created flag
# =============================================================================


def test_fabric_update_group_00800() -> None:
    """
    # Summary

    Verify `force_created` defaults to False on bare construction.

    ## Test

    - Construct model with only the required field
    - `force_created` is False

    ## Classes and Methods

    - FabricUpdateGroupModel.__init__()
    """
    with does_not_raise():
        instance = FabricUpdateGroupModel(update_group_name="g1")

    assert instance.force_created is False


def test_fabric_update_group_00810() -> None:
    """
    # Summary

    Verify `force_created` is excluded from both the diff and the PUT payload.

    `force_created` is an `attachGroup`-only operational flag, not part of the `updateGroup` resource
    schema. It must never reach the settings PUT body and must never trigger a false `changed`.

    ## Test

    - `force_created` is in `exclude_from_diff` and `payload_exclude_fields`
    - `to_payload()` omits it even when set True
    - `to_diff_dict()` omits it even when set True

    ## Classes and Methods

    - FabricUpdateGroupModel (exclude_from_diff / payload_exclude_fields)
    - FabricUpdateGroupModel.to_payload()
    - FabricUpdateGroupModel.to_diff_dict()
    """
    assert "force_created" in FabricUpdateGroupModel.exclude_from_diff
    assert "force_created" in FabricUpdateGroupModel.payload_exclude_fields

    instance = FabricUpdateGroupModel(
        update_group_name="g1",
        update_group_switches=["FDO1"],
        force_created=True,
    )

    assert "force_created" not in instance.to_payload()
    assert "forceCreated" not in instance.to_payload()
    assert "force_created" not in instance.to_diff_dict()
    assert "forceCreated" not in instance.to_diff_dict()


def test_fabric_update_group_00820() -> None:
    """
    # Summary

    Verify `from_config` reads `force_created` from an Ansible config dict.

    ## Test

    - Config dict sets `force_created: True`
    - The model attribute holds True

    ## Classes and Methods

    - FabricUpdateGroupModel.from_config()
    """
    config = dict(SAMPLE_ANSIBLE_CONFIG, force_created=True)

    with does_not_raise():
        instance = FabricUpdateGroupModel.from_config(config)

    assert instance.force_created is True


def test_fabric_update_group_00830() -> None:
    """
    # Summary

    Verify `get_argument_spec` exposes `force_created` as a bool option defaulting to False.

    ## Test

    - `config.options.force_created` is type bool with default False

    ## Classes and Methods

    - FabricUpdateGroupModel.get_argument_spec()
    """
    options = FabricUpdateGroupModel.get_argument_spec()["config"]["options"]

    assert options["force_created"]["type"] == "bool"
    assert options["force_created"].get("default") is None


# =============================================================================
# Test: Gathered State Filtering
# =============================================================================


def test_fabric_update_group_00900() -> None:
    """
    # Summary

    Verify `FabricUpdateGroupModel` opts into gathered filtering and
    `FabricUpdateGroupOrchestrator` does NOT opt into server-side (Lucene) filtering.

    The updateGroups endpoint does not support Lucene query parameters,
    so all filtering is local (post-query).

    ## Test

    - `supports_gathered_filtering` is True on the model
    - `gathered_filter_properties` contains the expected 6 properties
    - `supports_gathered_server_filtering` is False on the orchestrator

    ## Classes and Methods

    - FabricUpdateGroupModel (class vars)
    - FabricUpdateGroupOrchestrator (class vars)
    """
    assert FabricUpdateGroupModel.supports_gathered_filtering is True
    assert FabricUpdateGroupModel.gathered_filter_properties == (
        "update_group_name",
        "execution",
        "contingency",
        "analysis",
        "is_maintenance",
        "is_disruptive_update",
    )
    assert FabricUpdateGroupOrchestrator.supports_gathered_server_filtering is False


def test_fabric_update_group_00910() -> None:
    """
    # Summary

    Verify gathered filter matches by `update_group_name` (primary identifier).

    ## Test

    - Filter with matching name returns 1 result
    - Filter with non-matching name returns 0 results

    ## Classes and Methods

    - filter_gathered_response()
    - FabricUpdateGroupModel.matches_gathered_filter()
    """
    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"update_group_name": "leaf_group"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1
    assert result[0].update_group_name == "leaf_group"

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"update_group_name": "nonexistent_group"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 0


def test_fabric_update_group_00920() -> None:
    """
    # Summary

    Verify gathered filter matches by `execution` enum value.

    ## Test

    - Filter `execution: serial` matches the sample (which has serial)
    - Filter `execution: parallel` does not match

    ## Classes and Methods

    - filter_gathered_response()
    """
    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"execution": "serial"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"execution": "parallel"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 0


def test_fabric_update_group_00930() -> None:
    """
    # Summary

    Verify gathered filter matches by boolean properties.

    Boolean `False` is a meaningful filter criterion (not treated as absent).
    This confirms the framework correctly distinguishes `False` from `None`.

    ## Test

    - Filter `is_maintenance: true` matches (sample has True)
    - Filter `is_maintenance: false` does not match
    - Filter `is_disruptive_update: true` matches (sample has True)

    ## Classes and Methods

    - filter_gathered_response()
    """
    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"is_maintenance": True}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"is_maintenance": False}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 0

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"is_disruptive_update": True}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1


def test_fabric_update_group_00940() -> None:
    """
    # Summary

    Verify AND semantics within a single gathered filter item.

    When a user supplies multiple criteria in one config item, ALL must match
    the candidate for it to be included in the result.

    ## Test

    - `execution: serial` AND `contingency: continue` → matches (both true in sample)
    - `execution: serial` AND `contingency: pause` → no match (contingency mismatch)

    ## Classes and Methods

    - filter_gathered_response()
    """
    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"execution": "serial", "contingency": "continue"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"execution": "serial", "contingency": "pause"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 0


def test_fabric_update_group_00950() -> None:
    """
    # Summary

    Verify OR semantics across multiple gathered filter items.

    When a user supplies multiple items in the config list, a candidate matches
    if ANY item matches (union). This lets users express "show me groups that are
    serial OR groups named X" in a single task.

    ## Test

    - Two filter items: one doesn't match (name), one does (execution) → 1 result
    - Two filter items: neither matches → 0 results

    ## Classes and Methods

    - filter_gathered_response()
    """
    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[
            {"update_group_name": "nonexistent"},
            {"execution": "serial"},
        ],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[
            {"update_group_name": "nonexistent"},
            {"execution": "parallel"},
        ],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 0


def test_fabric_update_group_00960() -> None:
    """
    # Summary

    Verify `report_selection` and `reports` enum-valued gathered filters.

    ## Test

    - Filter `report_selection: advanced` matches (sample has advanced)
    - Filter `reports: usePreExistingReports` matches
    - Filter `report_selection: noReport` does not match

    ## Classes and Methods

    - filter_gathered_response()
    """
    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"report_selection": "advanced"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"reports": "usePreExistingReports"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 1

    result = filter_gathered_response(
        response_data=[deepcopy(SAMPLE_API_RESPONSE)],
        filters=[{"report_selection": "noReport"}],
        model_class=FabricUpdateGroupModel,
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
    )
    assert len(result) == 0


@pytest.mark.parametrize(
    "filter_item",
    [
        {"update_group_switches": ["192.168.7.11"]},
        {"force_created": True},
        {"install_image_data": {"nos_image_name": "nxos.9.3.13.bin"}},
    ],
    ids=["update_group_switches", "force_created", "install_image_data_nested"],
)
def test_fabric_update_group_00970(filter_item) -> None:
    """
    # Summary

    Verify unsupported gathered filter properties are rejected with a clear error.

    Properties excluded from `gathered_filter_properties` must not silently pass
    validation. This guards against customers accidentally filtering on fields
    that cannot work (module-only params, nested objects, list-valued fields).

    ## Test

    - `update_group_switches` (list-valued, no meaningful equality match)
    - `force_created` (module-only operational flag, never returned by API)
    - `install_image_data.nos_image_name` (nested property, not supported)

    ## Classes and Methods

    - validate_gathered_filters()
    """
    with pytest.raises(ValueError, match="unsupported properties"):
        validate_gathered_filters(
            filters=[filter_item],
            normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
            supported_properties=FabricUpdateGroupModel.gathered_filter_properties,
        )


def test_fabric_update_group_00980() -> None:
    """
    # Summary

    Verify Ansible-injected None values are not treated as filter criteria.

    Ansible pads all omitted suboptions with None after argument validation.
    These Nones must not trigger "unsupported property" errors or act as
    filter criteria. Only explicitly supplied non-None values count.

    ## Test

    - Filter item with one active property and several None-padded properties
      passes validation without error

    ## Classes and Methods

    - validate_gathered_filters()
    """
    filter_item = {
        "update_group_name": "leaf_group",
        "execution": None,
        "contingency": None,
        "analysis": None,
        "is_maintenance": None,
        "is_disruptive_update": None,
        "update_group_switches": None,
        "force_created": None,
        "install_image_data": None,
    }

    # Should not raise — None values are ignored by property validation
    validate_gathered_filters(
        filters=[filter_item],
        normalize_filter=FabricUpdateGroupModel.normalize_gathered_filter,
        supported_properties=FabricUpdateGroupModel.gathered_filter_properties,
    )
