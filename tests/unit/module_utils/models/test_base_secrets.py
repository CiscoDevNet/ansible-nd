# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the generic (base-model) secret handling: a single
``json_schema_extra={"secret": True}`` tag drives both no_log value collection
and output/diff stripping, while the value is kept in the controller payload.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class _DemoModel(NDBaseModel):
    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[str] = "single"
    name: str | None = None
    password: str | None = Field(default=None, json_schema_extra={"secret": True}, alias="pwd")


class TestBaseSecretHandling:
    def test_secret_field_keys(self):
        assert _DemoModel.secret_field_keys(by_alias=False) == {"password"}
        assert _DemoModel.secret_field_keys(by_alias=True) == {"pwd"}

    def test_masked_in_config_absent_from_diff(self):
        model = _DemoModel(name="u1", pwd="p@ss")
        # Config keeps the key but masks the value (never the real secret).
        assert model.to_config()["password"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        # Diff still excludes the secret entirely, so a secret-only change is not detected.
        assert "pwd" not in model.to_diff_dict()

    def test_kept_in_payload(self):
        model = _DemoModel(name="u1", pwd="p@ss")
        assert model.to_payload().get("pwd") == "p@ss"

    def test_collect_secret_values_from_raw_config(self):
        assert _DemoModel.collect_secret_values({"name": "u1", "password": "p@ss"}) == {"p@ss"}
        assert _DemoModel.collect_secret_values({"name": "u1"}) == set()
