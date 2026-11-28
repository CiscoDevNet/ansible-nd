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


class _NestedSecret(NDBaseModel):
    identifiers: ClassVar[list[str] | None] = []
    token: str | None = Field(default=None, json_schema_extra={"secret": True}, alias="tok")


class _ParentSecretModel(NDBaseModel):
    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[str] = "single"
    name: str | None = None
    child: _NestedSecret | None = None
    items: list[_NestedSecret] | None = None


class _ContainerModel(NDBaseModel):
    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[str] = "single"
    name: str | None = None
    cli: str | None = Field(default=None, json_schema_extra={"sensitive_container": True}, alias="extraConfig")
    template: dict[str, str] | None = Field(default=None, json_schema_extra={"sensitive_container": True}, alias="templateConfig")


class _DemoChildModel(_DemoModel):
    token: str | None = Field(default=None, json_schema_extra={"secret": True}, alias="tok")


class _PlainChild(NDBaseModel):
    identifiers: ClassVar[list[str] | None] = []
    note: str | None = None


class _PlainParent(NDBaseModel):
    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[str] = "single"
    name: str | None = None
    child: _PlainChild | None = None


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

    def test_internal_config_keeps_secret_for_request_builders(self):
        model = _DemoModel(name="u1", pwd="p@ss")
        internal = model.to_internal_config()
        display = model.to_config()
        assert internal["password"] == "p@ss"
        assert display["password"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        assert internal["name"] == display["name"] == "u1"

    def test_collect_secret_values_from_raw_config(self):
        assert _DemoModel.collect_secret_values({"name": "u1", "password": "p@ss"}) == {"p@ss"}
        assert _DemoModel.collect_secret_values({"name": "u1"}) == set()

    def test_nested_secret_collection_and_masking(self):
        raw = {"name": "p1", "child": {"token": "nested-canary"}, "items": [{"tok": "list-canary"}]}
        assert _ParentSecretModel.secret_field_keys(by_alias=False) == {"token"}
        assert _ParentSecretModel.secret_field_keys(by_alias=True) == {"tok"}
        assert _ParentSecretModel.collect_secret_values(raw) == {"nested-canary", "list-canary"}
        model = _ParentSecretModel.from_config(raw)
        display = model.to_config()
        assert display["child"]["token"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        assert display["items"][0]["token"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        internal = model.to_internal_config()
        assert internal["child"]["token"] == "nested-canary"
        assert internal["items"][0]["token"] == "list-canary"
        assert model.collect_model_secret_values() == {"nested-canary", "list-canary"}

    def test_sensitive_container_is_masked_but_kept_for_diff_and_payload(self):
        cli = "interface loopback10\n description POC-CLI-CANARY-359"
        raw = {"name": "c1", "cli": cli, "template": {"param": "POC-TMPL-CANARY-359"}}
        assert _ContainerModel.sensitive_container_keys(by_alias=False) == {"cli", "template"}
        assert "cli" not in _ContainerModel.secret_field_keys(by_alias=False)
        assert _ContainerModel.collect_secret_values(raw) == {cli, "POC-TMPL-CANARY-359"}
        model = _ContainerModel.from_config(raw)
        display = model.to_config()
        assert display["cli"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        assert display["template"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        internal = model.to_internal_config()
        assert internal["cli"] == cli
        assert internal["template"] == {"param": "POC-TMPL-CANARY-359"}
        payload = model.to_payload()
        assert payload["extraConfig"] == cli
        assert payload["templateConfig"] == {"param": "POC-TMPL-CANARY-359"}
        diff = model.to_diff_dict()
        assert diff["extraConfig"] == cli
        assert diff["templateConfig"] == {"param": "POC-TMPL-CANARY-359"}
        gathered = model.to_gathered_config()
        assert "cli" not in gathered
        assert "template" not in gathered
        other = _ContainerModel.from_config({"name": "c1", "cli": "hostname changed"})
        assert not model.get_diff(other, exclude_unset=True)
        assert model.collect_model_secret_values() == {cli, "POC-TMPL-CANARY-359"}

    def test_sensitive_schema_is_cached_per_class(self):
        first = _DemoModel._sensitive_schema()
        second = _DemoModel._sensitive_schema()
        assert first is second
        assert _DemoModel._has_sensitive_fields() is True
        assert _ParentSecretModel._has_sensitive_fields() is True

    def test_subclass_schema_is_not_the_parent_cache(self):
        parent = _DemoModel._sensitive_schema()
        child = _DemoChildModel._sensitive_schema()
        assert parent is not child
        assert _DemoModel.secret_field_keys(by_alias=False) == {"password"}
        assert _DemoChildModel.secret_field_keys(by_alias=False) == {"password", "token"}
        assert _DemoChildModel.collect_secret_values({"name": "u1", "password": "p@ss", "token": "nested"}) == {"p@ss", "nested"}

    def test_models_without_sensitive_fields_skip_nested_walks(self, monkeypatch):
        assert _PlainParent._has_sensitive_fields() is False
        assert _PlainParent.collect_secret_values({"name": "x", "child": {"note": "n"}}) == set()

        def fail_walk(cls):
            raise AssertionError(f"nested walk for {cls.__name__}")

        monkeypatch.setattr(_PlainParent, "_nested_model_fields", classmethod(fail_walk))
        monkeypatch.setattr(_PlainChild, "_nested_model_fields", classmethod(fail_walk))
        model = _PlainParent.from_config({"name": "x", "child": {"note": "n"}})
        assert model.collect_model_secret_values() == set()
        assert model.to_config() == model.to_internal_config()
        assert model.to_config()["child"]["note"] == "n"
        assert _PlainParent.collect_secret_values({"name": "x", "child": {"note": "n"}}) == set()

    def test_freeform_override_still_collects_when_class_has_no_tags(self):
        class _FreeFormSecret(NDBaseModel):
            identifiers: ClassVar[list[str] | None] = ["name"]
            identifier_strategy: ClassVar[str] = "single"
            name: str | None = None
            blob: dict | None = None

            @classmethod
            def collect_secret_values(cls, config_item):
                values = super().collect_secret_values(config_item)
                extra = (config_item or {}).get("blob") or {}
                if isinstance(extra, dict) and extra.get("password"):
                    values.add(extra["password"])
                return values

        assert _FreeFormSecret._has_sensitive_fields() is False
        assert _FreeFormSecret.collect_secret_values({"name": "x", "blob": {"password": "hidden"}}) == {"hidden"}
