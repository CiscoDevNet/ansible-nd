# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NTP key parsing and secret handling for ordinary and AI eBGP fabrics."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)

MASK = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
FAMILIES = (
    pytest.param(FabricEbgpModel, "vxlanEbgp", id="ebgp"),
    pytest.param(FabricAiEbgpVxlanModel, "aimlVxlanEbgp", id="ai-ebgp"),
)


def _construct(model_class, fabric_type, construction, key, key_type=None):
    if construction == "from_response":
        return model_class.from_response(
            {
                "name": "fabric1",
                "category": "fabric",
                "management": {
                    "type": fabric_type,
                    "bgpAsn": "65001",
                    "ntpAuthKey": key,
                    **({"ntpAuthKeyType": key_type} if key_type is not None else {}),
                },
            }
        )
    config = {
        "fabric_name": "fabric1",
        "management": {
            "bgp_asn": "65001",
            "ntp_auth_key": key,
            **({"ntp_auth_key_type": key_type} if key_type is not None else {}),
        },
    }
    return getattr(model_class, construction)(config)


@pytest.mark.parametrize(("model_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("construction", ("from_config", "model_validate", "from_response"))
@pytest.mark.parametrize("length", (1, 128), ids=("minimum", "maximum"))
def test_ebgp_ntp_key_bounds_parse_and_preserve_secret_surfaces(model_class, fabric_type, construction, length):
    """Valid boundary keys survive input and response parsing while public output stays masked."""
    key = "K" * length
    model = _construct(model_class, fabric_type, construction, key, key_type="6" if length > 32 else None)

    assert model.management.ntp_auth_key.get_secret_value() == key
    assert model.to_payload()["management"]["ntpAuthKey"] == key
    assert model.to_config()["management"]["ntp_auth_key"] == MASK
    assert model.to_diff_dict()["management"]["ntpAuthKey"] == MASK
    assert model.to_gathered_config()["management"]["ntp_auth_key"] == MASK
    argspec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]["ntp_auth_key"]
    assert argspec["type"] == "str"
    assert argspec["no_log"] is True


@pytest.mark.parametrize(("model_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("construction", ("from_config", "from_response"))
@pytest.mark.parametrize("key", ("K" * 129, "key with spaces", "key\n"), ids=("too-long", "space", "newline"))
def test_ebgp_invalid_ntp_key_constraints_are_still_enforced(model_class, fabric_type, construction, key):
    """Removing Pydantic's incompatible SecretStr constraints retains the declared input bounds."""
    with pytest.raises(ValueError, match="ntp_auth_key"):
        _construct(model_class, fabric_type, construction, key)


@pytest.mark.parametrize(("model_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("construction", ("from_config", "model_validate", "from_response"))
def test_ebgp_empty_ntp_key_keeps_existing_input_normalization(model_class, fabric_type, construction):
    """Ansible input normalizes an empty secret to None; direct/response empty strings fail the minimum."""
    if construction == "from_config":
        model = _construct(model_class, fabric_type, construction, "")
        assert model.management.ntp_auth_key is None
        assert "ntpAuthKey" not in model.to_payload()["management"]
    else:
        with pytest.raises(ValueError, match="ntp_auth_key"):
            _construct(model_class, fabric_type, construction, "")


@pytest.mark.parametrize(("model_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("construction", ("from_config", "from_response"))
def test_ebgp_null_ntp_key_remains_optional_and_absent_from_payload(model_class, fabric_type, construction):
    """The constraint correction does not introduce a secret or a new concrete default."""
    model = _construct(model_class, fabric_type, construction, None)
    assert model.management.ntp_auth_key is None
    assert "ntpAuthKey" not in model.to_payload()["management"]


@pytest.mark.parametrize(("model_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("construction", ("from_config", "model_validate"))
@pytest.mark.parametrize(
    ("key_type", "length", "accepted"), ((None, 32, True), (None, 33, False), ("7", 32, True), ("7", 33, False), ("6", 128, True), ("6", 129, False))
)
def test_ebgp_ntp_plaintext_length_depends_on_the_selected_key_type(model_class, fabric_type, construction, key_type, length, accepted):
    """API input limits distinguish type-7/default plaintext from type-6 encrypted text."""
    if accepted:
        model = _construct(model_class, fabric_type, construction, "K" * length, key_type=key_type)
        assert len(model.to_payload()["management"]["ntpAuthKey"]) == length
    else:
        with pytest.raises(ValueError, match="ntp_auth_key"):
            _construct(model_class, fabric_type, construction, "K" * length, key_type=key_type)


@pytest.mark.parametrize(("model_class", "fabric_type"), FAMILIES)
def test_ebgp_ntp_response_ciphertext_is_not_mistaken_for_type7_input(model_class, fabric_type):
    """A valid returned representation longer than type-7 input remains readable and maskable."""
    key = "C" * 64
    model = _construct(model_class, fabric_type, "from_response", key, key_type="7")
    assert model.to_payload()["management"]["ntpAuthKey"] == key
    assert model.to_gathered_config()["management"]["ntp_auth_key"] == MASK
