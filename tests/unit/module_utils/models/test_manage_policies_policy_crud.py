# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``models/manage_policies/policy_crud.py``.

Tests the policy CRUD request body models:

- ``PolicyCreateBulk``  - wraps ``list[PolicyCreate]`` for the bulk-create POST
  endpoint. ``min_length=1`` is enforced; ``to_request_dict()`` produces
  ``{"policies": [...]}`` with each item serialised through
  ``PolicyCreate.to_request_dict()``.
- ``PolicyUpdate``      - inherits all fields/validators from ``PolicyCreate``;
  the ``policyId`` lives in the URL path, not the body.
"""

# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import (
    PolicyEntityType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_base import (
    PolicyCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_crud import (
    PolicyCreateBulk,
    PolicyUpdate,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def _policy_kwargs(**overrides) -> dict:
    """Return the minimum required field set for constructing ``PolicyCreate``/
    ``PolicyUpdate``."""
    data = {
        "switch_id": "FDO25031SY4",
        "template_name": "feature_enable",
        "entity_type": PolicyEntityType.SWITCH,
        "entity_name": "SWITCH",
    }
    data.update(overrides)
    return data


def _policy(**overrides) -> PolicyCreate:
    """Return a fully constructed ``PolicyCreate`` instance."""
    return PolicyCreate(**_policy_kwargs(**overrides))


# =============================================================================
# Test: PolicyCreateBulk basic construction
# =============================================================================


def test_manage_policies_policy_crud_00010() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk`` constructs from a single ``PolicyCreate``
    instance and exposes it in the ``policies`` list.

    ## Test

    - ``policies`` is a list with the single supplied entry.
    - Each entry is still a ``PolicyCreate`` instance.

    ## Classes and Methods

    - ``PolicyCreateBulk.__init__``
    """
    with does_not_raise():
        bulk = PolicyCreateBulk(policies=[_policy()])

    assert len(bulk.policies) == 1
    assert isinstance(bulk.policies[0], PolicyCreate)
    assert bulk.policies[0].switch_id == "FDO25031SY4"


def test_manage_policies_policy_crud_00020() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk`` constructs from multiple ``PolicyCreate``
    instances and preserves their order.

    ## Test

    - All entries are kept in the supplied order.

    ## Classes and Methods

    - ``PolicyCreateBulk.__init__``
    """
    with does_not_raise():
        bulk = PolicyCreateBulk(
            policies=[
                _policy(switch_id="FDO111"),
                _policy(switch_id="FDO222"),
                _policy(switch_id="FDO333"),
            ]
        )

    assert [p.switch_id for p in bulk.policies] == ["FDO111", "FDO222", "FDO333"]


def test_manage_policies_policy_crud_00030() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk`` rejects an empty ``policies`` list
    (``min_length=1`` is enforced by Pydantic).

    ## Test

    - Empty list raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreateBulk.__init__``
    """
    with pytest.raises(ValidationError):
        PolicyCreateBulk(policies=[])


# =============================================================================
# Test: PolicyCreateBulk dict-based input is parsed via PolicyCreate
# =============================================================================


def test_manage_policies_policy_crud_00040() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk`` parses dict-shaped entries into
    ``PolicyCreate`` instances (so callers can build the bulk request from a
    JSON-like list).

    ## Test

    - Dict entries with snake_case keys are converted into ``PolicyCreate``
      instances with the documented defaults.

    ## Classes and Methods

    - ``PolicyCreateBulk.__init__``
    """
    with does_not_raise():
        bulk = PolicyCreateBulk(policies=[_policy_kwargs()])

    assert isinstance(bulk.policies[0], PolicyCreate)
    assert bulk.policies[0].priority == 500


def test_manage_policies_policy_crud_00050() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk`` propagates per-entry validation failures
    (e.g. missing required field on a nested entry).

    ## Test

    - Missing ``entity_name`` on one of the policies raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyCreateBulk.__init__``
    """
    bad = _policy_kwargs()
    bad.pop("entity_name")

    with pytest.raises(ValidationError):
        PolicyCreateBulk(policies=[_policy_kwargs(), bad])


# =============================================================================
# Test: PolicyCreateBulk.to_request_dict() payload shape
# =============================================================================


def test_manage_policies_policy_crud_00100() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk.to_request_dict()`` wraps the per-entry
    ``to_request_dict()`` output in a top-level ``"policies"`` key.

    ## Test

    - Output dict has exactly one top-level key, ``"policies"``.
    - ``policies`` is a list of dicts (not model instances).
    - Each nested dict matches the corresponding ``PolicyCreate.to_request_dict()``
      output (camelCase keys, ``exclude_none=True``).

    ## Classes and Methods

    - ``PolicyCreateBulk.to_request_dict``
    """
    bulk = PolicyCreateBulk(
        policies=[
            _policy(switch_id="FDO111", description="motd 1"),
            _policy(switch_id="FDO222", description="motd 2"),
        ]
    )

    payload = bulk.to_request_dict()

    assert list(payload.keys()) == ["policies"]
    assert isinstance(payload["policies"], list)
    assert len(payload["policies"]) == 2

    # Per-entry shape: camelCase keys, source="" emitted, description populated.
    first = payload["policies"][0]
    assert first["switchId"] == "FDO111"
    assert first["templateName"] == "feature_enable"
    assert first["entityType"] == "switch"
    assert first["entityName"] == "SWITCH"
    assert first["description"] == "motd 1"
    assert first["priority"] == 500
    assert first["source"] == ""
    # None-only optional fields are excluded.
    assert "templateInputs" not in first
    assert "secondaryEntityName" not in first


def test_manage_policies_policy_crud_00110() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk.to_request_dict()`` round-trips ``template_inputs``
    verbatim (the dict is preserved as JSON-ready data, not flattened).

    ## Test

    - ``templateInputs`` in the emitted payload equals the input dict.

    ## Classes and Methods

    - ``PolicyCreateBulk.to_request_dict``
    """
    bulk = PolicyCreateBulk(
        policies=[
            _policy(template_inputs={"featureName": "lacp"}),
        ]
    )

    payload = bulk.to_request_dict()

    assert payload["policies"][0]["templateInputs"] == {"featureName": "lacp"}


def test_manage_policies_policy_crud_00120() -> None:
    """
    # Summary

    Verify ``PolicyCreateBulk.to_request_dict()`` emits each nested entry
    identically to ``PolicyCreate.to_request_dict()`` so the bulk wrapper has
    no payload-shape drift relative to the single-entry path.

    ## Test

    - Bulk-emitted entry equals the corresponding ``PolicyCreate.to_request_dict()``
      output dict.

    ## Classes and Methods

    - ``PolicyCreateBulk.to_request_dict``
    - ``PolicyCreate.to_request_dict``
    """
    single = _policy(description="motd 1", template_inputs={"featureName": "lacp"})
    bulk = PolicyCreateBulk(policies=[single])

    bulk_entry = bulk.to_request_dict()["policies"][0]
    single_payload = single.to_request_dict()

    assert bulk_entry == single_payload


# =============================================================================
# Test: PolicyUpdate inherits PolicyCreate behavior
# =============================================================================


def test_manage_policies_policy_crud_00200() -> None:
    """
    # Summary

    Verify ``PolicyUpdate`` is a subclass of ``PolicyCreate`` (i.e. the
    ``policyPut`` schema is identical to ``createPolicy``).

    ## Test

    - ``issubclass(PolicyUpdate, PolicyCreate)`` is True.
    - ``PolicyUpdate`` carries the same identifier strategy and identifier list
      inherited from ``PolicyCreate``.

    ## Classes and Methods

    - ``PolicyUpdate``
    """
    assert issubclass(PolicyUpdate, PolicyCreate)
    assert PolicyUpdate.identifiers == PolicyCreate.identifiers
    assert PolicyUpdate.identifier_strategy == PolicyCreate.identifier_strategy
    assert PolicyUpdate.exclude_from_diff == PolicyCreate.exclude_from_diff


def test_manage_policies_policy_crud_00210() -> None:
    """
    # Summary

    Verify ``PolicyUpdate`` enforces the same required-field set as
    ``PolicyCreate``.

    ## Test

    - Omitting ``switch_id`` raises ``ValidationError``.

    ## Classes and Methods

    - ``PolicyUpdate.__init__``
    """
    data = _policy_kwargs()
    data.pop("switch_id")

    with pytest.raises(ValidationError):
        PolicyUpdate(**data)


@pytest.mark.parametrize("priority", [0, -1, 2001])
def test_manage_policies_policy_crud_00220(priority) -> None:
    """
    # Summary

    Verify ``PolicyUpdate`` enforces the same priority bounds as
    ``PolicyCreate`` (inherited validator).

    ## Test

    - Out-of-range priorities raise ``ValidationError``.

    ## Classes and Methods

    - ``PolicyUpdate.__init__``
    """
    with pytest.raises(ValidationError):
        PolicyUpdate(**_policy_kwargs(priority=priority))


def test_manage_policies_policy_crud_00230() -> None:
    """
    # Summary

    Verify ``PolicyUpdate.to_request_dict()`` produces the same payload shape
    as ``PolicyCreate.to_request_dict()`` for the same field values.

    ## Test

    - Both payloads are dict-equal.
    - The ``policyId`` is NOT part of the body (the field does not exist on
      ``PolicyUpdate``).

    ## Classes and Methods

    - ``PolicyUpdate.to_request_dict``
    """
    update = PolicyUpdate(
        **_policy_kwargs(
            description="Updated policy description",
            priority=100,
            template_inputs={"featureName": "lacp"},
        )
    )
    create = PolicyCreate(
        **_policy_kwargs(
            description="Updated policy description",
            priority=100,
            template_inputs={"featureName": "lacp"},
        )
    )

    update_payload = update.to_request_dict()

    assert update_payload == create.to_request_dict()
    assert "policyId" not in update_payload
    assert "policy_id" not in update_payload
    assert update_payload["templateName"] == "feature_enable"
    assert update_payload["priority"] == 100
    assert update_payload["description"] == "Updated policy description"


def test_manage_policies_policy_crud_00240() -> None:
    """
    # Summary

    Verify ``PolicyUpdate`` instances are accepted by ``PolicyCreateBulk``
    (since ``PolicyUpdate`` is a ``PolicyCreate`` subclass).

    ## Test

    - A ``PolicyCreateBulk`` constructed from ``PolicyUpdate`` instances
      validates successfully and emits the documented payload shape.

    ## Classes and Methods

    - ``PolicyCreateBulk.__init__``
    - ``PolicyCreateBulk.to_request_dict``
    """
    update = PolicyUpdate(**_policy_kwargs(description="upd-1"))

    with does_not_raise():
        bulk = PolicyCreateBulk(policies=[update])

    assert isinstance(bulk.policies[0], PolicyCreate)
    payload = bulk.to_request_dict()
    assert payload["policies"][0]["description"] == "upd-1"
