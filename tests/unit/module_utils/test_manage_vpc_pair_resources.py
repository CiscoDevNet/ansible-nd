# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import resources
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import VpcPairResourceError


def _make_nrm(logs):
    """Build a duck-typed stand-in for VpcPairStateMachine, sufficient for _refresh_after_state."""
    module = MagicMock()
    module.params = {"state": "deleted", "verify": {"enabled": True, "retries": 1, "timeout": 30}}
    module.check_mode = False
    model_orchestrator = MagicMock()
    model_orchestrator.query_all.side_effect = RuntimeError("list query failed")
    return SimpleNamespace(
        module=module,
        logs=logs,
        model_orchestrator=model_orchestrator,
        model_class=MagicMock(),
        existing=None,
    )


def test_manage_vpc_pair_resources_00010_refresh_failure_after_real_change_reports_changed_true():
    """A post-apply refresh failure after a write already succeeded must carry changed=True, not default False."""
    nrm = _make_nrm(logs=[{"identifier": ("SW-A", "SW-B"), "status": "deleted"}])

    with pytest.raises(VpcPairResourceError) as exc:
        resources.VpcPairStateMachine._refresh_after_state(nrm)

    assert exc.value.details["changed"] is True


def test_manage_vpc_pair_resources_00020_refresh_failure_with_no_logged_change_reports_changed_false():
    """A refresh failure with nothing logged as created/updated/deleted reports changed=False."""
    nrm = _make_nrm(logs=[])

    with pytest.raises(VpcPairResourceError) as exc:
        resources.VpcPairStateMachine._refresh_after_state(nrm)

    assert exc.value.details["changed"] is False
