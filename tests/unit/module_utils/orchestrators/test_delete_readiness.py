# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for delete-readiness timing helpers."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.delete_readiness import (
    DeleteReadinessPolicy,
)


def test_delete_readiness_policy_scales_by_chunk_and_caps_timeout():
    policy = DeleteReadinessPolicy(
        poll_interval=5,
        chunk_size=30,
        base_timeout=120,
        extra_chunk_timeout=30,
        max_timeout=900,
    )

    assert policy.timeout_for(0) == 120
    assert policy.timeout_for(1) == 120
    assert policy.timeout_for(30) == 120
    assert policy.timeout_for(31) == 150
    assert policy.timeout_for(6000) == 900


def test_delete_readiness_policy_rejects_invalid_settings():
    with pytest.raises(ValueError, match="chunk_size"):
        DeleteReadinessPolicy(
            poll_interval=5,
            chunk_size=0,
            base_timeout=120,
            extra_chunk_timeout=30,
            max_timeout=900,
        )
