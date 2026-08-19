# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Contract tests for scoped REST retry policy."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.rest.retry_policy import RestRetryPolicy


def test_rest_retry_policy_accepts_explicit_contract() -> None:
    policy = RestRetryPolicy(attempts=3, interval=0, retry_transport_errors=True)

    assert policy.attempts == 3
    assert policy.interval == 0
    assert policy.retry_transport_errors is True


@pytest.mark.parametrize("field", ["attempts", "interval"])
def test_rest_retry_policy_rejects_boolean_integer_fields(field: str) -> None:
    values = {"attempts": 3, "interval": 1}
    values[field] = True

    with pytest.raises(TypeError, match=field):
        RestRetryPolicy(**values)


@pytest.mark.parametrize(
    ("values", "match"),
    [
        ({"attempts": 0, "interval": 1}, "attempts"),
        ({"attempts": 1, "interval": -1}, "interval"),
    ],
)
def test_rest_retry_policy_rejects_out_of_range_values(values: dict[str, int], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        RestRetryPolicy(**values)
