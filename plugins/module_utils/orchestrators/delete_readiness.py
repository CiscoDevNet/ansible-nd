# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Delete-readiness timing helpers for resource workflows."""

from __future__ import annotations

import time

from dataclasses import dataclass


@dataclass(frozen=True)
class DeleteReadinessPolicy:
    """
    # Summary

    Calculates internal wait budgets for delete-readiness polling.

    ## Raises

    ### ValueError

    - If `poll_interval`, `chunk_size`, `base_timeout`, `extra_chunk_timeout`, or `max_timeout` are invalid.
    """

    poll_interval: int
    chunk_size: int
    base_timeout: int
    extra_chunk_timeout: int
    max_timeout: int

    def __post_init__(self) -> None:
        """
        # Summary

        Validate delete-readiness timing settings.

        ## Raises

        ### ValueError

        - If any timing value is outside the supported range.
        """
        if self.poll_interval < 0:
            raise ValueError("poll_interval must be greater than or equal to 0.")
        if self.chunk_size < 1:
            raise ValueError("chunk_size must be greater than 0.")
        if self.base_timeout < 0:
            raise ValueError("base_timeout must be greater than or equal to 0.")
        if self.extra_chunk_timeout < 0:
            raise ValueError("extra_chunk_timeout must be greater than or equal to 0.")
        if self.max_timeout < self.base_timeout:
            raise ValueError("max_timeout must be greater than or equal to base_timeout.")

    def timeout_for(self, item_count: int) -> int:
        """
        # Summary

        Return the delete-readiness timeout for the requested item count.

        ## Raises

        This method does not raise directly.
        """
        extra_chunks = max(0, (max(item_count, 1) - 1) // self.chunk_size)
        return min(self.max_timeout, self.base_timeout + (extra_chunks * self.extra_chunk_timeout))

    def deadline_for(self, item_count: int) -> tuple[float, int]:
        """
        # Summary

        Return the monotonic deadline and timeout seconds for the requested item count.

        ## Raises

        This method does not raise directly.
        """
        timeout = self.timeout_for(item_count)
        return time.monotonic() + timeout, timeout

    @staticmethod
    def now() -> float:
        """
        # Summary

        Return a monotonic timestamp.

        ## Raises

        This method does not raise directly.
        """
        return time.monotonic()
