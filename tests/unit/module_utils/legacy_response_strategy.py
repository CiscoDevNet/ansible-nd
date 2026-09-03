# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

A structural response validation strategy implementing only the original (pre-#502) `ResponseValidationStrategy` members.

## Description

`LegacyStrategy` implements every member of `ResponseValidationStrategy` and nothing else — in particular no `is_terminal_client_error()`
(the optional `TerminalClientErrorPolicy` capability). It stands in for an out-of-tree strategy written against the older protocol, so unit
tests can prove that such a strategy is still accepted by `ResponseHandler.validation_strategy` and keeps the historical retry behavior
(every non-success 4xx retryable). Shared by `test_response_handler_nd.py` and `test_rest_send.py`.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name


class LegacyStrategy:
    """
    # Summary

    Pre-#502 structural strategy: satisfies `ResponseValidationStrategy` but not `TerminalClientErrorPolicy`.

    ## Raises

    None
    """

    @property
    def success_codes(self) -> set[int]:
        """
        # Summary

        HTTP status codes treated as success.

        ## Raises

        None
        """
        return {200, 201, 202, 204, 207}

    @property
    def not_found_code(self) -> int:
        """
        # Summary

        HTTP status code treated as not-found.

        ## Raises

        None
        """
        return 404

    def is_success(self, response: dict) -> bool:
        """
        # Summary

        True when `RETURN_CODE` is a success code.

        ## Raises

        None
        """
        return response["RETURN_CODE"] in self.success_codes

    def is_not_found(self, return_code: int) -> bool:
        """
        # Summary

        True when `return_code` is the not-found code.

        ## Raises

        None
        """
        return return_code == self.not_found_code

    def is_changed(self, response: dict) -> bool:
        """
        # Summary

        True unless the `modified` header is explicitly `"false"`.

        ## Raises

        None
        """
        return response.get("modified") != "false"

    def is_changed_on_failure(self, response: dict) -> bool:  # pylint: disable=unused-argument
        """
        # Summary

        A failed mutation never changed state under this strategy.

        ## Raises

        None
        """
        return False

    def extract_error_message(self, response: dict) -> str | None:
        """
        # Summary

        Return the HTTP reason phrase as the error message.

        ## Raises

        None
        """
        return response.get("MESSAGE")
