# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Response generator for unit tests.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name


class ResponseGenerator:
    """
    Given a coroutine which yields dictionaries, return the yielded items
    with each call to the next property

    For usage in the context of dcnm_image_policy unit tests, see:
        test: test_image_policy_create_bulk_00037
        file: tests/unit/modules/dcnm/dcnm_image_policy/test_image_policy_create_bulk.py

    Simplified usage example below.

    def responses():
        yield {"key1": "value1"}
        yield {"key2": "value2"}

    gen = ResponseGenerator(responses())

    print(gen.next) # {"key1": "value1"}
    print(gen.next) # {"key2": "value2"}
    """

    def __init__(self, gen):
        self.gen = gen

    @property
    def next(self):
        """
        Return the next item in the generator
        """
        return next(self.gen)

    @property
    def implements(self):
        """
        ### Summary
        Used by Sender() classes to verify Sender().gen is a
        response generator which implements the response_generator
        interfacee.
        """
        return "response_generator"

    def public_method_for_pylint(self):
        """
        Add one public method to appease pylint
        """
