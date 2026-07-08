# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import time


try:
    from jsonpath_ng import parse

    HAS_JSONPATH_NG_PARSE = True
except ImportError:
    HAS_JSONPATH_NG_PARSE = False

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    """Run an ND 4.x module integration test with a common execution pattern."""

    TRANSFERS_FILES = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp

        args = self._task.args.copy()

        module_name = args.get("module")
        state = args.get("state")
        config = args.get("config")
        common_args = args.get("common_args", {})
        module_args = args.get("module_args", {})
        expected = args.get("expected", {})
        run_check_mode = args.get("check_mode", True)
        run_idempotency = args.get("idempotency", True)
        idempotency_retries = int(args.get("idempotency_retries", 1))
        idempotency_delay = int(args.get("idempotency_delay", 0))
        nd_queries = args.get("nd_queries", [])

        if not module_name:
            raise AnsibleActionFail("Missing required argument: module")

        if not state:
            raise AnsibleActionFail("Missing required argument: state")

        if not isinstance(common_args, dict):
            raise AnsibleActionFail("Argument common_args must be a dictionary")

        if not isinstance(module_args, dict):
            raise AnsibleActionFail("Argument module_args must be a dictionary")

        if not isinstance(expected, dict):
            raise AnsibleActionFail("Argument expected must be a dictionary")

        if not isinstance(nd_queries, list):
            raise AnsibleActionFail("Argument nd_queries must be a list")

        if idempotency_retries < 1:
            raise AnsibleActionFail("Argument idempotency_retries must be 1 or greater")

        if idempotency_delay < 0:
            raise AnsibleActionFail("Argument idempotency_delay must be 0 or greater")

        final_module_args = {}
        final_module_args.update(common_args)
        final_module_args.update(module_args)
        final_module_args["state"] = state

        if config is not None:
            final_module_args["config"] = config

        check_mode_result = None
        first_run_result = None
        second_run_result = None
        idempotency_attempts = 0
        original_check_mode = self._task.check_mode
        nd_query_results = []

        try:
            if run_check_mode:
                self._task.check_mode = True
                check_mode_result = self._run_target_module(
                    module_name=module_name,
                    module_args=final_module_args,
                    task_vars=task_vars,
                )

            self._task.check_mode = False
            first_run_result = self._run_target_module(
                module_name=module_name,
                module_args=final_module_args,
                task_vars=task_vars,
            )

            if run_idempotency and not self._has_unexpected_failure(first_run_result, expected):
                second_run_result, idempotency_attempts = self._run_idempotency_check(
                    module_name=module_name,
                    module_args=final_module_args,
                    task_vars=task_vars,
                    expected=expected,
                    retries=idempotency_retries,
                    delay=idempotency_delay,
                )

            if nd_queries and not bool(first_run_result.get("failed", False)):
                nd_query_results = self._run_nd_queries(
                    nd_queries=nd_queries,
                    task_vars=task_vars,
                )

        finally:
            self._task.check_mode = original_check_mode

        self._assert_expected(
            expected=expected,
            check_mode_result=check_mode_result,
            first_run_result=first_run_result,
            second_run_result=second_run_result,
            idempotency_attempts=idempotency_attempts,
        )

        result.update(
            {
                "changed": bool(first_run_result and first_run_result.get("changed", False)),
                "check_mode_result": check_mode_result,
                "first_run_result": first_run_result,
                "second_run_result": second_run_result,
                "idempotency_attempts": idempotency_attempts,
                "nd_query_results": nd_query_results,
            }
        )

        return result

    def _run_target_module(self, module_name, module_args, task_vars):
        return self._execute_module(
            module_name=module_name,
            module_args=module_args,
            task_vars=task_vars,
        )

    def _run_nd_queries(self, nd_queries, task_vars):
        results = []

        for query in nd_queries:
            if not isinstance(query, dict):
                raise AnsibleActionFail("Each nd_queries entry must be a dictionary")

            name = query.get("name")
            path = query.get("path")
            method = query.get("method", "get")
            expected_status = query.get("expected_status")
            expected_failed = bool(query.get("expected_failed", False))

            if not path:
                raise AnsibleActionFail("Each nd_queries entry must include path")

            rendered_path = self._templar.template(path)

            query_result = self._execute_module(
                module_name="cisco.nd.nd_rest",
                module_args={
                    "path": rendered_path,
                    "method": method,
                },
                task_vars=task_vars,
            )

            query_label = name or rendered_path
            actual_failed = bool(query_result.get("failed", False))
            actual_status = query_result.get("status")

            if expected_status is not None:
                if actual_status is None:
                    raise AnsibleActionFail(
                        "ND query %s expected status %s but the result did not contain a status"
                        % (query_label, expected_status)
                    )

                try:
                    status_matches = int(actual_status) == int(expected_status)
                except (TypeError, ValueError):
                    raise AnsibleActionFail(
                        "ND query %s returned invalid status %s"
                        % (query_label, actual_status)
                    )

                if not status_matches:
                    raise AnsibleActionFail(
                        "ND query %s expected status %s but got %s"
                        % (query_label, expected_status, actual_status)
                    )
            if actual_failed != expected_failed:
                raise AnsibleActionFail(
                    "ND query %s expected failed=%s but got failed=%s"
                    % (query_label, expected_failed, actual_failed)
                )

            if not expected_failed:
                self._assert_nd_query_expectations(query, query_result)

            results.append(
                {
                    "name": name,
                    "path": rendered_path,
                    "method": method,
                    "status": actual_status,
                    "failed": actual_failed,
                    "result": query_result,
                }
            )

        return results

    def _assert_nd_query_expectations(self, query, query_result):
        expectations = query.get("expect", [])

        if not isinstance(expectations, list):
            raise AnsibleActionFail("nd_queries expect must be a list")

        for expectation in expectations:
            if not isinstance(expectation, dict):
                raise AnsibleActionFail("Each nd_queries expectation must be a dictionary")

            expression = expectation.get("jsonpath")
            if not expression:
                raise AnsibleActionFail("Each nd_queries expectation must include jsonpath")

            values = self._jsonpath_values(query_result, expression)

            if "exists" in expectation:
                expected_exists = bool(expectation["exists"])
                actual_exists = len(values) > 0

                if actual_exists != expected_exists:
                    raise AnsibleActionFail(
                        "ND query expectation failed for %s: expected exists=%s but got exists=%s"
                        % (expression, expected_exists, actual_exists)
                    )

            if "equals" in expectation:
                expected_value = expectation["equals"]

                if not values:
                    raise AnsibleActionFail(
                        "ND query expectation failed for %s: no value found, expected %s"
                        % (expression, expected_value)
                    )

                if values[0] != expected_value:
                    raise AnsibleActionFail(
                        "ND query expectation failed for %s: expected %s but got %s"
                        % (expression, expected_value, values[0])
                    )

    def _jsonpath_values(self, data, expression):
        if not HAS_JSONPATH_NG_PARSE:
            raise AnsibleActionFail(
                "Cannot use JSONPath validation because the jsonpath-ng "
                "Python library is not available"
            )
        try:
            jsonpath_expression = parse(expression)
        except Exception as exc:
            raise AnsibleActionFail("Invalid JSONPath expression %s: %s" % (expression, exc))
        return [match.value for match in jsonpath_expression.find(data)]

    def _has_unexpected_failure(self, module_result, expected):
        if module_result is None:
            return False

        expected_failed = bool(expected.get("failed", False))
        actual_failed = bool(module_result.get("failed", False))
        return actual_failed != expected_failed

    def _run_idempotency_check(self, module_name, module_args, task_vars, expected, retries, delay):
        expected_changed = None

        if "idempotency" in expected:
            expected_changed = not bool(expected["idempotency"])
        elif "second_run_changed" in expected:
            expected_changed = bool(expected["second_run_changed"])

        for attempt in range(1, retries + 1):
            module_result = self._run_target_module(
                module_name=module_name,
                module_args=module_args,
                task_vars=task_vars,
            )

            if expected_changed is None:
                return module_result, attempt

            actual_changed = bool(module_result.get("changed", False))
            if actual_changed == expected_changed:
                return module_result, attempt

            if attempt < retries and delay:
                time.sleep(delay)

        return module_result, retries

    def _assert_expected(
        self,
        expected,
        check_mode_result,
        first_run_result,
        second_run_result,
        idempotency_attempts,
    ):
        expected_failed = bool(expected.get("failed", False))
        failed_checks = [
            ("check_mode_result", check_mode_result),
            ("first_run_result", first_run_result),
            ("second_run_result", second_run_result),
        ]

        for result_name, module_result in failed_checks:
            if module_result is None:
                continue

            actual_failed = bool(module_result.get("failed", False))

            if actual_failed != expected_failed:
                raise AnsibleActionFail(
                    self._format_expectation_failure(
                        message="Expected %s failed=%s but got failed=%s"
                        % (result_name, expected_failed, actual_failed),
                        check_mode_result=check_mode_result,
                        first_run_result=first_run_result,
                        second_run_result=second_run_result,
                        idempotency_attempts=idempotency_attempts,
                    )
                )

        changed_checks = [
            ("check_mode_changed", check_mode_result),
            ("apply_changed", first_run_result),
            ("first_run_changed", first_run_result),
            ("second_run_changed", second_run_result),
        ]

        for expected_key, module_result in changed_checks:
            if expected_key not in expected:
                continue

            if module_result is None:
                raise AnsibleActionFail(
                    "Expected %s but the related module run was skipped" % expected_key
                )

            expected_value = bool(expected[expected_key])
            actual_value = bool(module_result.get("changed", False))

            if actual_value != expected_value:
                raise AnsibleActionFail(
                    self._format_expectation_failure(
                        message="Expected %s=%s but got changed=%s"
                        % (expected_key, expected_value, actual_value),
                        check_mode_result=check_mode_result,
                        first_run_result=first_run_result,
                        second_run_result=second_run_result,
                        idempotency_attempts=idempotency_attempts,
                    )
                )
        if "idempotency" in expected:
            if second_run_result is None:
                raise AnsibleActionFail("Expected idempotency but the idempotency run was skipped")

            expected_idempotent = bool(expected["idempotency"])
            actual_idempotent = not bool(second_run_result.get("changed", False))

            if actual_idempotent != expected_idempotent:
                raise AnsibleActionFail(
                    self._format_expectation_failure(
                        message="Expected idempotency=%s but got idempotency=%s"
                        % (expected_idempotent, actual_idempotent),
                        check_mode_result=check_mode_result,
                        first_run_result=first_run_result,
                        second_run_result=second_run_result,
                        idempotency_attempts=idempotency_attempts,
                    )
                )

    def _format_expectation_failure(
        self,
        message,
        check_mode_result,
        first_run_result,
        second_run_result,
        idempotency_attempts,
    ):
        summary = {
            "idempotency_attempts": idempotency_attempts,
            "check_mode_result": self._summarize_module_result(check_mode_result),
            "first_run_result": self._summarize_module_result(first_run_result),
            "second_run_result": self._summarize_module_result(second_run_result),
        }
        return "%s\nRun summary: %s" % (message, json.dumps(summary, sort_keys=True))

    def _summarize_module_result(self, module_result):
        if module_result is None:
            return None

        summary = {
            "changed": bool(module_result.get("changed", False)),
            "failed": bool(module_result.get("failed", False)),
        }

        if module_result.get("msg"):
            summary["msg"] = module_result.get("msg")

        diff = module_result.get("diff")
        if isinstance(diff, list):
            summary["diff_count"] = len(diff)
        elif diff:
            summary["diff_present"] = True

        for key in ("before", "after", "proposed"):
            value = module_result.get(key)
            if isinstance(value, list):
                summary["%s_count" % key] = len(value)
                summary["%s_items" % key] = [
                    self._summarize_config_item(item) for item in value[:10]
                ]
            elif value is not None:
                summary[key] = value

        return summary

    def _summarize_config_item(self, item):
        if not isinstance(item, dict):
            return item

        config_data = item.get("config_data") or item.get("configData") or {}
        network_os = config_data.get("network_os") or config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}

        return {
            "switch_ip": item.get("switch_ip") or item.get("switchIp"),
            "interface_name": item.get("interface_name") or item.get("interfaceName"),
            "interface_type": item.get("interface_type") or item.get("interfaceType"),
            "ip": policy.get("ip"),
            "vrf": policy.get("vrf") or policy.get("vrfInterface"),
            "policy_type": policy.get("policy_type") or policy.get("policyType"),
        }
