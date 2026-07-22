# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

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

    ALLOWED_ARGUMENTS = {
        "module",
        "state",
        "config",
        "common_args",
        "module_args",
        "expected",
        "check_mode",
        "idempotency",
        "idempotency_retries",
        "idempotency_delay",
        "nd_queries",
    }

    ALLOWED_EXPECTED_PHASES = {
        "check_mode",
        "apply",
        "idempotency",
    }

    ALLOWED_PHASE_EXPECTATIONS = {
        "changed",
        "failed",
    }

    ALLOWED_ND_QUERY_ARGUMENTS = {
        "name",
        "path",
        "method",
        "expected_status",
        "expected_failed",
        "expect",
    }

    ALLOWED_ND_EXPECTATION_ARGUMENTS = {
        "jsonpath",
        "exists",
        "equals",
    }

    def _reject_unknown_keys(self, value, allowed_keys, argument_name):
        unknown_keys = sorted(set(value) - allowed_keys)

        if unknown_keys:
            raise AnsibleActionFail(
                "Unsupported keys in %s: %s"
                % (argument_name, ", ".join(unknown_keys))
            )

    def _parse_bool(self, value, argument_name):
        if isinstance(value, bool):
            return value

        if isinstance(value, int) and value in (0, 1):
            return bool(value)

        if isinstance(value, str):
            normalized = value.strip().lower()

            if normalized in ("true", "yes", "on", "1"):
                return True

            if normalized in ("false", "no", "off", "0"):
                return False

        raise AnsibleActionFail(
            "Argument %s must be a boolean, got %r"
            % (argument_name, value)
        )

    def _parse_int(self, value, argument_name):
        try:
            return int(value)
        except (TypeError, ValueError):
            raise AnsibleActionFail(
                "Argument %s must be an integer, got %r"
                % (argument_name, value)
            )

    def _validate_arguments(self, args):
        if not isinstance(args, dict):
            raise AnsibleActionFail("Action-plugin arguments must be a dictionary")

        self._reject_unknown_keys(
            args,
            self.ALLOWED_ARGUMENTS,
            "nd4x_module_test",
        )

        module_name = args.get("module")
        state = args.get("state")

        if not isinstance(module_name, str) or not module_name.strip():
            raise AnsibleActionFail(
                "Argument module must be a non-empty string"
            )

        if not isinstance(state, str) or not state.strip():
            raise AnsibleActionFail(
                "Argument state must be a non-empty string"
            )

        for name in ("common_args", "module_args", "expected"):
            value = args.get(name, {})

            if not isinstance(value, dict):
                raise AnsibleActionFail(
                    "Argument %s must be a dictionary" % name
                )

        nd_queries = args.get("nd_queries", [])

        if not isinstance(nd_queries, list):
            raise AnsibleActionFail(
                "Argument nd_queries must be a list"
            )

    def _normalize_expected(self, expected):
        self._reject_unknown_keys(
            expected,
            self.ALLOWED_EXPECTED_PHASES,
            "expected",
        )

        normalized = {}

        for phase_name, phase_expectation in expected.items():
            if not isinstance(phase_expectation, dict):
                raise AnsibleActionFail(
                    "Argument expected.%s must be a dictionary"
                    % phase_name
                )

            self._reject_unknown_keys(
                phase_expectation,
                self.ALLOWED_PHASE_EXPECTATIONS,
                "expected.%s" % phase_name,
            )

            normalized[phase_name] = {}

            if "changed" in phase_expectation:
                normalized[phase_name]["changed"] = self._parse_bool(
                    phase_expectation["changed"],
                    "expected.%s.changed" % phase_name,
                )

            if "failed" in phase_expectation:
                normalized[phase_name]["failed"] = self._parse_bool(
                    phase_expectation["failed"],
                    "expected.%s.failed" % phase_name,
                )

        return normalized

    def _validate_nd_queries(self, nd_queries):
        for query_index, query in enumerate(nd_queries):
            if not isinstance(query, dict):
                raise AnsibleActionFail(
                    "nd_queries[%s] must be a dictionary"
                    % query_index
                )

            self._reject_unknown_keys(
                query,
                self.ALLOWED_ND_QUERY_ARGUMENTS,
                "nd_queries[%s]" % query_index,
            )

            path = query.get("path")

            if not isinstance(path, str) or not path.strip():
                raise AnsibleActionFail(
                    "nd_queries[%s].path must be a non-empty string"
                    % query_index
                )

            if "expected_failed" in query:
                self._parse_bool(
                    query["expected_failed"],
                    "nd_queries[%s].expected_failed" % query_index,
                )

            expectations = query.get("expect", [])

            if not isinstance(expectations, list):
                raise AnsibleActionFail(
                    "nd_queries[%s].expect must be a list"
                    % query_index
                )

            for expectation_index, expectation in enumerate(expectations):
                if not isinstance(expectation, dict):
                    raise AnsibleActionFail(
                        "nd_queries[%s].expect[%s] must be a dictionary"
                        % (query_index, expectation_index)
                    )

                self._reject_unknown_keys(
                    expectation,
                    self.ALLOWED_ND_EXPECTATION_ARGUMENTS,
                    "nd_queries[%s].expect[%s]"
                    % (query_index, expectation_index),
                )

                expression = expectation.get("jsonpath")

                if not isinstance(expression, str) or not expression.strip():
                    raise AnsibleActionFail(
                        "nd_queries[%s].expect[%s].jsonpath "
                        "must be a non-empty string"
                        % (query_index, expectation_index)
                    )

                if "exists" in expectation:
                    self._parse_bool(
                        expectation["exists"],
                        "nd_queries[%s].expect[%s].exists"
                        % (query_index, expectation_index),
                    )

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp

        args = self._task.args.copy()
        self._validate_arguments(args)

        module_name = args.get("module")
        state = args.get("state")
        config = args.get("config")
        common_args = args.get("common_args", {})
        module_args = args.get("module_args", {})

        expected = self._normalize_expected(
            args.get("expected", {})
        )

        run_check_mode = self._parse_bool(
            args.get("check_mode", True),
            "check_mode",
        )

        run_idempotency = self._parse_bool(
            args.get("idempotency", True),
            "idempotency",
        )

        idempotency_retries = self._parse_int(
            args.get("idempotency_retries", 1),
            "idempotency_retries",
        )

        idempotency_delay = self._parse_int(
            args.get("idempotency_delay", 0),
            "idempotency_delay",
        )

        nd_queries = args.get("nd_queries", [])
        self._validate_nd_queries(nd_queries)

        if idempotency_retries != 1:
            raise AnsibleActionFail(
                "Argument idempotency_retries must be 1 because "
                "idempotency performs exactly one second application"
            )

        if idempotency_delay != 0:
            raise AnsibleActionFail(
                "Argument idempotency_delay must be 0 because "
                "idempotency retries are not supported"
            )

        # Automatically require the second run to be unchanged.
        if run_idempotency:
            idempotency_expected = expected.setdefault(
                "idempotency",
                {},
            )

            if (
                "changed" in idempotency_expected
                and idempotency_expected["changed"] is not False
            ):
                raise AnsibleActionFail(
                    "expected.idempotency.changed must be false "
                    "when idempotency is enabled"
                )

            idempotency_expected["changed"] = False
            idempotency_expected.setdefault("failed", False)

        # Unless explicitly overridden, every executed phase must succeed.
        expected.setdefault("check_mode", {}).setdefault(
            "failed",
            False,
        )
        expected.setdefault("apply", {}).setdefault(
            "failed",
            False,
        )

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
        nd_query_results = []

        play_context = getattr(
            self,
            "_play_context",
            None,
        )
        global_check_mode = bool(
            getattr(play_context, "check_mode", False)
        )
        original_check_mode = self._task.check_mode

        try:
            if global_check_mode:
                # Ansible was started with --check. Run only the
                # predictive check-mode phase.
                self._task.check_mode = True

                check_mode_result = self._run_target_module(
                    module_name=module_name,
                    module_args=final_module_args,
                    task_vars=task_vars,
                )

                self._assert_phase(
                    phase_name="check_mode",
                    module_result=check_mode_result,
                    phase_expectation=expected.get(
                        "check_mode",
                        {"failed": False},
                    ),
                    check_mode_result=check_mode_result,
                    first_run_result=None,
                    second_run_result=None,
                    idempotency_attempts=0,
                )

            else:
                # Optional internal predictive phase.
                if run_check_mode:
                    self._task.check_mode = True

                    check_mode_result = self._run_target_module(
                        module_name=module_name,
                        module_args=final_module_args,
                        task_vars=task_vars,
                    )

                    self._assert_phase(
                        phase_name="check_mode",
                        module_result=check_mode_result,
                        phase_expectation=expected.get(
                            "check_mode",
                            {"failed": False},
                        ),
                        check_mode_result=check_mode_result,
                        first_run_result=None,
                        second_run_result=None,
                        idempotency_attempts=0,
                    )

                # First and only initial real application.
                self._task.check_mode = False

                first_run_result = self._run_target_module(
                    module_name=module_name,
                    module_args=final_module_args,
                    task_vars=task_vars,
                )

                self._assert_phase(
                    phase_name="apply",
                    module_result=first_run_result,
                    phase_expectation=expected.get(
                        "apply",
                        {"failed": False},
                    ),
                    check_mode_result=check_mode_result,
                    first_run_result=first_run_result,
                    second_run_result=None,
                    idempotency_attempts=0,
                )

                # Run exactly one second application for idempotency.
                if (
                    run_idempotency
                    and not bool(
                        first_run_result.get("failed", False)
                    )
                ):
                    second_run_result = (
                        self._run_target_module(
                            module_name=module_name,
                            module_args=final_module_args,
                            task_vars=task_vars,
                        )
                    )
                    idempotency_attempts = 1

                    self._assert_phase(
                        phase_name="idempotency",
                        module_result=second_run_result,
                        phase_expectation=expected[
                            "idempotency"
                        ],
                        check_mode_result=check_mode_result,
                        first_run_result=first_run_result,
                        second_run_result=second_run_result,
                        idempotency_attempts=idempotency_attempts,
                    )

                # REST validation is performed only after a real apply.
                if (
                    nd_queries
                    and not bool(
                        first_run_result.get("failed", False)
                    )
                ):
                    nd_query_results = self._run_nd_queries(
                        nd_queries=nd_queries,
                        task_vars=task_vars,
                    )

        finally:
            self._task.check_mode = original_check_mode

        reported_result = (
            check_mode_result
            if global_check_mode
            else first_run_result
        )
        result.update(
            {
                "changed": bool(
                    reported_result
                    and reported_result.get("changed", False)
                ),

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
            expected_failed = self._parse_bool(
                query.get("expected_failed", False),
                "nd_queries.expected_failed",
            )

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
                expected_exists = self._parse_bool(
                    expectation["exists"],
                    "nd_queries.expect.exists",
                )
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

    def _assert_phase(
        self,
        phase_name,
        module_result,
        phase_expectation,
        check_mode_result,
        first_run_result,
        second_run_result,
        idempotency_attempts,
    ):
        if module_result is None:
            raise AnsibleActionFail(
                "Expected phase %s was not executed"
                % phase_name
            )

        if "failed" in phase_expectation:
            expected_failed = phase_expectation["failed"]
            actual_failed = bool(
                module_result.get("failed", False)
            )

            if actual_failed != expected_failed:
                raise AnsibleActionFail(
                    self._format_expectation_failure(
                        message=(
                            "Expected %s failed=%s but got failed=%s"
                            % (
                                phase_name,
                                expected_failed,
                                actual_failed,
                            )
                        ),
                        check_mode_result=check_mode_result,
                        first_run_result=first_run_result,
                        second_run_result=second_run_result,
                        idempotency_attempts=idempotency_attempts,
                    )
                )

        if "changed" in phase_expectation:
            expected_changed = phase_expectation["changed"]
            actual_changed = bool(
                module_result.get("changed", False)
            )

            if actual_changed != expected_changed:
                raise AnsibleActionFail(
                    self._format_expectation_failure(
                        message=(
                            "Expected %s changed=%s but got changed=%s"
                            % (
                                phase_name,
                                expected_changed,
                                actual_changed,
                            )
                        ),
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
