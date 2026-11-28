# Copyright: (c) 2026, astawast <astawast@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Redact secrets from diagnostic copies of requests and controller responses.

Ansible's ``no_log_values`` scrubbing only applies to the result a module
returns. Debug log records and the stored public copies of API calls are built
earlier, sometimes before a controller-returned secret is known, so they are
redacted here instead:

-   by key: any mapping key a model declares as a secret field or sensitive
    container is masked at any depth, which covers values not yet registered;
-   by value: registered ``no_log_values`` are replaced inside log text.

Secret field values found in raw controller responses are also registered as
``no_log_values`` so Ansible scrubs them from the final module result.

Requests sent to the controller are never redacted.
"""

# isort: off
# fmt: off
from __future__ import (absolute_import, division, print_function)
from __future__ import annotations
# fmt: on
# isort: on

from typing import Any, Iterable

NO_LOG_PLACEHOLDER = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"

_MODULE_ATTRIBUTE = "_nd_secret_redactor"


class SecretRedactor:
    """
    # Summary

    Hold the secret key names for one module run and redact copies of data for logs and public output.

    Registered secret values are read from ``module.no_log_values`` on every call, so values registered after
    construction (for example controller-returned passwords) are honoured without re-wiring.

    ## Raises

    None
    """

    def __init__(self, module: Any = None) -> None:
        self._module = module
        self._keys: set[str] = set()
        self._value_keys: set[str] = set()

    @property
    def keys(self) -> frozenset[str]:
        """Secret field and sensitive-container names, snake_case and API aliases."""
        return frozenset(self._keys)

    def add_keys(self, keys: Iterable[str]) -> None:
        """Register more secret key names (for example ``NDBaseModel.redaction_keys()``)."""
        self._keys.update(key for key in keys if isinstance(key, str) and key)

    def add_secret_value_keys(self, keys: Iterable[str]) -> None:
        """Register secret field names (``NDBaseModel.secret_value_keys()``) whose values `register_secret_values` collects."""
        keys = {key for key in keys if isinstance(key, str) and key}
        self._keys.update(keys)
        self._value_keys.update(keys)

    def register_secret_values(self, data: Any) -> None:
        """
        # Summary

        Add every non-empty string under a secret field name in ``data`` to ``module.no_log_values``.

        Called on each raw controller response, before it is filtered or converted, so secrets of objects the
        module does not manage are also scrubbed from the final result.

        ## Raises

        None
        """
        values = getattr(self._module, "no_log_values", None)
        if not self._value_keys or not isinstance(values, set):
            return
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                for key, value in item.items():
                    if key in self._value_keys and isinstance(value, str) and value:
                        values.add(value)
                    else:
                        stack.append(value)
            elif isinstance(item, (list, tuple)):
                stack.extend(item)

    def _secret_values(self) -> list[str]:
        values = getattr(self._module, "no_log_values", None)
        if not isinstance(values, (set, frozenset, list, tuple)):
            return []
        # Longest first so a secret that contains another is replaced whole.
        return sorted((value for value in values if isinstance(value, str) and value), key=len, reverse=True)

    def redact_keys(self, data: Any) -> Any:
        """Return a copy of ``data`` with every value under a secret key masked. ``data`` is never mutated."""
        if not self._keys:
            return data
        return self._walk(data, self._keys, ())

    def redact(self, data: Any) -> Any:
        """Return a copy of ``data`` masked by secret key and by registered secret value. For log records."""
        return self._walk(data, self._keys, self._secret_values())

    def redact_text(self, text: Any) -> str:
        """Return ``str(text)`` with registered secret values replaced. For log and error text."""
        return self._replace_values(str(text), self._secret_values())

    @staticmethod
    def _replace_values(text: str, values: Iterable[str]) -> str:
        for value in values:
            if value in text:
                text = text.replace(value, NO_LOG_PLACEHOLDER)
        return text

    def _walk(self, data: Any, keys: set[str], values: Iterable[str]) -> Any:
        if isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                if key in keys and value not in (None, ""):
                    redacted[key] = NO_LOG_PLACEHOLDER
                else:
                    redacted[key] = self._walk(value, keys, values)
            return redacted
        if isinstance(data, (list, tuple)):
            return [self._walk(item, keys, values) for item in data]
        if isinstance(data, str) and values:
            return self._replace_values(data, values)
        return data


def get_redactor(module: Any) -> SecretRedactor:
    """
    # Summary

    Return the module run's shared `SecretRedactor`, creating it on first use.

    The redactor is stored on the module object so every `RestSend`, `Sender`, and `Results` built for the same run
    shares one set of secret keys. A missing module yields a fresh redactor with no keys and no values.

    ## Raises

    None
    """
    if module is None:
        return SecretRedactor()
    redactor = getattr(module, _MODULE_ATTRIBUTE, None)
    if isinstance(redactor, SecretRedactor):
        return redactor
    redactor = SecretRedactor(module)
    try:
        setattr(module, _MODULE_ATTRIBUTE, redactor)
    except AttributeError:
        pass
    return redactor
