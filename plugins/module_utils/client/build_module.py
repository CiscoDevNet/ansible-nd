# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Drop in replacement for ``AnsibleModule()`` inside cisco.nd module ``main()``.

In subprocess mode (no action plugin) ``build_module`` returns a real
AnsibleModule. When the action plugin has stashed an ``NDClient`` and task
args on the thread local context, ``build_module`` returns an
``NDInlineModule`` instead. The rest of the module (orchestrator, state
machine, endpoints) is agnostic.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import threading

from ansible.module_utils.basic import AnsibleModule


_context = threading.local()


def set_inline_context(params, nd_client, check_mode=False, diff=False):
    """Stash NDClient + rendered params on the thread local context."""
    _context.params = params
    _context.nd_client = nd_client
    _context.check_mode = check_mode
    _context.diff = diff


def clear_inline_context():
    """Drop any thread local context entries set by the action plugin."""
    for attr in ("params", "nd_client", "check_mode", "diff"):
        if hasattr(_context, attr):
            delattr(_context, attr)


def build_module(argument_spec, **kwargs):
    """Return a real AnsibleModule, or an NDInlineModule when running in process."""
    nd_client = getattr(_context, "nd_client", None)

    if nd_client is None:
        return AnsibleModule(argument_spec=argument_spec, **kwargs)

    from ansible_collections.cisco.nd.plugins.module_utils.client.nd_inline_module import (
        NDInlineModule,
    )

    return NDInlineModule(
        raw_params=getattr(_context, "params", {}),
        argument_spec=argument_spec,
        nd_client=nd_client,
        check_mode=getattr(_context, "check_mode", False),
        diff=getattr(_context, "diff", False),
        mutually_exclusive=kwargs.get("mutually_exclusive"),
        required_together=kwargs.get("required_together"),
        required_one_of=kwargs.get("required_one_of"),
        required_if=kwargs.get("required_if"),
        required_by=kwargs.get("required_by"),
    )
