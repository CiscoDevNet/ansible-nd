# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Callback plugin that removes the cisco.nd session cache after each playbook run.

Enable in ansible.cfg:

    [defaults]
    callbacks_enabled = cisco.nd.nd_session_cleanup

When disabled, tokens persist on disk until ``NDClient.SESSION_CACHE_TTL``.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
  name: nd_session_cleanup
  type: aggregate
  short_description: Delete cisco.nd on-disk session caches at end of playbook.
  description:
    - Deletes the per-user token cache files used by the cisco.nd fast path
      once a playbook completes.
    - Enable when you want zero on-disk persistence of ND tokens between plays.
  requirements:
    - Enable via callbacks_enabled in ansible.cfg under [defaults].
"""

import glob
import os

from ansible.plugins.callback import CallbackBase


_XDG_CACHE = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
_CACHE_GLOB = os.path.join(_XDG_CACHE, "ansible-cisco-nd", "nd_session_*.json")


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "cisco.nd.nd_session_cleanup"
    CALLBACK_NEEDS_ENABLED = True

    def v2_playbook_on_stats(self, stats):
        """Delete any leftover session cache files after the playbook finishes."""
        for path in glob.glob(_CACHE_GLOB):
            try:
                os.unlink(path)
            except OSError:
                pass
