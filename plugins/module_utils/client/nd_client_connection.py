# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Duck typed drop in for ansible.module_utils.connection.Connection.

``NDModule.set_connection()`` creates an ``NDClientConnection`` when the
action plugin attached an ``NDClient`` to the module. All methods forward to
the underlying client so the rest of the codebase (NDModule, orchestrators,
endpoints) is unchanged.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class NDClientConnection(object):
    """Connection like facade around an ``NDClient`` instance."""

    def __init__(self, nd_client):
        self._client = nd_client
        if nd_client._token:
            self._auth = {
                "Authorization": "Bearer {0}".format(nd_client._token),
                "Cookie": "AuthCookie={0}".format(nd_client._token),
            }
        else:
            self._auth = None

        self._params = {}
        self._messages = []
        self._connected = True

    def send_request(self, method, path, data=None):
        """Forward a request to the underlying ``NDClient``."""
        return self._client.request(method, path, data=data)

    def send_file_request(self, method, path, file=None, data=None,
                          remote_path=None, file_key="file", file_ext=None):
        """File transfer is not supported on the fast path; use httpapi for these tasks."""
        raise NotImplementedError(
            "File upload/download is not yet supported via NDClient. "
            "Use 'connection: httpapi' in inventory for this specific task."
        )

    def pop_messages(self):
        """Drain and return any queued debug messages."""
        msgs = self._messages
        self._messages = []
        return msgs

    def queue_message(self, level, msg):
        """Append a debug message for later retrieval by ``pop_messages``."""
        self._messages.append((level, msg))

    def set_params(self, params):
        """Store module params exposed through ``get_option`` / ``set_option``."""
        self._params = params or {}

    def get_option(self, name):
        """Return a connection option; common ones are mapped to client attributes."""
        mapping = {
            "host": self._client.host,
            "port": self._client.port,
            "remote_user": self._client.username,
            "password": self._client.password,
            "login_domain": self._client.login_domain,
            "use_ssl": True,
            "validate_certs": self._client.verify_certs,
            "timeout": self._client.timeout,
        }
        if name in mapping:
            return mapping[name]
        return self._params.get(name)

    def set_option(self, name, value):
        """Override a connection option at runtime."""
        self._params[name] = value

    def get_version(self, platform="nd"):
        """Forward to ``NDClient.get_version`` for ``NDModule.version``."""
        return self._client.get_version(platform)
