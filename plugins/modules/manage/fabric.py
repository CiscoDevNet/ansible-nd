import copy
import inspect
import json
import logging

from ansible.module_utils._text import to_bytes
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, write_file

from ...module_utils.common.log import Log


class Common():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, params):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")
        # super().__init__()
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        self.playbook_params = params
        self.state = params['state']
        self.payloads = {}

        self.have = {}
        self.query = []
        self.validated = []
        self.want = []

        msg = "ENTERED Common(): "
        # msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

class Merged():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, params):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.common = Common(params)
        import epdb ; epdb.serve(port=5555)

        msg = "ENTERED Merged(): "
        # msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

class Replaced():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, params):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        msg = "ENTERED Replaced(): "
        # msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

class Deleted():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, params):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        msg = "ENTERED Deleted(): "
        # msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

class Query():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, params):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        msg = "ENTERED Query(): "
        # msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        state=dict(type="str", default="merged", choices=["merged", "replaced", "deleted"]),
        config=dict(required=False, type="list", elements="dict"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Logging setup
    try:
        log = Log()
        log.commit()
        mainlog = logging.getLogger(f"nd.main")
    except ValueError as error:
        ansible_module.fail_json(str(error))

    nd = NDModule(module)

    config = nd.params.get("config")

    try:
        task = None
        if nd.params.get("state") == "merged":
            task = Merged(nd.params)
        elif nd.params.get("state") == "replaced":
            task = Replaced(nd.params)
        elif nd.params.get("state") == "deleted":
            task = Deleted(nd.params)
        elif nd.params.get("state") == "query":
            task = Query(nd.params)
        if task is None:
            ansible_module.fail_json(f"Invalid state: {params['state']}")
    except ValueError as error:
        ansible_module.fail_json(f"{error}")

    create_path = "/api/v1/manage/fabrics"
    fabric = config[0]
    payload = {
        "name": f"{fabric['name']}",
        "securityDomain": f"{fabric['securityDomain']}",
        "management": {
            "type": f"{fabric['management']['type']}",
            "bgpAsn": f"{fabric['management']['bgpAsn']}",
            "anycastGatewayMac": f"{fabric['management']['anycastGatewayMac']}",
            "replicationMode": f"{fabric['management']['replicationMode']}",
        }
    }

    mainlog.info('Calling nd.request in main')
    nd.request(create_path, method="POST", data=payload)

    nd.exit_json()


if __name__ == "__main__":
    main()

# {
#   "name": "{{fabric}}",
#   "securityDomain": "all",
#   "management": {
#     "type": "vxlanIbgp",
#     "bgpAsn": "65502.65508",
#     "anycastGatewayMac": "2020.0000.00aa"
#   }
# }