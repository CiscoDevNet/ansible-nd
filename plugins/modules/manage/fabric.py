import copy
import inspect
import json
import logging
import re
from deepdiff import DeepDiff

from ansible.module_utils._text import to_bytes
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, write_file
from ansible_collections.cisco.nd.plugins.module_utils.manage.fabric.model_playbook_fabric import FabricModel

from ...module_utils.common.log import Log

class GetHave():
    """
    Object To Get Fabric State From ND
    """

    def __init__(self, nd):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.path = "/api/v1/manage/fabrics"
        self.verb = "GET"
        self.fabric_state = {}
        self.have = []
        self.nd = nd

        msg = "ENTERED GetHave(): "
        self.log.debug(msg)

    def refresh(self):
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        self.fabric_state = self.nd.request(self.path, method=self.verb)

    def validate_nd_state(self):
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.fabric_state.get('fabrics'):
            fabric_state = {
                "name": f"{fabric['name']}",
                "category": f"{fabric['category']}",
                "securityDomain": f"{fabric['securityDomain']}",
                "management": {
                    "type": f"{fabric['management']['type']}",
                    "bgpAsn": f"{fabric['management']['bgpAsn']}",
                    "anycastGatewayMac": f"{fabric['management']['anycastGatewayMac']}",
                    "replicationMode": f"{fabric['management']['replicationMode']}",
                }
            }
            fabric = FabricModel(**fabric_state)
            self.have.append(fabric)



class Common():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, playbook):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")
        # super().__init__()
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        self.result = dict(changed=False, diff=[], response=[], warnings=[])
        self.playbook_params = playbook
        self.state = playbook['state']
        self.payloads = {}

        self.have = {}
        self.query = []
        self.validated = []
        self.want = []

        self.validate_playbook_params()

        msg = "ENTERED Common(): "
        msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def validate_playbook_params(self):
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.playbook_params.get('config'):
            fabric_config_payload = {
                "name": f"{fabric['name']}",
                "category": f"{fabric['category']}",
                "securityDomain": f"{fabric['securityDomain']}",
                "management": {
                    "type": f"{fabric['management']['type']}",
                    "bgpAsn": f"{fabric['management']['bgpAsn']}",
                    "anycastGatewayMac": f"{fabric['management']['anycastGatewayMac']}",
                    "replicationMode": f"{fabric['management']['replicationMode']}",
                }
            }
            fabric = FabricModel(**fabric_config_payload)
            self.want.append(fabric)

    def fabric_in_have(self, fabric_name):
        """
        Check and return fabric object if a fabric with the given name exists in the have state.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name} with fabric_name: {fabric_name}"
        self.log.debug(msg)

        # return any(fabric.name == fabric_name for fabric in self.have)
        have_fabric = next((h for h in self.have if h.name == fabric_name), None)
        return have_fabric

class Merged():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, playbook, have_state):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.common = Common(playbook)
        self.common.have = have_state

        self.verb = "POST"
        self.path = "/api/v1/manage/fabrics"

        for fabric in self.common.want:
            want_fabric = fabric
            have_fabric = self.common.fabric_in_have(want_fabric.name)

            if want_fabric == have_fabric:
                # want_fabric and have_fabric are the same, no action needed
                self.log.debug(f"Fabric {want_fabric.name} is already in the desired state, skipping.")
                continue

            if not have_fabric:
                # If the fabric does not exist in the have state, we will create it
                self.path = "/api/v1/manage/fabrics"
                self.verb = "POST"
                payload = copy.deepcopy(want_fabric.model_dump())
            else:
                # If the fabric already exists in the have state, we will update it
                self.path = "/api/v1/manage/fabrics" + f"/{want_fabric.name}"
                self.verb = "PUT"
                payload = self.update_payload_merged(have_fabric, want_fabric)

            # Check if want_fabric is in the last of have fabrics
            # have_fabric = next((h for h in self.common.have if h.name == fabric.name), None)
            self.common.payloads[want_fabric.name] = {'verb': self.verb, 'path': self.path, 'payload': payload}


        msg = "ENTERED Merged(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def _parse_path(self, path):
        """
        Helper function to parse paths from DeepDiff.
        Handles both dot notation and bracket notation.
        """
        # Handle paths like "root.key1.key2"
        if '.' in path and "[" not in path:
            parts = path.split('.')
            if parts[0] == 'root':
                parts = parts[1:]
            return parts

        # Handle paths like "root['key1']['key2']"
        parts = re.findall(r"'([^']*)'", path)
        return parts

    def update_payload_merged(self, have, want):
        """
        Calculate the difference between the have and want states.
        Returns an updated paylod based on those differences.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Use DeepDiff to calculate the difference
        diff = DeepDiff(have, want, ignore_order=True)

        # Create a copy of have as a dictionary
        updated_payload = have.model_dump()

        # If there are no differences, just return the original payload
        # NOTE: I don't think we will ever hit this condition
        if not diff:
            return updated_payload

        # Get want as dictionary for reference
        want_dict = want.model_dump()

        # Update changed values
        if 'values_changed' in diff:
            # Log the values changed for debugging
            self.log.debug(f"Values changed: {diff['values_changed']}")

            for path, change in diff['values_changed'].items():
                parts = self._parse_path(path)

                # Navigate to the correct nested dictionary
                current = updated_payload
                for part in parts[:-1]:
                    current = current[part]

                # Update the value
                current[parts[-1]] = change['new_value']

        # Add new dictionary items
        if 'dictionary_item_added' in diff:
            # Log the dictionary items added for debugging
            self.log.debug(f"Dictionary items added: {diff['dictionary_item_added']}")

            for path in diff['dictionary_item_added']:
                parts = self._parse_path(path)

                # Navigate to the correct nested dictionary
                current = updated_payload
                for i, part in enumerate(parts[:-1]):
                    if part not in current:
                        current[part] = {}
                    current = current[part]

                # Get the value from want
                value = want_dict
                for part in parts:
                    value = value[part]

                # Add the new item
                current[parts[-1]] = value

        return updated_payload

class Replaced():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, playbook, have_state):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.common = Common(playbook)
        self.common.have = have_state

        msg = "ENTERED Replaced(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

class Deleted():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, playbook, have_state):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.common = Common(playbook)
        self.common.have = have_state
        self.verb = "DELETE"
        self.path = "/api/v1/manage/fabrics/{fabric_name}"

        # Create a list of fabric names to be deleted that are in both self.common.want and self.have
        self.delete_fabric_names = [fabric.name for fabric in self.common.want if fabric.name in [h.name for h in self.common.have]]
        # self.delete_fabric_names = [fabric.name for fabric in self.common.want]

        for fabric in self.delete_fabric_names:
            # Create a path for each fabric name to be deleted
            self.common.payloads[fabric] = {'verb': self.verb, 'path': self.path.format(fabric_name=fabric), 'payload': ""}

        msg = "ENTERED Deleted(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

class Query():
    """
    Common methods, properties, and resources for all states.
    """

    def __init__(self, playbook, have_state):
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.common = Common(playbook)
        self.have = have_state

        msg = "ENTERED Query(): "
        msg += f"state: {self.common.state}, "
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
        module.fail_json(str(error))

    nd = NDModule(module)
    playbook = nd.params
    fabrics = GetHave(nd)
    fabrics.refresh()
    fabrics.validate_nd_state()

    try:
        task = None
        if playbook.get("state") == "merged":
            task = Merged(playbook, fabrics.have)
        elif playbook.get("state") == "replaced":
            task = Replaced(playbook, fabrics.have)
        elif playbook.get("state") == "deleted":
            task = Deleted(playbook, fabrics.have)
        elif playbook.get("state") == "query":
            task = Query(playbook, fabrics.have)
        if task is None:
            module.fail_json(f"Invalid state: {playbook['state']}")
    except ValueError as error:
        module.fail_json(f"{error}")

    # create_path = "/api/v1/manage/fabrics"

    # If the task is a query, we will just return the have state
    if isinstance(task, Query):
        task.common.result['have'] = fabrics.have
        module.exit_json(**task.common.result)


    # import epdb ; epdb.serve(port=5555)
    # Process all the payloads from task.common.payloads
    # Sample entry:
    #   {'fabric-ansible': {'verb': 'DELETE', 'path': '/api/v1/manage/fabrics/fabric-ansible', 'payload': ''}
    if task.common.payloads:
        for fabric, request_data in task.common.payloads.items():
            verb = request_data['verb']
            path = request_data['path']
            payload = request_data['payload']

            mainlog.info(f"Calling nd.request with path: {path}, verb: {verb}, and payload: {payload}")
            # Make the API request
            response = nd.request(path, method=verb, data=payload if payload else None)
            task.common.result['response'].append(response)
            task.common.result['changed'] = True
    else:
        mainlog.info("No payloads to process")

    # nd.exit_json()
    module.exit_json(**task.common.result)

if __name__ == "__main__":
    main()