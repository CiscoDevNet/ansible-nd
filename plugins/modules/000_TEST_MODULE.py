from ansible_collections.cisco.nd.plugins.module_utils.ep.v1 import EpManageSwitchesGet

# The below raises a validation error because fabric_name
# exceeds the max length of 64 characters defined in the model.

ep = EpManageSwitchesGet()
ep.endpoint_params.fabric_name = "x" * 65


