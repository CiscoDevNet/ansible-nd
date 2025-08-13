from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Mike Wiebe"

# This try-except block is used to handle the import of Pydantic.
# If Pydantic is not available, it will define a minimal BaseModel class
# and related functions to ensure compatibility with existing code.
#
# This is used to satisfy the ansible sanity test requirements
try:
    from pydantic import BaseModel
except ImportError as imp_exc:
    PYDANTIC_IMPORT_ERROR = imp_exc

    # If Pydantic is not available, define a minimal BaseModel and related functions
    # Reference: https://docs.ansible.com/ansible-core/2.17/dev_guide/testing/sanity/import.html
    class BaseModel:
        pass

    def ConfigDict(*args, **kwargs):
        return dict(*args, **kwargs)

else:
    PYDANTIC_IMPORT_ERROR = None


def merge_models(have_model, want_model):
    """
    Recursively merge two Pydantic models, preferring values from want_model when present.

    This utility function combines two Pydantic model instances by taking values from the
    want_model when they are not None, otherwise preserving values from have_model.
    It handles nested Pydantic models by recursively applying the same merge logic.

    Args:
        have_model (BaseModel): The current/existing Pydantic model instance
        want_model (BaseModel): The desired Pydantic model instance with new values

    Returns:
        dict: A dictionary suitable for API payloads containing the merged configuration

    Raises:
        ValueError: If either argument is not a Pydantic model instance

    Example:
        >>> have_fabric = FabricModel(name="test", category="fabric")
        >>> want_fabric = FabricModel(name="test", category="updated")
        >>> merged = merge_models(have_fabric, want_fabric)
        >>> # Result: {"name": "test", "category": "updated", ...}
    """
    # from pydantic import BaseModel

    if not isinstance(have_model, BaseModel) or not isinstance(want_model, BaseModel):
        raise ValueError("Both arguments must be Pydantic models.")
    model_cls = type(have_model)
    result = {}
    for field in model_cls.model_fields:
        have_value = getattr(have_model, field)
        new_value = getattr(want_model, field, None)
        # If the field is itself a Pydantic model, recurse
        if isinstance(have_value, BaseModel) and isinstance(new_value, BaseModel):
            result[field] = merge_models(have_value, new_value)
        else:
            # Use new_value if not None, else have_value
            result[field] = new_value if new_value is not None else have_value
    return result


def model_payload_with_defaults(want_model):
    """
    Build a payload dict from a Pydantic model, using set fields or default values if not set.

    This utility function creates a dictionary representation of a Pydantic model by using
    the actual field values when they are set, or falling back to the model's default values
    when fields are not explicitly provided. It handles nested Pydantic models recursively.

    Args:
        want_model (BaseModel): The Pydantic model instance to convert to a payload dict

    Returns:
        dict: A dictionary containing all model fields with their values or defaults,
              suitable for API payloads

    Example:
        >>> fabric = FabricModel(name="test")  # Other fields use defaults
        >>> payload = model_payload_with_defaults(fabric)
        >>> # Result: {"name": "test", "category": "fabric", "securityDomain": "all", ...}

    Note:
        This function ensures that all required fields have values by using model defaults,
        making it suitable for 'replaced' and 'overridden' operations where complete
        configuration is needed.
    """
    # from pydantic import BaseModel

    model_cls = type(want_model)
    result = {}
    for field, field_info in model_cls.model_fields.items():
        value = getattr(want_model, field, None)
        default_value = field_info.default
        # If the field is itself a Pydantic model, recurse
        if isinstance(field_info.annotation, type) and issubclass(field_info.annotation, BaseModel):
            if isinstance(value, BaseModel):
                result[field] = model_payload_with_defaults(value)
            else:
                result[field] = model_payload_with_defaults(field_info.default)
        else:
            result[field] = value if value is not None else default_value
    return result
