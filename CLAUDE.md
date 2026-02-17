# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains the **Cisco ND (Nexus Dashboard)** Ansible collection (`cisco.nd`, version 1.4.0). It provides modules to manage Cisco Nexus Dashboard infrastructure, including NDI (Nexus Dashboard Insights) compliance, assurance, and site management.

This collection also serves as the **HTTPAPI transport for `cisco.dcnm`** modules when connecting through Nexus Dashboard.

## Common Commands

### Linting and Code Quality

There is no `tox.ini` in this repo. Run linters directly or via the virtual environment:

```bash
# Activate virtual environment (uses uv package manager)
source .venv/bin/activate

# Run linters individually
black -l 159 <file_or_directory>
isort <file>
pylint <file>
mypy <file>

# Check formatting without modifying (as CI does)
black --check --diff --color -l 159 plugins/ tests/

# Markdown linting
markdownlint <file>.md
```

**Line length is 159** (configured in `pyproject.toml` for black, isort, and pylint).

### Testing

```bash
# Run unit tests
python -m pytest tests/unit/

# Run a specific test file
python -m pytest tests/unit/module_utils/test_rest_send.py

# Run with coverage
coverage run -m pytest tests/unit/ && coverage report

# Run sanity tests (requires Docker)
ansible-test sanity --docker

# Build collection
ansible-galaxy collection build
```

Note: Unit tests are currently **disabled in CI** (`if: false` in the workflow). They are run locally only.

### Environment Setup

```bash
source .venv/bin/activate
source env # Repository-specific env vars
```

## Architecture

### Two-Generation Module Infrastructure

This codebase has two coexisting development patterns:

**Generation 1 (Legacy)** - Used by all existing `nd_*` modules:

- `plugins/module_utils/nd.py` - `NDModule` class that uses `Connection` directly, calls `fail_json`/`exit_json`
- `plugins/module_utils/ndi.py` - NDI variant of the above
- Modules: `nd_site`, `nd_backup`, `nd_setup`, `nd_pcv`, all `ndi_*` modules, etc.

**Generation 2 (Active Development)** - New infrastructure on `rest_send_integration` branch:

- `plugins/module_utils/nd_v2.py` - New `NDModule` class using `RestSend`, raises `NDModuleError` instead of `fail_json`
- `plugins/module_utils/rest_send.py` - HTTP orchestration with retry, check_mode support
- `plugins/module_utils/sender_nd.py` - Production `Sender` implementing `SenderProtocol`
- `plugins/module_utils/response_handler_nd.py` - `ResponseHandler` implementing `ResponseHandlerProtocol`
- `plugins/module_utils/results.py` - Pydantic-based `Results` with three-model lifecycle (CurrentTaskData -> TaskResultData -> FinalResultData)
- `plugins/module_utils/enums.py` - `HttpVerbEnum` (GET/POST/PUT/DELETE/PATCH), `OperationType`
- `plugins/module_utils/protocol_sender.py` / `protocol_response_handler.py` - `@runtime_checkable` Protocol classes

### Smart Endpoint Layer (`plugins/module_utils/ep/`)

Pydantic-based endpoint models that bundle URL path + HTTP verb:

- `ep/base_path.py` - Root API constants (`ND_INFRA_API`, `ND_MANAGE_API`, `NDFC_API`, etc.)
- `ep/base_paths_infra.py`, `ep/base_paths_manage.py` - `BasePath` classes per API prefix
- `ep/endpoint_mixins.py` - Pydantic mixins for path segments (`LoginIdMixin`, `FabricNameMixin`, `SwitchSerialNumberMixin`, etc.)
- `ep/query_params.py` - Query parameter models with camelCase conversion and URL encoding
- `ep/ep_api_v1_infra_*.py`, `ep/ep_api_v1_manage_*.py` - Concrete endpoint definitions

```python
# Usage pattern
ep = EpApiV1InfraAaaLocalUsersGet()
ep.login_id = "admin"
rest_send.path = ep.path    # "/api/v1/infra/aaa/localUsers/admin"
rest_send.verb = ep.verb    # HttpVerbEnum.GET
```

### HttpAPI Plugin (`plugins/httpapi/nd.py`)

Transport layer for Ansible's connection framework. Key compatibility features:

- `login()` / `logout()` - Bearer token + AuthCookie auth
- `send_request()` - JSON requests
- `send_file_request()` - Multipart uploads via `requests_toolbelt`
- **DCNM compatibility methods**: `get_version(platform="ndfc")`, `get_token()`, `get_url_connection()`, `send_txt_request()` - required for `cisco.dcnm` modules to work through ND

### Response Format Convention

All responses throughout the codebase use this dict structure:

```python
{
    "RETURN_CODE": 200,
    "METHOD": "GET",
    "REQUEST_PATH": "/api/v1/...",
    "MESSAGE": "OK",
    "DATA": {...}
}
```

### Dependency Injection Pattern

`RestSend` accepts injected `SenderProtocol` and `ResponseHandlerProtocol` implementations:

- **Production**: `Sender` from `sender_nd.py` (uses Ansible `Connection`)
- **Testing**: `Sender` from `tests/unit/module_utils/sender_file.py` (reads from `ResponseGenerator`)

### Pydantic with Fallback

All Pydantic imports go through `plugins/module_utils/pydantic_compat.py`, which provides complete fallback shims when Pydantic is unavailable (needed for `ansible-test sanity` which runs in a minimal environment).

## Development Guidelines

### Code Standards

- Line length: **159 characters** (not 160)
- Black formatting, isort imports, pylint, mypy with Pydantic plugin
- Python >= 3.11 required
- Pydantic v2 models preferred for new code
- `HttpVerbEnum` for HTTP methods (this collection has the enum implemented, unlike `cisco.dcnm`)

### Class and Method Docstrings

All docstrings MUST use Markdown formatting:

```python
def some_method(self, value: str) -> None:
    """
    # Summary

    Do something with the provided value.

    ## Raises

    - `ValueError` if value is empty or None
    - `TypeError` if value is not a string
    """
```

- Use `# Summary` as top-level heading
- `## Raises` is required (use "None" if no exceptions)
- Use single backticks for inline code references

### Unit Test Patterns

**Standard pylint directives** for test files:

```python
# pylint: disable=unused-import
# pylint: disable=redefined-outer-name
# pylint: disable=protected-access
# pylint: disable=unused-argument
# pylint: disable=unused-variable
# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=too-many-lines
```

**Test setup pattern:**

```python
method_name = inspect.stack()[0][3]
key = f"{method_name}a"

def responses():
    yield responses_rest_send(f"{key}")

gen_responses = ResponseGenerator(responses())

sender = Sender()
sender.ansible_module = MockAnsibleModule()
sender.gen = gen_responses

rest_send = RestSend(params)
rest_send.unit_test = True
rest_send.timeout = 1
rest_send.response_handler = ResponseHandler()
rest_send.sender = sender
```

**Fixture key convention**: `test_<module>_<NNNNNa>` where `a` suffix is appended. Each test gets unique fixture data.

**Variable naming**: Never use `_` as a variable name (pylint `disallowed-name`). Use `result` instead.

### Fixture File Structure

```json
{
    "TEST_NOTES": ["Description of fixture file"],
    "test_rest_send_00070a": {
        "TEST_NOTES": ["Notes for this test"],
        "RETURN_CODE": 200,
        "METHOD": "GET",
        "REQUEST_PATH": "/api/endpoint",
        "MESSAGE": "OK",
        "DATA": {}
    }
}
```

## Key File Locations

- **Modules**: `plugins/modules/nd_*.py`
- **Legacy module utils**: `plugins/module_utils/nd.py`, `ndi.py`
- **New module utils**: `plugins/module_utils/nd_v2.py`, `rest_send.py`, `results.py`, `enums.py`
- **Endpoints**: `plugins/module_utils/ep/`
- **HttpAPI plugin**: `plugins/httpapi/nd.py`
- **Test infrastructure**: `tests/unit/module_utils/common_utils.py`, `mock_ansible_module.py`, `response_generator.py`, `sender_file.py`
- **Test fixtures**: `tests/unit/module_utils/fixtures/fixture_data/`
- **CI workflow**: `.github/workflows/ansible-test.yml`

## Collection Info

- **Namespace**: `cisco.nd`
- **Version**: 1.4.0
- **Repository**: https://github.com/CiscoDevNet/ansible-nd
- **Ansible requirement**: >= 2.16
- **Python requirement**: >= 3.11
- **Dependency**: `ansible.netcommon >= 2.6.1`
