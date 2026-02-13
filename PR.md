# PR: RestSend framework with Smart Endpoints and unit tests

## Summary

Introduces the RestSend framework for the ND collection, including Smart Endpoints for REST API path construction, response handling, Pydantic compatibility, logging infrastructure, and comprehensive unit test coverage.

## Changes

### Core REST framework

- **rest_send.py** - `RestSend` class for sending REST requests with retry logic, check mode support, and configurable timeout/send_interval
- **sender_nd.py** - `Sender` class implementing `SenderProtocol` for sending requests via the Ansible HttpApi plugin, with response normalization for non-JSON responses
- **response_handler_nd.py** - `ResponseHandler` class implementing `ResponseHandlerProtocol` for parsing ND controller responses, including GET (found/success) vs POST/PUT/DELETE (changed/success) handling and extraction of 7 ND error message formats
- **protocol_sender.py** / **protocol_response_handler.py** - Runtime-checkable Protocol definitions for dependency injection
- **results.py** - `Results` class for aggregating task results across multiple REST operations

### Smart Endpoints (plugins/module_utils/ep/)

- **base_path.py** - Base class for API path construction
- **base_paths_infra.py** / **base_paths_manage.py** - Base paths for `/api/v1/infra` and `/api/v1/manage` schema divisions
- **endpoint_mixins.py** - Reusable endpoint mixins for common patterns
- **ep_api_v1_infra_aaa.py** - AAA endpoints (users, sessions, etc.)
- **ep_api_v1_infra_clusterhealth.py** - Cluster health endpoints
- **ep_api_v1_manage_switches.py** - Switch management endpoints
- **query_params.py** - Composable query parameter builders with Lucene search support

### Supporting infrastructure

- **enums.py** - `HttpVerbEnum`, `BooleanStringEnum`, `OperationType` enums
- **log.py** - Logging infrastructure with JSON configuration
- **pydantic_compat.py** - Pydantic v1/v2 compatibility layer
- **nd_v2.py** - Module framework integrating RestSend with Ansible module lifecycle

### Unit tests (79 new tests in this session, 14,208 total lines added)

- **test_response_handler_nd.py** (49 tests) - Isolated tests for `ResponseHandler`:
  - Property validation (response, verb, result setters/getters)
  - `_handle_get_response()` across all status codes (200, 201, 202, 204, 404, 400, 401, 500)
  - `_handle_post_put_delete_response()` with ERROR key, DATA.error, success codes, error codes
  - `error_message` for all 7 ND error formats (raw_response, code/message, messages array, errors array, no DATA, non-dict DATA, unknown fallback)
  - Response routing verification and sequential commit behavior
- **test_sender_nd.py** (30 tests) - Isolated tests for `Sender`:
  - Property validation for all properties (ansible_module, path, verb, payload, response)
  - `_normalize_response()` for normal JSON, non-JSON raw, missing MESSAGE, missing raw
  - `commit()` with mocked Connection for GET/POST/PUT/DELETE, connection reuse, error wrapping
- **test_rest_send.py** (31 tests) - Integration tests for `RestSend` with check mode, retries, sequential commits, error conditions
- **ep/test_*.py** - Tests for all Smart Endpoint classes (base_path, base_paths_infra, base_paths_manage, endpoint_mixins, query_params, and individual endpoints)
- **test_log.py** - Tests for logging infrastructure
- **Test infrastructure**: sender_file.py (mock sender), response_generator.py, mock_ansible_module.py, common_utils.py, fixture loader and JSON fixture data

## Test plan

- [ ] Run unit tests: `PYTHONPATH=<collections_root> python -m pytest tests/unit/`
- [ ] Run linters: `black -l160 --check`, `isort --check-only`, `pylint`
- [ ] Verify existing test_rest_send.py tests still pass alongside new dedicated tests
