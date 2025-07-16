import pytest
import logging
from unittest.mock import Mock, MagicMock, patch
from ansible_collections.cisco.nd.plugins.modules.manage.fabric import GetHave
from ansible_collections.cisco.nd.plugins.module_utils.manage.fabric.model_playbook_fabric import (
    FabricModel,
)


class TestGetHave:
    """
    Test suite for the GetHave class that handles fabric state retrieval and validation.
    This test class provides comprehensive coverage for the GetHave functionality, including:
    - Initialization with and without custom loggers
    - API interaction for fabric state refresh
    - Fabric data validation and model creation
    - Error handling for various failure scenarios
    - Complete workflow integration testing
    The tests use mocked dependencies to isolate the GetHave class behavior and verify
    proper interaction with the ND API, logging system, and FabricModel instances.
    Fixtures:
        mock_nd: Mock ND module instance for API interactions
        mock_logger: Mock logger instance for testing logging behavior
        sample_fabric_state: Sample fabric data structure for testing
    Test Categories:
        - Initialization tests: Verify proper setup with/without logger
        - Refresh tests: Test API calls and response handling
        - Validation tests: Test fabric data processing and model creation
        - Error handling tests: Test exception scenarios and edge cases
        - Integration tests: Test complete workflows and parametrized scenarios

    To Run Tests:
        # Run all tests for this module
        pytest tests/unit/modules/manage/fabric/test_get_have.py -v

        # Run with coverage
        pytest tests/unit/modules/manage/fabric/test_get_have.py --cov=ansible_collections.cisco.nd.plugins.modules.manage.fabric --cov-report=html

        # Run specific test
        pytest tests/unit/modules/manage/fabric/test_get_have.py::TestGetHave::test_refresh_success -v
    """

    @pytest.fixture
    def mock_nd(self):
        """Create a mock ND module instance."""
        nd_mock = Mock()
        nd_mock.request = Mock()
        return nd_mock

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger instance."""
        logger = Mock(spec=logging.Logger)
        return logger

    @pytest.fixture
    def sample_fabric_state(self):
        """Sample fabric state data from API response."""
        return {
            "fabrics": [
                {
                    "name": "test-fabric-1",
                    "category": "VXLAN",
                    "securityDomain": "default",
                    "management": {
                        "type": "vxlan",
                        "bgpAsn": "65001",
                        "anycastGatewayMac": "00:00:00:00:00:01",
                        "replicationMode": "multicast",
                    },
                },
                {
                    "name": "test-fabric-2",
                    "category": "BGP",
                    "securityDomain": "production",
                    "management": {
                        "type": "bgp",
                        "bgpAsn": "65002",
                        "anycastGatewayMac": "00:00:00:00:00:02",
                        "replicationMode": "ingress",
                    },
                },
            ]
        }

    def test_init_with_logger(self, mock_nd, mock_logger):
        """Test GetHave initialization with provided logger."""
        get_have = GetHave(mock_nd, logger=mock_logger)

        assert get_have.class_name == "GetHave"
        assert get_have.log == mock_logger
        assert get_have.path == "/api/v1/manage/fabrics"
        assert get_have.verb == "GET"
        assert get_have.fabric_state == {}
        assert get_have.have == []
        assert get_have.nd == mock_nd

        mock_logger.debug.assert_called_once()

    def test_init_without_logger(self, mock_nd):
        """Test GetHave initialization without provided logger."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger

            get_have = GetHave(mock_nd)

            assert get_have.class_name == "GetHave"
            assert get_have.log == mock_logger
            assert get_have.path == "/api/v1/manage/fabrics"
            assert get_have.verb == "GET"
            assert get_have.fabric_state == {}
            assert get_have.have == []
            assert get_have.nd == mock_nd

            mock_get_logger.assert_called_once_with("nd.GetHave")
            mock_logger.debug.assert_called_once()

    def test_refresh_success(self, mock_nd, mock_logger, sample_fabric_state):
        """Test successful refresh method."""
        mock_nd.request.return_value = sample_fabric_state

        get_have = GetHave(mock_nd, logger=mock_logger)
        get_have.refresh()

        assert get_have.fabric_state == sample_fabric_state
        mock_nd.request.assert_called_once_with("/api/v1/manage/fabrics", method="GET")
        assert mock_logger.debug.call_count == 2  # Init + refresh

    def test_refresh_empty_response(self, mock_nd, mock_logger):
        """Test refresh method with empty response."""
        empty_response = {"fabrics": []}
        mock_nd.request.return_value = empty_response

        get_have = GetHave(mock_nd, logger=mock_logger)
        get_have.refresh()

        assert get_have.fabric_state == empty_response
        mock_nd.request.assert_called_once_with("/api/v1/manage/fabrics", method="GET")

    def test_refresh_api_error(self, mock_nd, mock_logger):
        """Test refresh method when API raises an exception."""
        mock_nd.request.side_effect = Exception("API connection failed")

        get_have = GetHave(mock_nd, logger=mock_logger)

        with pytest.raises(Exception, match="API connection failed"):
            get_have.refresh()

    @patch("ansible_collections.cisco.nd.plugins.modules.manage.fabric.FabricModel")
    def test_validate_nd_state_success(
        self, mock_fabric_model, mock_nd, mock_logger, sample_fabric_state
    ):
        """Test successful validate_nd_state method."""
        # Setup mock FabricModel instances
        fabric1_mock = Mock()
        fabric2_mock = Mock()
        mock_fabric_model.side_effect = [fabric1_mock, fabric2_mock]

        get_have = GetHave(mock_nd, logger=mock_logger)
        get_have.fabric_state = sample_fabric_state
        get_have.validate_nd_state()

        # Verify FabricModel was called for each fabric
        assert mock_fabric_model.call_count == 2
        mock_fabric_model.assert_any_call(**sample_fabric_state["fabrics"][0])
        mock_fabric_model.assert_any_call(**sample_fabric_state["fabrics"][1])

        # Verify fabrics were added to have list
        assert len(get_have.have) == 2
        assert get_have.have[0] == fabric1_mock
        assert get_have.have[1] == fabric2_mock

        assert mock_logger.debug.call_count == 2  # Init + validate

    def test_validate_nd_state_empty_fabrics(self, mock_nd, mock_logger):
        """Test validate_nd_state with empty fabrics list."""
        empty_state = {"fabrics": []}

        get_have = GetHave(mock_nd, logger=mock_logger)
        get_have.fabric_state = empty_state
        get_have.validate_nd_state()

        assert get_have.have == []
        assert mock_logger.debug.call_count == 2

    def test_validate_nd_state_invalid_fabric_data(self, mock_nd, mock_logger):
        """Test validate_nd_state with invalid fabric data."""
        invalid_state = {"fabrics": ["not_a_dict", 123]}

        get_have = GetHave(mock_nd, logger=mock_logger)
        get_have.fabric_state = invalid_state

        with pytest.raises(ValueError, match="Fabric data is not a dictionary"):
            get_have.validate_nd_state()

    @patch("ansible_collections.cisco.nd.plugins.modules.manage.fabric.FabricModel")
    def test_validate_nd_state_fabric_model_error(
        self, mock_fabric_model, mock_nd, mock_logger, sample_fabric_state
    ):
        """Test validate_nd_state when FabricModel raises an exception."""
        mock_fabric_model.side_effect = ValueError("Invalid fabric configuration")

        get_have = GetHave(mock_nd, logger=mock_logger)
        get_have.fabric_state = sample_fabric_state

        with pytest.raises(ValueError, match="Invalid fabric configuration"):
            get_have.validate_nd_state()

    def test_validate_nd_state_missing_fabrics_key(self, mock_nd, mock_logger):
        """Test validate_nd_state when fabric_state doesn't have 'fabrics' key."""
        invalid_state = {"data": []}

        get_have = GetHave(mock_nd, logger=mock_logger)
        get_have.fabric_state = invalid_state

        with pytest.raises(TypeError):
            get_have.validate_nd_state()

    def test_full_workflow(self, mock_nd, mock_logger, sample_fabric_state):
        """Test complete workflow: init -> refresh -> validate."""
        with patch(
            "ansible_collections.cisco.nd.plugins.modules.manage.fabric.FabricModel"
        ) as mock_fabric_model:
            # Setup
            mock_nd.request.return_value = sample_fabric_state
            fabric1_mock = Mock()
            fabric2_mock = Mock()
            mock_fabric_model.side_effect = [fabric1_mock, fabric2_mock]

            # Execute full workflow
            get_have = GetHave(mock_nd, logger=mock_logger)
            get_have.refresh()
            get_have.validate_nd_state()

            # Verify final state
            assert get_have.fabric_state == sample_fabric_state
            assert len(get_have.have) == 2
            assert get_have.have[0] == fabric1_mock
            assert get_have.have[1] == fabric2_mock

            # Verify API was called correctly
            mock_nd.request.assert_called_once_with(
                "/api/v1/manage/fabrics", method="GET"
            )

            # Verify logging calls
            assert mock_logger.debug.call_count == 3  # Init + refresh + validate

    def test_class_attributes_immutable(self, mock_nd, mock_logger):
        """Test that class attributes are set correctly and don't change unexpectedly."""
        get_have = GetHave(mock_nd, logger=mock_logger)

        # Store original values
        original_path = get_have.path
        original_verb = get_have.verb
        original_class_name = get_have.class_name

        # Attempt to modify (shouldn't affect the object's behavior)
        get_have.path = "/modified/path"
        get_have.verb = "POST"

        # Verify changes took effect (Python allows this)
        assert get_have.path == "/modified/path"
        assert get_have.verb == "POST"
        assert get_have.class_name == original_class_name  # This shouldn't change

    @pytest.mark.parametrize("fabric_count", [0, 1, 5, 10])
    def test_validate_nd_state_various_fabric_counts(
        self, mock_nd, mock_logger, fabric_count
    ):
        """Test validate_nd_state with various numbers of fabrics."""
        with patch(
            "ansible_collections.cisco.nd.plugins.modules.manage.fabric.FabricModel"
        ) as mock_fabric_model:
            # Create fabric data
            fabrics = []
            mock_instances = []
            for i in range(fabric_count):
                fabric = {
                    "name": f"fabric-{i}",
                    "category": "VXLAN",
                    "securityDomain": "default",
                    "management": {
                        "type": "vxlan",
                        "bgpAsn": f"6500{i}",
                        "anycastGatewayMac": f"00:00:00:00:00:0{i}",
                        "replicationMode": "multicast",
                    },
                }
                fabrics.append(fabric)
                mock_instances.append(Mock())

            mock_fabric_model.side_effect = mock_instances
            fabric_state = {"fabrics": fabrics}

            get_have = GetHave(mock_nd, logger=mock_logger)
            get_have.fabric_state = fabric_state
            get_have.validate_nd_state()

            assert len(get_have.have) == fabric_count
            assert mock_fabric_model.call_count == fabric_count
