import os
import pytest
import yaml
from unittest.mock import AsyncMock, patch, MagicMock
from src.models.hamstring import Hamstring


@pytest.fixture
def ids():
    ids = Hamstring()
    ids.container_id = 123
    ids.tap_interface_name = "tap123"
    ids.configuration_location = "my/config/location"
    ids.log_location = "my/log/location"
    ids.working_dir = "./"
    ids.kafka_brokers = ["kafka1:19092", "kafka2:19093"]
    ids.kafka_topic = "hamstring_alerts"
    return ids



@pytest.mark.asyncio
@patch("src.models.hamstring.execute_command_async", new_callable=AsyncMock)
async def test_execute_network_analysis_command(mock_execute_command, ids: Hamstring):
    mock_execute_command.return_value = 555
    pid = await ids.execute_network_analysis_command()
    mock_execute_command.assert_called_once_with(
        [
            "python3",
            ids.wrapper_script_path,
            "-m",
            "network",
            "-c",
            ids.configuration_location,
            "-i",
            ids.tap_interface_name,
            "-o",
            ids.log_location,
            "--working-dir",
            ids.working_dir,
            "--kafka-brokers",
            ",".join(ids.kafka_brokers),
            "--kafka-topic",
            ids.kafka_topic,
        ],
        cwd=ids.working_dir,
        suppress_output=False,
        raise_on_error=True,
    )
    assert pid == 555


@pytest.mark.asyncio
async def test_execute_network_analysis_requires_kafka(ids: Hamstring):
    ids.kafka_brokers = []
    ids.kafka_topic = None
    with pytest.raises(ValueError):
        await ids.execute_network_analysis_command()


@pytest.mark.asyncio
@patch("src.models.hamstring.execute_command_async", new_callable=AsyncMock)
async def test_execute_static_analysis_command(mock_execute_command, ids: Hamstring):
    mock_execute_command.return_value = 777
    dataset_path = "/path/to/capture.pcap"
    pid = await ids.execute_static_analysis_command(dataset_path)
    mock_execute_command.assert_called_once_with(
        [
            "python3",
            ids.wrapper_script_path,
            "-m",
            "static",
            "-c",
            ids.configuration_location,
            "-f",
            dataset_path,
            "-o",
            ids.log_location,
            "--working-dir",
            ids.working_dir,
            "--kafka-brokers",
            ",".join(ids.kafka_brokers),
            "--kafka-topic",
            ids.kafka_topic,
        ],
        cwd=ids.working_dir,
        suppress_output=False,
        raise_on_error=True,
    )
    assert pid == 777


@pytest.mark.asyncio
async def test_execute_static_analysis_requires_kafka(ids: Hamstring):
    ids.kafka_brokers = []
    ids.kafka_topic = None
    with pytest.raises(ValueError):
        await ids.execute_static_analysis_command("/path/to/capture.pcap")
