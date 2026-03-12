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
async def test_configure_parses_kafka_config(tmp_path):
    ids = Hamstring()
    ids.configuration_location = str(tmp_path / "config.yaml")
    ids.log_location = str(tmp_path / "logs")
    config_file = tmp_path / "incoming.yaml"
    config = {
        "pipeline": {"alerting": {"external_kafka_topic": "hamstring_alerts"}},
        "environment": {
            "kafka_brokers": [
                {"hostname": "kafka1", "internal_port": 19092},
                {"node_ip": "127.0.0.1", "external_port": 9092},
            ]
        },
    }
    config_file.write_text(yaml.safe_dump(config), encoding="utf-8")

    response = await ids.configure(str(config_file))

    assert response == "succesfully configured"
    assert os.path.isfile(ids.configuration_location)
    assert os.path.isdir(ids.log_location)
    assert ids.kafka_brokers == ["kafka1:19092", "127.0.0.1:9092"]
    assert ids.kafka_topic == "hamstring_alerts"


@pytest.mark.asyncio
async def test_configure_with_existing_log_dir(tmp_path):
    ids = Hamstring()
    ids.configuration_location = str(tmp_path / "config.yaml")
    ids.log_location = str(tmp_path / "logs")
    os.mkdir(ids.log_location)
    config_file = tmp_path / "incoming.yaml"
    config_file.write_text("pipeline: {}", encoding="utf-8")

    await ids.configure(str(config_file))

    assert os.path.isdir(ids.log_location)
    assert ids.kafka_brokers == []
    assert ids.kafka_topic is None


@pytest.mark.asyncio
@patch("shutil.move")
async def test_configure_ruleset(mock_shutil, ids: Hamstring):
    # This method does nothing and only passes
    await ids.configure_ruleset("/path/to/rules.rules")
    assert True


@pytest.mark.asyncio
@patch("src.models.hamstring.execute_command_async", new_callable=AsyncMock)
async def test_execute_network_analysis_command(mock_execute_command, ids: Hamstring):
    mock_execute_command.return_value = 555
    pid = await ids.execute_network_analysis_command()
    mock_execute_command.assert_called_once_with(
        [
            "python3",
            "./src/zeek_wrapper.py",
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
        ]
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
            "./src/zeek_wrapper.py",
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
        ]
    )
    assert pid == 777


@pytest.mark.asyncio
async def test_execute_static_analysis_requires_kafka(ids: Hamstring):
    ids.kafka_brokers = []
    ids.kafka_topic = None
    with pytest.raises(ValueError):
        await ids.execute_static_analysis_command("/path/to/capture.pcap")
