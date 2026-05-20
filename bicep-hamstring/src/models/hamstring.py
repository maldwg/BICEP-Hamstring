import os
from typing import Optional

import yaml

from src.utils.general_utilities import execute_command_async
from src.utils.general_utilities import LOGGER
from src.utils.models.ids_base import IDSBase

from .hamstring_parser import HamstringParser


class Hamstring(IDSBase):
    configuration_location: str = os.getenv(
        "CONFIGURATION_DEFAULT_LOCATION", "/app/config.yaml"
    )
    # the interface to listen on in network analysis modes
    log_location: str = "/opt/logs"

    # unique variables
    wrapper_script_path = "/opt/code/src/zeek_wrapper.py"
    hamstring_zeek_binary_path = os.getenv(
        "HAMSTRING_ZEEK_BINARY", "/opt/hamstring_zeek"
    )
    working_dir = "/opt"
    parser = HamstringParser()
    parser.alert_file_location = f"{log_location}/hamstring.json"
    kafka_brokers: list[str] = []
    kafka_topic: Optional[str] = None

    def __init__(self):
        super().__init__()

        if not os.path.isdir(self.log_location):
            os.mkdir(self.log_location)

        try:
            with open(self.configuration_location, "r", encoding="utf-8") as config_file:
                config = yaml.safe_load(config_file) or {}
        except FileNotFoundError as e:
            LOGGER.debug(
                f"Configuration file not found during startup: {self.configuration_location}"
            )
            config = {}
        kafka_brokers = []
        for broker in config.get("environment", {}).get("kafka_brokers", []):
            host = broker.get("node_ip")
            port = broker.get("external_port")
            if host and port:
                kafka_brokers.append(f"{host}:{port}")
        self.kafka_brokers = kafka_brokers
        LOGGER.debug(f"Brokers: {self.kafka_brokers}")
        self.kafka_topic = (
            config.get("pipeline", {})
            .get("alerting", {})
            .get("external_kafka_topic")
        )
        LOGGER.debug(f"Kafka Poll Topic: {self.kafka_topic}")

    async def configure(self, temporary_file):
        """
            Configuring a CIDS is not necessary as this involves a complete restart of all components anyways.
            As the config is injected initially via docker compose, just use the init method.
        """
 
        return "successfully configured"


    async def configure_ruleset(self, temporary_file):
        """
            No ruleset configuration is necessary for Hamstring as CIDS will be restarted after configuration changes occured.
        """
        pass

    async def execute_network_analysis_command(self):
        if not self.kafka_brokers or not self.kafka_topic:
            raise ValueError("Kafka configuration missing; run configure() first.")
        command = [
            "python3",
            self.wrapper_script_path,
            "-m",
            "network",
            "-c",
            self.configuration_location,
            "-i",
            self.tap_interface_name,
        ]
        if self.log_location:
            command.extend(["-o", self.log_location])
        command.extend(["--working-dir", self.working_dir])
        command.extend(["--hamstring-zeek-bin", self.hamstring_zeek_binary_path])
        command.extend(["--kafka-brokers", ",".join(self.kafka_brokers)])
        command.extend(["--kafka-topic", self.kafka_topic])
        pid = await execute_command_async(
            command,
            cwd=self.working_dir,
            suppress_output=False,
            raise_on_error=True,
        )
        return pid

    async def execute_static_analysis_command(self, file_path):
        if not self.kafka_brokers or not self.kafka_topic:
            raise ValueError("Kafka configuration missing; run configure() first.")
        command = [
            "python3",
            self.wrapper_script_path,
            "-m",
            "static",
            "-c",
            self.configuration_location,
            "-f",
            file_path,
        ]
        if self.log_location:
            command.extend(["-o", self.log_location])
        command.extend(["--working-dir", self.working_dir])
        command.extend(["--hamstring-zeek-bin", self.hamstring_zeek_binary_path])
        command.extend(["--kafka-brokers", ",".join(self.kafka_brokers)])
        command.extend(["--kafka-topic", self.kafka_topic])
        pid = await execute_command_async(
            command,
            cwd=self.working_dir,
            suppress_output=False,
            raise_on_error=True,
        )
        return pid
