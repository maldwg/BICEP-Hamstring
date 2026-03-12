import asyncio
from src.utils.models.ids_base import IDSBase
import shutil
import os
import yaml
from typing import Optional
from src.utils.general_utilities import execute_command_async
from .hamstring_parser import HamstringParser
from concurrent.futures import ProcessPoolExecutor
import subprocess


class Hamstring(IDSBase):
    configuration_location: str = "/app/configuration.yaml"
    # the interface to listen on in network analysis modes
    log_location: str = "/opt/logs"

    # unqiue variables
    working_dir = "/opt/src"
    parser = HamstringParser()
    parser.alert_file_location = f"{log_location}/hamstring.json"
    kafka_brokers: list[str] = []
    kafka_topic: Optional[str] = None

    async def configure(self, temporary_file):
        """
            Configuring a CIDS is not necessary as this involves a complete restart of all components anyways.
        """
        shutil.move(temporary_file, self.configuration_location)
        if not os.path.isdir(self.log_location):
            os.mkdir(self.log_location)

        try:
            with open(self.configuration_location, "r", encoding="utf-8") as config_file:
                config = yaml.safe_load(config_file) or {}
        except FileNotFoundError:
            config = {}

        kafka_brokers = []
        for broker in config.get("environment", {}).get("kafka_brokers", []):
            host = broker.get("hostname") or broker.get("node_ip")
            port = broker.get("internal_port") or broker.get("external_port")
            if host and port:
                kafka_brokers.append(f"{host}:{port}")

        self.kafka_brokers = kafka_brokers
        self.kafka_topic = (
            config.get("pipeline", {})
            .get("alerting", {})
            .get("external_kafka_topic")
        )

        return "succesfully configured"
  

    async def configure_ruleset(self, temporary_file):
        """
            No ruleset configuration is necessary for Hamstring as CIDS will be restarted after configuration changes occured.
        """
        pass

    async def execute_network_analysis_command(self):
        if not self.kafka_brokers or not self.kafka_topic:
            raise ValueError("Kafka configuration missing; run configure() first.")
        wrapper_path = os.path.join(self.working_dir, "src", "zeek_wrapper.py")
        command = [
            "python3",
            wrapper_path,
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
        command.extend(["--kafka-brokers", ",".join(self.kafka_brokers)])
        command.extend(["--kafka-topic", self.kafka_topic])
        pid = await execute_command_async(command)
        return pid

    async def execute_static_analysis_command(self, file_path):
        if not self.kafka_brokers or not self.kafka_topic:
            raise ValueError("Kafka configuration missing; run configure() first.")
        wrapper_path = os.path.join(self.working_dir, "src", "zeek_wrapper.py")
        command = [
            "python3",
            wrapper_path,
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
        command.extend(["--kafka-brokers", ",".join(self.kafka_brokers)])
        command.extend(["--kafka-topic", self.kafka_topic])
        pid = await execute_command_async(command)
        return pid
