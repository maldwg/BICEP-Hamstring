import pytest

pytest.importorskip("kafka")

from src.zeek_wrapper import _main_async, _wait_for_static_kafka_activity


class FakeKafkaRecord:
    def __init__(self, value: bytes):
        self.value = value


class FakeKafkaConsumer:
    def __init__(self, polls):
        self.polls = list(polls)

    def poll(self, timeout_ms=0):
        if self.polls:
            return self.polls.pop(0)
        return {}


@pytest.mark.asyncio
async def test_main_async_writes_debug_log_when_handler_is_missing(tmp_path):
    config_path = tmp_path / "config.yaml"
    dataset_path = tmp_path / "capture.pcap"
    output_dir = tmp_path / "logs"

    config_path.write_text("pipeline: {}\n", encoding="utf-8")
    dataset_path.write_bytes(b"dummy-pcap")

    exit_code = await _main_async(
        [
            "-m",
            "static",
            "-c",
            str(config_path),
            "-f",
            str(dataset_path),
            "-o",
            str(output_dir),
            "--working-dir",
            str(tmp_path),
            "--zeek-handler",
            "missing_handler.py",
            "--kafka-brokers",
            "127.0.0.1:9092",
            "--kafka-topic",
            "hamstring_alerts",
        ]
    )

    debug_log_path = output_dir / "zeek_wrapper.log"
    assert exit_code == 2
    assert debug_log_path.is_file()
    assert "Zeek handler script does not exist" in debug_log_path.read_text(
        encoding="utf-8"
    )


@pytest.mark.asyncio
async def test_wait_for_static_kafka_activity_ends_after_initial_timeout(tmp_path):
    debug_log_path = tmp_path / "zeek_wrapper.log"
    consumer = FakeKafkaConsumer([{}, {}, {}, {}, {}])

    await _wait_for_static_kafka_activity(
        consumer=consumer,
        kafka_topic="hamstring_alerts",
        initial_wait_seconds=0.05,
        idle_seconds=0.05,
        poll_interval=0.01,
        output_path=None,
        debug_log_path=str(debug_log_path),
    )

    log_text = debug_log_path.read_text(encoding="utf-8")
    assert "no Kafka messages arrived within 0.05 seconds" in log_text


@pytest.mark.asyncio
async def test_wait_for_static_kafka_activity_resets_idle_timer_on_new_messages(tmp_path):
    debug_log_path = tmp_path / "zeek_wrapper.log"
    output_path = tmp_path / "hamstring.json"
    consumer = FakeKafkaConsumer(
        [
            {},
            {
                "topic": [
                    FakeKafkaRecord(b'{"alert":"one"}'),
                ]
            },
            {},
            {
                "topic": [
                    FakeKafkaRecord(b'{"alert":"two"}'),
                ]
            },
            {},
            {},
            {},
            {},
            {},
            {},
        ]
    )

    await _wait_for_static_kafka_activity(
        consumer=consumer,
        kafka_topic="hamstring_alerts",
        initial_wait_seconds=0.05,
        idle_seconds=0.05,
        poll_interval=0.01,
        output_path=str(output_path),
        debug_log_path=str(debug_log_path),
    )

    output_lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    log_text = debug_log_path.read_text(encoding="utf-8")
    assert len(output_lines) == 2
    assert "received the first Kafka message batch" in log_text
    assert "no Kafka messages arrived for 0.05 seconds after the last message" in log_text
