import argparse
import asyncio
import json
import os
import sys
from typing import List, Optional

from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable


DEFAULT_ZEEK_HANDLER = "./zeek/zeek_handler.py"
ANALYSIS_MODES = ("static", "network")
DEFAULT_KAFKA_IDLE_SECONDS = 10.0
DEFAULT_KAFKA_POLL_INTERVAL = 1.0


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Zeek analysis (network or static) via zeek_handler.py",
    )
    parser.add_argument(
        "-m",
        "--mode",
        required=True,
        choices=list(ANALYSIS_MODES),
        help="Analysis mode: static or network",
    )
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to the configuration file",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Interface to listen on (network mode)",
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Path to the static dataset (static mode)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output/log directory to pass to the handler",
    )
    parser.add_argument(
        "--working-dir",
        help="Working directory to execute the Zeek handler from",
    )
    parser.add_argument(
        "--zeek-handler",
        default=DEFAULT_ZEEK_HANDLER,
        help="Path to the zeek_handler.py script",
    )
    parser.add_argument(
        "--kafka-brokers",
        help="Comma-separated list of Kafka brokers (host:port)",
    )
    parser.add_argument(
        "--kafka-topic",
        help="Kafka topic name to poll",
    )
    parser.add_argument(
        "--kafka-idle-seconds",
        type=float,
        default=DEFAULT_KAFKA_IDLE_SECONDS,
        help="Idle time after process completion before exiting (static mode)",
    )
    parser.add_argument(
        "--kafka-poll-interval",
        type=float,
        default=DEFAULT_KAFKA_POLL_INTERVAL,
        help="Polling interval in seconds",
    )

    args = parser.parse_args(argv)

    if args.mode == "network" and not args.interface:
        parser.error("--interface is required for network mode")
    if args.mode == "static" and not args.file:
        parser.error("--file is required for static mode")

    return args


def _build_command(args: argparse.Namespace) -> List[str]:
    command = [
        "python3",
        args.zeek_handler,
        "-c",
        args.config,
    ]

    if args.output:
        command.extend(["-o", args.output])

    if args.mode == "network":
        command.extend(["-i", args.interface])
    else:
        command.extend(["-f", args.file])

    return command


def _parse_kafka_brokers(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


async def _append_json_line(path: str, payload: str) -> None:
    def _write() -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            try:
                parsed = json.loads(payload)
                json.dump(parsed, handle)
                handle.write("\n")
            except json.JSONDecodeError:
                json.dump({"raw": payload}, handle)
                handle.write("\n")

    await asyncio.to_thread(_write)


async def _run_with_kafka(
    command: List[str],
    working_dir: Optional[str],
    kafka_brokers: List[str],
    kafka_topic: str,
    mode: str,
    idle_seconds: float,
    poll_interval: float,
    output_path: Optional[str],
) -> int:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=working_dir,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        stdin=asyncio.subprocess.DEVNULL,
    )

    consumer = KafkaConsumer(
        kafka_topic,
        bootstrap_servers=kafka_brokers,
        auto_offset_reset="latest",
        enable_auto_commit=False,
        group_id=None,
    )

    loop = asyncio.get_running_loop()
    last_message_time = loop.time()
    process_finished_time: Optional[float] = None
    process_wait_task = asyncio.create_task(process.wait())

    try:
        while True:
            records = consumer.poll(timeout_ms=0)
            if records:
                last_message_time = loop.time()
                if output_path:
                    for _, batch in records.items():
                        for record in batch:
                            try:
                                payload = record.value.decode("utf-8")
                            except Exception:
                                payload = str(record.value)
                            await _append_json_line(output_path, payload)

            if process_wait_task.done() and process_finished_time is None:
                process_finished_time = loop.time()

            if mode == "network":
                if process_wait_task.done():
                    return process_wait_task.result()
            else:
                if process_finished_time is not None:
                    last_activity = max(last_message_time, process_finished_time)
                    if loop.time() - last_activity >= idle_seconds:
                        return process_wait_task.result()

            await asyncio.sleep(poll_interval)
    finally:
        consumer.close()


async def _main_async(argv: List[str]) -> int:
    args = _parse_args(argv)

    working_dir = args.working_dir
    if working_dir and not os.path.isdir(working_dir):
        print(f"Working directory does not exist: {working_dir}", file=sys.stderr)
        return 2

    command = _build_command(args)
    kafka_brokers = _parse_kafka_brokers(args.kafka_brokers)
    if not kafka_brokers or not args.kafka_topic:
        print("Kafka brokers/topic missing. Pass --kafka-brokers and --kafka-topic.", file=sys.stderr)
        return 2
    output_path = None
    if args.output:
        output_path = os.path.join(args.output, "hamstring.json")

    try:
        return await _run_with_kafka(
            command=command,
            working_dir=working_dir,
            kafka_brokers=kafka_brokers,
            kafka_topic=args.kafka_topic,
            mode=args.mode,
            idle_seconds=max(args.kafka_idle_seconds, 0.0),
            poll_interval=max(args.kafka_poll_interval, 0.1),
            output_path=output_path,
        )
    except NoBrokersAvailable:
        print("Kafka brokers not available.", file=sys.stderr)
        return 3


def main() -> int:
    try:
        return asyncio.run(_main_async(sys.argv[1:]))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
