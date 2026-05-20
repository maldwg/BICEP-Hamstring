import argparse
import asyncio
import json
import os
import signal
import shlex
import sys
from datetime import datetime
from typing import List, Optional

try:
    from kafka import KafkaConsumer
    from kafka.errors import NoBrokersAvailable
except ImportError:
    KafkaConsumer = None

    class NoBrokersAvailable(Exception):
        pass


DEFAULT_HAMSTRING_ZEEK_BINARY = "/opt/hamstring_zeek"
ANALYSIS_MODES = ("static", "network")
DEFAULT_KAFKA_IDLE_SECONDS = 30.0
DEFAULT_KAFKA_INITIAL_WAIT_SECONDS = 180.0
DEFAULT_KAFKA_POLL_INTERVAL = 2.0
DEFAULT_DEBUG_LOG_PATH = "/tmp/zeek_wrapper.log"


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Hamstring Zeek analysis (network or static) via hamstring_zeek",
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
        help="Working directory to execute hamstring_zeek from",
    )
    parser.add_argument(
        "--hamstring-zeek-bin",
        "--zeek-handler",
        dest="hamstring_zeek_bin",
        default=DEFAULT_HAMSTRING_ZEEK_BINARY,
        help="Path to the hamstring_zeek binary",
    )
    parser.add_argument(
        "--zeek-config-location",
        help="Optional override for the Zeek local.zeek path passed to hamstring_zeek",
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
        help="Idle time after the last Kafka message before exiting (static mode)",
    )
    parser.add_argument(
        "--kafka-initial-wait-seconds",
        type=float,
        default=DEFAULT_KAFKA_INITIAL_WAIT_SECONDS,
        help="Maximum time to wait for the first Kafka message after the static analysis process exits",
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
        args.hamstring_zeek_bin,
        "-c",
        args.config,
    ]
    if args.mode == "network":
        command.extend(["-i", args.interface])
    else:
        command.extend(["-f", args.file])
    if args.zeek_config_location:
        command.extend(["--zeek-config-location", args.zeek_config_location])

    return command


def _parse_kafka_brokers(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _get_debug_log_path(output_dir: Optional[str]) -> str:
    env_path = os.getenv("ZEEK_WRAPPER_DEBUG_LOG")
    if env_path:
        return env_path
    if output_dir:
        return os.path.join(output_dir, "zeek_wrapper.log")
    return DEFAULT_DEBUG_LOG_PATH


def _debug_log(message: str, debug_log_path: str, *, stderr: bool = False) -> None:
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    formatted = f"{timestamp} [zeek_wrapper pid={os.getpid()}] {message}"
    target_stream = sys.stderr if stderr else sys.stdout
    print(formatted, file=target_stream, flush=True)

    try:
        log_dir = os.path.dirname(debug_log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(debug_log_path, "a", encoding="utf-8") as handle:
            handle.write(formatted)
            handle.write("\n")
    except Exception as exc:
        print(
            f"{timestamp} [zeek_wrapper pid={os.getpid()}] Failed to write debug log to "
            f"{debug_log_path}: {exc}",
            file=sys.stderr,
            flush=True,
        )


def _resolve_path(path: Optional[str], base_dir: str) -> Optional[str]:
    if not path:
        return None
    if os.path.isabs(path):
        return path
    return os.path.abspath(os.path.join(base_dir, path))


async def _append_json_line(path: str, payload: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        try:
            parsed = json.loads(payload)
            json.dump(parsed, handle)
            handle.write("\n")
        except json.JSONDecodeError:
            json.dump({"raw": payload}, handle)
            handle.write("\n")


async def _stream_process_output(
    stream: Optional[asyncio.StreamReader],
    label: str,
    debug_log_path: str,
) -> None:
    if stream is None:
        return

    while True:
        line = await stream.readline()
        if not line:
            return
        decoded = line.decode("utf-8", errors="replace").rstrip()
        if decoded:
            _debug_log(f"[hamstring_zeek {label}] {decoded}", debug_log_path, stderr=(label == "stderr"))


async def _consume_kafka_records(
    consumer: KafkaConsumer,
    kafka_topic: str,
    output_path: Optional[str],
    debug_log_path: str,
) -> int:
    records = consumer.poll(timeout_ms=0)
    if not records:
        return 0

    total_records = sum(len(batch) for batch in records.values())
    _debug_log(
        f"Received {total_records} Kafka record(s) from topic {kafka_topic}",
        debug_log_path,
    )

    if output_path:
        for _, batch in records.items():
            for record in batch:
                try:
                    payload = record.value.decode("utf-8")
                except Exception:
                    payload = str(record.value)
                await _append_json_line(output_path, payload)

    return total_records


async def _wait_for_static_kafka_activity(
    consumer: KafkaConsumer,
    kafka_topic: str,
    initial_wait_seconds: float,
    idle_seconds: float,
    poll_interval: float,
    output_path: Optional[str],
    debug_log_path: str,
) -> None:
    loop = asyncio.get_running_loop()
    first_message_deadline = loop.time() + initial_wait_seconds
    _debug_log(
        f"Static mode: waiting up to {initial_wait_seconds} seconds for the first Kafka message.",
        debug_log_path,
    )

    last_message_time: Optional[float] = None

    while loop.time() < first_message_deadline:
        record_count = await _consume_kafka_records(
            consumer=consumer,
            kafka_topic=kafka_topic,
            output_path=output_path,
            debug_log_path=debug_log_path,
        )
        if record_count > 0:
            last_message_time = loop.time()
            _debug_log(
                f"Static mode: received the first Kafka message batch; now waiting for {idle_seconds} seconds of inactivity.",
                debug_log_path,
            )
            break
        await asyncio.sleep(poll_interval)

    if last_message_time is None:
        _debug_log(
            f"Static mode: no Kafka messages arrived within {initial_wait_seconds} seconds after process completion. Ending analysis.",
            debug_log_path,
        )
        return

    while True:
        record_count = await _consume_kafka_records(
            consumer=consumer,
            kafka_topic=kafka_topic,
            output_path=output_path,
            debug_log_path=debug_log_path,
        )
        now = loop.time()
        if record_count > 0:
            last_message_time = now
        elif now - last_message_time >= idle_seconds:
            _debug_log(
                f"Static mode: no Kafka messages arrived for {idle_seconds} seconds after the last message. Ending analysis.",
                debug_log_path,
            )
            return
        await asyncio.sleep(poll_interval)


async def _run_with_kafka(
    command: List[str],
    working_dir: Optional[str],
    kafka_brokers: List[str],
    kafka_topic: str,
    mode: str,
    initial_wait_seconds: float,
    idle_seconds: float,
    poll_interval: float,
    output_path: Optional[str],
    debug_log_path: str,
) -> int:
    if KafkaConsumer is None:
        _debug_log("kafka-python is not installed.", debug_log_path, stderr=True)
        return 3

    _debug_log(
        f"Creating Kafka consumer for topic={kafka_topic} brokers={kafka_brokers}",
        debug_log_path,
    )

    consumer = KafkaConsumer(
        kafka_topic,
        bootstrap_servers=kafka_brokers,
        auto_offset_reset="latest",
        enable_auto_commit=False,
        group_id=None,
    )

    _debug_log(
        f"Launching hamstring_zeek with cwd={working_dir} command={shlex.join(command)}",
        debug_log_path,
    )
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=working_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
    )
    _debug_log(f"Spawned hamstring_zeek pid={process.pid}", debug_log_path)

    loop = asyncio.get_running_loop()
    process_wait_task = asyncio.create_task(process.wait())
    stdout_task = asyncio.create_task(
        _stream_process_output(process.stdout, "stdout", debug_log_path)
    )
    stderr_task = asyncio.create_task(
        _stream_process_output(process.stderr, "stderr", debug_log_path)
    )

    registered_signals: list[signal.Signals] = []

    def _forward_shutdown_signal(received_signal: signal.Signals) -> None:
        _debug_log(
            f"Received {received_signal.name}; forwarding shutdown to hamstring_zeek pid={process.pid}",
            debug_log_path,
        )
        if process.returncode is None:
            process.terminate()

    for handled_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(
                handled_signal,
                _forward_shutdown_signal,
                handled_signal,
            )
            registered_signals.append(handled_signal)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        if mode == "network":
            while True:
                await _consume_kafka_records(
                    consumer=consumer,
                    kafka_topic=kafka_topic,
                    output_path=output_path,
                    debug_log_path=debug_log_path,
                )

                if process_wait_task.done():
                    return_code = process_wait_task.result()
                    _debug_log(
                        f"hamstring_zeek process exited with return code {return_code}",
                        debug_log_path,
                        stderr=return_code != 0,
                    )
                    _debug_log(
                        "Network mode completed because hamstring_zeek exited.",
                        debug_log_path,
                    )
                    return return_code

                await asyncio.sleep(poll_interval)

        _debug_log(
            "Static mode: waiting for hamstring_zeek to finish before checking Kafka inactivity windows.",
            debug_log_path,
        )
        return_code = await process_wait_task
        _debug_log(
            f"hamstring_zeek process exited with return code {return_code}",
            debug_log_path,
            stderr=return_code != 0,
        )
        await _wait_for_static_kafka_activity(
            consumer=consumer,
            kafka_topic=kafka_topic,
            initial_wait_seconds=initial_wait_seconds,
            idle_seconds=idle_seconds,
            poll_interval=poll_interval,
            output_path=output_path,
            debug_log_path=debug_log_path,
        )
        return return_code
    finally:
        for registered_signal in registered_signals:
            loop.remove_signal_handler(registered_signal)
        if process.returncode is None:
            _debug_log(
                f"Stopping hamstring_zeek pid={process.pid} during wrapper cleanup",
                debug_log_path,
            )
            process.terminate()
            try:
                await asyncio.wait_for(process_wait_task, timeout=10)
            except asyncio.TimeoutError:
                _debug_log(
                    f"hamstring_zeek pid={process.pid} did not stop after SIGTERM; killing it",
                    debug_log_path,
                    stderr=True,
                )
                process.kill()
                await process_wait_task
        consumer.close()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)


async def _main_async(argv: List[str]) -> int:
    args = _parse_args(argv)
    debug_log_path = _get_debug_log_path(args.output)
    _debug_log(f"Wrapper invoked with argv={argv}", debug_log_path)
    _debug_log(f"Current process working directory is {os.getcwd()}", debug_log_path)

    working_dir = args.working_dir
    resolved_working_dir = (
        os.path.abspath(working_dir) if working_dir else os.getcwd()
    )
    _debug_log(
        f"Requested working directory={working_dir}, resolved working directory={resolved_working_dir}",
        debug_log_path,
    )
    if working_dir and not os.path.isdir(working_dir):
        _debug_log(
            f"Working directory does not exist: {working_dir}",
            debug_log_path,
            stderr=True,
        )
        return 2

    resolved_binary = _resolve_path(args.hamstring_zeek_bin, resolved_working_dir)
    resolved_config = _resolve_path(args.config, resolved_working_dir)
    resolved_file = _resolve_path(args.file, resolved_working_dir)
    resolved_zeek_config_location = _resolve_path(
        args.zeek_config_location, resolved_working_dir
    )
    _debug_log(f"Resolved hamstring_zeek path: {resolved_binary}", debug_log_path)
    _debug_log(f"Resolved config path: {resolved_config}", debug_log_path)
    if resolved_zeek_config_location:
        _debug_log(
            f"Resolved Zeek config location: {resolved_zeek_config_location}",
            debug_log_path,
        )
    if args.mode == "static":
        _debug_log(f"Resolved dataset path: {resolved_file}", debug_log_path)

    if not resolved_binary or not os.path.isfile(resolved_binary):
        _debug_log(
            f"hamstring_zeek binary does not exist: {resolved_binary}",
            debug_log_path,
            stderr=True,
        )
        return 2

    if not resolved_config or not os.path.isfile(resolved_config):
        _debug_log(
            f"Configuration file does not exist: {resolved_config}",
            debug_log_path,
            stderr=True,
        )
        return 2

    if args.mode == "static" and (not resolved_file or not os.path.isfile(resolved_file)):
        _debug_log(
            f"Static input file does not exist: {resolved_file}",
            debug_log_path,
            stderr=True,
        )
        return 2

    args.hamstring_zeek_bin = resolved_binary
    args.config = resolved_config
    if resolved_file:
        args.file = resolved_file
    if resolved_zeek_config_location:
        args.zeek_config_location = resolved_zeek_config_location

    command = _build_command(args)
    _debug_log(f"Built command: {shlex.join(command)}", debug_log_path)

    kafka_brokers = _parse_kafka_brokers(args.kafka_brokers)
    if not kafka_brokers or not args.kafka_topic:
        _debug_log(
            "Kafka brokers/topic missing. Pass --kafka-brokers and --kafka-topic.",
            debug_log_path,
            stderr=True,
        )
        return 2
    output_path = None
    if args.output:
        output_path = os.path.join(args.output, "hamstring.json")
        _debug_log(f"Kafka output path resolved to {output_path}", debug_log_path)

    try:
        return await _run_with_kafka(
            command=command,
            working_dir=resolved_working_dir,
            kafka_brokers=kafka_brokers,
            kafka_topic=args.kafka_topic,
            mode=args.mode,
            initial_wait_seconds=max(args.kafka_initial_wait_seconds, 0.0),
            idle_seconds=max(args.kafka_idle_seconds, 0.0),
            poll_interval=max(args.kafka_poll_interval, 0.1),
            output_path=output_path,
            debug_log_path=debug_log_path,
        )
    except NoBrokersAvailable:
        _debug_log("Kafka brokers not available.", debug_log_path, stderr=True)
        return 3


def main() -> int:
    try:
        return asyncio.run(_main_async(sys.argv[1:]))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
