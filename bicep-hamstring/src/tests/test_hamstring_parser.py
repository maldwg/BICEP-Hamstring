import json
import os
import pytest
from src.models.hamstring_parser import HamstringParser
from src.utils.models.ids_base import Alert


@pytest.fixture
def parser(tmp_path):
    parser = HamstringParser()
    parser.alert_file_location = str(tmp_path / "hamstring.json")
    return parser


def _sample_payload(overall_score=0.73):
    return {
        "overall_score": overall_score,
        "result": [
            {
                "request": {
                    "ts": "2026-03-12T09:51:30.635139",
                    "uid": "CSOuEL39Rhs8MGRcyd",
                    "src_ip": "147.32.84.192",
                    "src_port": 1668,
                    "dns_server_ip": "147.32.80.9",
                    "dns_server_port": 53,
                    "domain_name": "toto.capway.com",
                    "record_type": "A",
                    "rejected": False,
                    "status_code_id": 3,
                    "status_code": "NXDOMAIN",
                    "size": 79,
                    "logline_id": "d1e9822a-9dde-4bae-a4ee-5e3b6a9b787f",
                },
                "probability": overall_score,
                "name": "RF-dga_detector",
                "sha256": "5db8bfb617e80361362c33b1d1afc6d762c28e9fa9275fb11514a3bdef76bb88",
            }
        ],
        "src_ip": "147.32.84.192",
        "alert_timestamp": "2026-03-12T09:51:30.635139",
        "suspicious_batch_id": "49990f07-588a-4390-b94e-2b05244c61f3",
        "detector_name": "RF-dga_detector",
    }


@pytest.mark.asyncio
async def test_parse_alerts_empty_file(parser: HamstringParser):
    alerts = await parser.parse_alerts()
    assert len(alerts) == 0


@pytest.mark.asyncio
async def test_parse_alerts_valid_and_invalid_lines(parser: HamstringParser):
    valid_payload = _sample_payload()
    raw_variant = _sample_payload(0.42)
    raw_variant["result"][0]["request"]["src_port"] = 1669
    raw_payload = {"raw": json.dumps(raw_variant)}
    invalid_json = "not-json"
    invalid_payload = {"raw": "{this is not json}"}

    with open(parser.alert_file_location, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(valid_payload) + "\n")
        handle.write(json.dumps(raw_payload) + "\n")
        handle.write(invalid_json + "\n")
        handle.write(json.dumps(invalid_payload) + "\n")

    alerts = await parser.parse_alerts()

    assert len(alerts) == 2
    assert all(isinstance(alert, Alert) for alert in alerts)

    with open(parser.alert_file_location, "r", encoding="utf-8") as handle:
        assert handle.read() == ""


@pytest.mark.asyncio
async def test_parse_line_maps_fields(parser: HamstringParser):
    payload = _sample_payload()
    alert = await parser.parse_line(payload)

    assert alert.source_ip == "147.32.84.192"
    assert alert.source_port == "1668"
    assert alert.destination_ip == "147.32.80.9"
    assert alert.destination_port == "53"
    assert alert.type == "RF-dga_detector"
    assert alert.severity == 0.73

    message = json.loads(alert.message)
    assert message["domain"] == "toto.capway.com"
    assert message["status_code"] == "NXDOMAIN"
    assert message["record_type"] == "A"
    assert message["batch_id"] == "49990f07-588a-4390-b94e-2b05244c61f3"
    assert message["detector"] == "RF-dga_detector"


@pytest.mark.asyncio
async def test_parse_line_uses_probability_when_missing_overall_score(parser: HamstringParser):
    payload = _sample_payload()
    payload.pop("overall_score", None)
    payload["result"].append({"probability": 0.12, "request": payload["result"][0]["request"]})

    alert = await parser.parse_line(payload)
    assert alert.severity == 0.73


@pytest.mark.asyncio
async def test_parse_line_handles_raw_payload(parser: HamstringParser):
    payload = {"raw": json.dumps(_sample_payload(0.11))}
    alert = await parser.parse_line(payload)
    assert alert.severity == 0.11


@pytest.mark.asyncio
async def test_parse_line_requires_minimum_fields(parser: HamstringParser):
    payload = _sample_payload()
    payload["result"][0]["request"].pop("src_port", None)
    # Since we have fallbacks, we must also ensure it's not in the top level if we want it to fail
    payload.pop("src_port", None) 
    with pytest.raises(Exception):
        await parser.parse_line(payload)


@pytest.mark.asyncio
async def test_parse_line_handles_result_as_dict(parser: HamstringParser):
    payload = _sample_payload()
    payload["result"] = payload["result"][0]
    alert = await parser.parse_line(payload)
    assert alert.source_port == "1668"
    assert alert.severity == 0.73


@pytest.mark.asyncio
async def test_parse_line_handles_missing_result_with_fallback(parser: HamstringParser):
    payload = {
        "src_ip": "192.168.10.9",
        "src_port": 58467,
        "alert_timestamp": "2026-03-26T13:07:15",
        "detector_name": "TestDetector"
    }
    alert = await parser.parse_line(payload)
    assert alert.source_ip == "192.168.10.9"
    assert alert.source_port == "58467"
    assert alert.type == "TestDetector"


@pytest.mark.asyncio
async def test_parse_line_handles_user_provided_alert(parser: HamstringParser):
    user_alert = {
        "overall_score": 0.0008593629145939803,
        "result": [
            {
                "request": {
                    "ts": "2017-07-03T09:02:10",
                    "src_ip": "192.168.10.9",
                    "src_port": 58467,
                    "dns_server_ip": "192.168.10.3",
                    "dns_server_port": 53,
                    "domain_name": "shield-normandy-elb-prod-2099053585.us-west-2.elb.amazonaws.com",
                    "record_type": "A"
                }
            }
        ],
        "src_ip": "192.168.10.9",
        "alert_timestamp": "2026-03-26T13:07:15.457187",
        "detector_name": "RF-dga_detector"
    }
    alert = await parser.parse_line(user_alert)
    assert alert.source_ip == "192.168.10.9"
    assert alert.source_port == "58467"
    assert alert.severity == 0.0 # rounded from 0.0008
    assert alert.type == "RF-dga_detector"



@pytest.mark.asyncio
async def test_get_threat_level_and_normalize(parser: HamstringParser):
    assert await parser.get_threat_level("info") == 0
    assert await parser.get_threat_level("low") == 1
    assert await parser.get_threat_level("medium") == 2
    assert await parser.get_threat_level("high") == 3
    assert await parser.get_threat_level("critical") == 4
    assert await parser.normalize_threat_levels(1) == 0.25
    assert await parser.normalize_threat_levels(4) == 1
    assert await parser.normalize_threat_levels(None) is None
