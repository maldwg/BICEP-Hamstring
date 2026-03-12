from src.utils.models.ids_base import IDSParser, Alert
import json
import os
import os.path
from datetime import datetime, timezone
from ..utils.general_utilities import normalize_timestamp_for_alert

class HamstringParser(IDSParser):
    alert_file_location = "/opt/logs/hamstring.json"
    flows_as_hashmap = {}

    async def parse_alerts(self):
        parsed_lines = set()

        if not os.path.isfile(self.alert_file_location):
            return parsed_lines

        with open(self.alert_file_location, "r") as alerts:
            for line in alerts:
                try:
                    line_as_json = json.loads(line)
                    parsed_line = await self.parse_line(line_as_json)
                    if parsed_line != None:
                        parsed_lines.add(parsed_line)
                except Exception as e:
                    #print(f"could not parse line {line} because of error {e}")
                    # print(f"could not parse line {line} \n ... skipping")
                    continue
        # cleanup the alertsfile after parsing to prevent doubled entries
        open(self.alert_file_location, 'w').close()
        return list(parsed_lines)

    async def parse_line(self, line):
        if not isinstance(line, dict):
            return None

        if "raw" in line and isinstance(line["raw"], str):
            try:
                line = json.loads(line["raw"])
            except json.JSONDecodeError:
                return None

        parsed_line = Alert()
        result_list = line.get("result") or []
        request = {}
        if result_list and isinstance(result_list, list):
            first = result_list[0]
            if isinstance(first, dict):
                request = first.get("request") or {}

        timestamp = line.get("alert_timestamp") or request.get("ts")
        if timestamp:
            try:
                parsed_line.time = await normalize_timestamp_for_alert(
                    datetime.fromisoformat(timestamp).astimezone(timezone.utc).isoformat()
                )
            except Exception:
                parsed_line.time = await normalize_timestamp_for_alert(timestamp)

        parsed_line.source_ip = line.get("src_ip") or request.get("src_ip")
        if request.get("src_port") is not None:
            parsed_line.source_port = str(request.get("src_port"))
        parsed_line.destination_ip = request.get("dns_server_ip") or request.get("dst_ip")
        if request.get("dns_server_port") is not None:
            parsed_line.destination_port = str(request.get("dns_server_port"))

        if not parsed_line.time or not parsed_line.source_ip or not parsed_line.source_port:
            raise Exception("Missing important information in logline")

        detector_name = line.get("detector_name") or "Alert"
        parsed_line.type = detector_name

        severity = None
        overall_score = line.get("overall_score")
        if isinstance(overall_score, (int, float)):
            severity = float(overall_score)
        elif result_list:
            try:
                severity = max(
                    float(item.get("probability", 0.0))
                    for item in result_list
                    if isinstance(item, dict)
                )
            except Exception:
                severity = None
        if severity is not None:
            parsed_line.severity = round(max(min(severity, 1.0), 0.0), 2)

        details = {}
        domain = request.get("domain_name")
        if domain:
            details["domain"] = domain
        if request.get("status_code"):
            details["status_code"] = request.get("status_code")
        if request.get("record_type"):
            details["record_type"] = request.get("record_type")
        if line.get("suspicious_batch_id"):
            details["batch_id"] = line.get("suspicious_batch_id")
        details["detector"] = detector_name
        parsed_line.message = json.dumps(details) if details else detector_name

        return parsed_line
 
    async def get_threat_level(self, severity: str, ):
        # get everything after substring for threat level
        severity = severity.lower()
        try:
            if severity == "info":
                return 0    
            elif severity == "low":
                return 1
            elif severity == "medium":
                return 2
            elif severity == "high":
                return 3
            elif severity == "critical":
                return 4 
        # As alert lines will not have this info but rather a normal threat_level, use that instead
        except Exception as e:
            print(f"Could not determine threat level for line {severity}, using lowest level now")
            return 0



            
    
    async def normalize_threat_levels(self, threat: int):
        # threat levels are from 0 (info) to 4 (critical)
        # parse the levels into numbers
        max_level = 4
        if threat is None or threat > max_level:
            # Unexpected high value
            return None
        return round(threat / max_level,2)



        
