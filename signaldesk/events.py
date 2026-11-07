"""Strict normalization; input is evidence, never code."""
import hashlib
import ipaddress
import json
from datetime import datetime, timezone

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

KINDS = {"auth_failure", "auth_success", "process_start", "audit_cleared"}
FIELDS = {"timestamp", "host", "source", "event_id", "kind", "user", "src_ip", "command", "synthetic"}
MAX_BYTES = 5 * 1024 * 1024
MAX_EVENTS = 10000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize(row):
    if not isinstance(row, dict) or set(row) - FIELDS:
        raise ValueError("Expected an event object containing only documented schema fields")
    result = {}
    for key in ("timestamp", "host", "source", "event_id", "kind"):
        value = row.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"{key} must be a nonempty string of at most 256 characters")
        result[key] = value.strip()
    try:
        stamp = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        if stamp.utcoffset() is None:
            raise ValueError()
        result["timestamp"] = stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        raise ValueError("timestamp must be an ISO-8601 date with an explicit time zone") from None
    if result["kind"] not in KINDS:
        raise ValueError("Unsupported event kind")
    for key, limit in (("user", 256), ("src_ip", 64), ("command", 8192)):
        value = row.get(key, "")
        if not isinstance(value, str) or len(value) > limit or "\x00" in value:
            raise ValueError(f"Invalid {key}")
        result[key] = value.strip()
    if result["src_ip"]:
        try:
            result["src_ip"] = str(ipaddress.ip_address(result["src_ip"]))
        except ValueError:
            raise ValueError("src_ip must be a valid IP address or empty") from None
    if type(row.get("synthetic", False)) is not bool:
        raise ValueError("synthetic must be a boolean")
    result["synthetic"] = row.get("synthetic", False)
    result["id"] = digest(canonical(result))
    return result


def windows_rows(text):
    """Read exported Event XML, retaining Windows record identifiers."""
    root = ET.fromstring(text)
    # Strip namespace URIs, supporting Security EventData and 1102 UserData.
    for element in root.iter():
        element.tag = element.tag.rsplit("}", 1)[-1]
    events = [root] if root.tag == "Event" else list(root.findall("Event"))
    if root.tag not in ("Event", "Events"):
        raise ValueError("Expected Windows Event or Events XML")
    mapping = {"4625": "auth_failure", "4624": "auth_success", "4688": "process_start", "1102": "audit_cleared"}
    for element in events:
        system = element.find("System")
        if system is None:
            raise ValueError("Windows event has no System element")
        code = system.findtext("EventID")
        if code not in mapping:
            raise ValueError(f"Unsupported Windows event ID: {code}; export 4624, 4625, 4688 or 1102")
        data = {d.get("Name"): d.text or "" for d in element.findall("EventData/Data")}
        for d in element.findall("UserData/LogFileCleared/*"):
            data[d.tag] = d.text or ""
        time = system.find("TimeCreated")
        ip = data.get("IpAddress", "")
        if ip in ("-", "::", "0.0.0.0"):
            ip = ""
        yield {"timestamp": time.get("SystemTime", "") if time is not None else "",
               "host": system.findtext("Computer", ""), "source": "windows_security",
               "event_id": f"{code}:{system.findtext('EventRecordID', '')}",
               "kind": mapping[code], "user": data.get("TargetUserName") or data.get("SubjectUserName", ""),
               "src_ip": ip, "command": data.get("CommandLine", ""), "synthetic": False}


def parse_payload(payload, format):
    if len(payload) > MAX_BYTES:
        raise ValueError("Import exceeds 5 MiB")
    try:
        text = payload.decode("utf-8-sig")
        if format == "ndjson":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif format == "windows-xml":
            rows = list(windows_rows(text))
        else:
            raise ValueError("format must be ndjson or windows-xml")
        if not 1 <= len(rows) <= MAX_EVENTS:
            raise ValueError("Import must contain 1 to 10000 events")
        return [normalize(row) for row in rows]
    except (UnicodeError, ET.ParseError, DefusedXmlException, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid {format} input") from exc
