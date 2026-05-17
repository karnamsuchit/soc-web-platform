import csv
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit


APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<request>.*?)" '
    r"(?P<status>\d{3}) (?P<size>\S+)(?: \"(?P<referrer>.*?)\" \"(?P<user_agent>.*?)\")?"
)

AUTH_LOG_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<service>[\w\-/]+)(?:\[\d+\])?: (?P<message>.*)"
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _parse_apache_timestamp(value):
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return value


def _parse_auth_timestamp(value):
    try:
        current_year = datetime.utcnow().year
        parsed = datetime.strptime(f"{current_year} {value}", "%Y %b %d %H:%M:%S")
        return parsed.isoformat()
    except ValueError:
        return value


def _split_request(request):
    parts = request.split()
    if len(parts) < 2:
        return "", request, ""

    method = parts[0]
    protocol = parts[-1] if parts[-1].startswith("HTTP/") else ""
    url = " ".join(parts[1:-1]) if protocol else " ".join(parts[1:])
    return method, url, protocol


def _url_metadata(url):
    decoded = unquote_plus(str(url or ""))
    parsed = urlsplit(decoded)
    return {
        "url": decoded,
        "path": parsed.path or decoded,
        "query": parsed.query,
    }


def _base_event(source_format, line_number=None):
    return {
        "timestamp": None,
        "source_ip": None,
        "destination_host": None,
        "username": None,
        "method": None,
        "url": None,
        "path": None,
        "query": None,
        "status": None,
        "bytes": 0,
        "user_agent": None,
        "event_type": "network",
        "category": "web",
        "action": "observed",
        "source_format": source_format,
        "line_number": line_number,
        "raw": None,
    }


def parse_apache_line(line, line_number=None):
    match = APACHE_LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    method, url, protocol = _split_request(data.get("request", ""))
    url_data = _url_metadata(url)

    status = int(data["status"])
    event = _base_event("apache_http", line_number)
    event.update(
        {
            "timestamp": _parse_apache_timestamp(data["timestamp"]),
            "source_ip": data["ip"],
            "method": method,
            "protocol": protocol,
            "status": status,
            "bytes": 0 if data["size"] == "-" else int(data["size"]),
            "user_agent": data.get("user_agent") or "",
            "referrer": data.get("referrer") or "",
            "event_type": "http_request",
            "category": "web",
            "action": "failed" if status in [401, 403] else "observed",
            "raw": line,
            **url_data,
        }
    )
    return event


def parse_json_line(line, line_number=None):
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None

    event = _base_event("json", line_number)
    url = payload.get("url") or payload.get("request") or payload.get("path")
    url_data = _url_metadata(url)

    event.update(
        {
            "timestamp": payload.get("timestamp") or payload.get("@timestamp") or payload.get("time"),
            "source_ip": payload.get("source_ip") or payload.get("src_ip") or payload.get("ip"),
            "destination_host": payload.get("destination_host") or payload.get("host"),
            "username": payload.get("username") or payload.get("user"),
            "method": payload.get("method"),
            "status": _safe_int(payload.get("status") or payload.get("status_code")),
            "bytes": _safe_int(payload.get("bytes") or payload.get("size"), 0),
            "user_agent": payload.get("user_agent") or payload.get("ua"),
            "event_type": payload.get("event_type") or payload.get("type") or "json_event",
            "category": payload.get("category") or "application",
            "action": payload.get("action") or payload.get("outcome") or "observed",
            "raw": line,
            **url_data,
        }
    )
    return event


def parse_auth_line(line, line_number=None):
    match = AUTH_LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    message = data["message"]
    ips = IP_PATTERN.findall(message)
    user_match = re.search(r"(?:user|for|invalid user)\s+([A-Za-z0-9_.@-]+)", message, re.IGNORECASE)
    failed = any(term in message.lower() for term in ["failed password", "authentication failure", "invalid user"])

    event = _base_event("auth_syslog", line_number)
    event.update(
        {
            "timestamp": _parse_auth_timestamp(data["timestamp"]),
            "source_ip": ips[0] if ips else None,
            "destination_host": data["host"],
            "username": user_match.group(1) if user_match else None,
            "event_type": "authentication",
            "category": "authentication",
            "action": "failed" if failed else "observed",
            "service": data["service"],
            "message": message,
            "raw": line,
        }
    )
    return event


def parse_text_file(file_path):
    parsed_logs = []
    malformed_logs = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                continue

            parsed_line = (
                parse_json_line(line, line_number)
                or parse_apache_line(line, line_number)
                or parse_auth_line(line, line_number)
            )

            if parsed_line:
                parsed_logs.append(parsed_line)
            else:
                malformed_logs.append({"line_number": line_number, "content": line})

    return parsed_logs, malformed_logs


def parse_csv_file(file_path):
    parsed_logs = []
    malformed_logs = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as file:
        sample = file.read(2048)
        file.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(file, dialect=dialect)
        if not reader.fieldnames:
            return parsed_logs, [{"line_number": 1, "content": "Missing CSV headers"}]

        for line_number, row in enumerate(reader, start=2):
            if not any(row.values()):
                continue

            event = _event_from_csv_row(row, line_number)
            if event:
                parsed_logs.append(event)
            else:
                malformed_logs.append({"line_number": line_number, "content": str(row)})

    return parsed_logs, malformed_logs


def _event_from_csv_row(row, line_number):
    normalized = {str(key).strip().lower().replace(" ", "_"): value for key, value in row.items() if key}

    source_ip = (
        normalized.get("source_ip")
        or normalized.get("src_ip")
        or normalized.get("ip")
        or normalized.get("client_ip")
        or normalized.get("station_mac")
    )
    url = normalized.get("url") or normalized.get("request") or normalized.get("path") or ""
    url_data = _url_metadata(url)

    event = _base_event("csv", line_number)
    event.update(
        {
            "timestamp": normalized.get("timestamp") or normalized.get("time") or normalized.get("date"),
            "source_ip": source_ip,
            "destination_host": normalized.get("host") or normalized.get("destination_host") or normalized.get("server"),
            "username": normalized.get("username") or normalized.get("user"),
            "method": normalized.get("method"),
            "status": _safe_int(normalized.get("status") or normalized.get("status_code")),
            "bytes": _safe_int(normalized.get("bytes") or normalized.get("size"), 0),
            "user_agent": normalized.get("user_agent"),
            "event_type": normalized.get("event_type") or normalized.get("type") or "csv_event",
            "category": normalized.get("category") or "general",
            "action": normalized.get("action") or normalized.get("outcome") or "observed",
            "raw": row,
            **url_data,
        }
    )
    return event


def _safe_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_log_file(file_path):
    file_path = Path(file_path)
    extension = file_path.suffix.lower()

    try:
        if extension == ".csv":
            parsed_logs, malformed_logs = parse_csv_file(file_path)
        elif extension in [".log", ".txt", ".json", ".jsonl"]:
            parsed_logs, malformed_logs = parse_text_file(file_path)
        else:
            return {"error": "Unsupported file type"}

        formats = sorted({event.get("source_format") for event in parsed_logs if event.get("source_format")})
        return {
            "parsed_logs": parsed_logs,
            "malformed_logs": malformed_logs,
            "total_parsed": len(parsed_logs),
            "total_malformed": len(malformed_logs),
            "detected_format": ", ".join(formats) if formats else extension,
        }
    except Exception as error:
        return {"error": str(error)}
