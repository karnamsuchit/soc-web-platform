import re
import csv
from pathlib import Path
from datetime import datetime

APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) '
    r'(?P<url>\S+) '
    r'(?P<protocol>.*?)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+)'
)


def parse_apache_line(line):

    match = APACHE_LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        parsed_timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )

        data["timestamp"] = parsed_timestamp.isoformat()

    except Exception:
        pass

    if data["size"] == "-":
        data["size"] = 0
    else:
        data["size"] = int(data["size"])

    data["status"] = int(data["status"])

    data["log_type"] = "apache_http"

    return data


def parse_csv_file(file_path):

    parsed_logs = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:

        reader = csv.DictReader(file)

        for row in reader:

            normalized_row = {
                key.strip(): value.strip()
                for key, value in row.items()
            }

            normalized_row["log_type"] = "csv"

            parsed_logs.append(normalized_row)

    return parsed_logs


def parse_text_file(file_path):

    parsed_logs = []
    malformed_logs = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            parsed_line = parse_apache_line(line)

            if parsed_line:
                parsed_logs.append(parsed_line)

            else:
                malformed_logs.append({
                    "line_number": line_number,
                    "content": line
                })

    return parsed_logs, malformed_logs


def parse_log_file(file_path):

    file_path = Path(file_path)

    extension = file_path.suffix.lower()

    parsed_logs = []
    malformed_logs = []

    try:

        # CSV Logs
        if extension == ".csv":

            parsed_logs = parse_csv_file(file_path)

        # TXT / LOG Files
        elif extension in [".log", ".txt"]:

            parsed_logs, malformed_logs = parse_text_file(file_path)

        else:
            return {
                "error": "Unsupported file type"
            }

        return {
            "parsed_logs": parsed_logs,
            "malformed_logs": malformed_logs,
            "total_parsed": len(parsed_logs),
            "total_malformed": len(malformed_logs),
            "detected_format": extension
        }

    except Exception as error:

        return {
            "error": str(error)
        }
