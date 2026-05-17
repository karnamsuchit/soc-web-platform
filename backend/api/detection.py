from fastapi import APIRouter, HTTPException
from pathlib import Path

from config.settings import UPLOAD_DIR
from parser.log_parser import parse_log_file
from detection_engine.detector import run_detection_engine
from mitre_mapper.mapper import map_alerts_to_mitre

router = APIRouter()
SAMPLE_LOG_DIR = Path(__file__).resolve().parent.parent / "sample_logs"
ROOT_SAMPLE_LOG_DIR = Path(__file__).resolve().parents[2] / "sample_logs"

@router.get("/detect/{filename}")
async def detect_threats(filename: str):

    file_path = UPLOAD_DIR / filename

    if not file_path.exists():

        raise HTTPException(
            status_code=404,
            detail="File not found"
        )

    return analyze_file(file_path, filename)


@router.get("/samples")
async def list_sample_logs():
    sample_paths = get_sample_files()

    if not sample_paths:
        return {"samples": []}

    samples = [
        {"filename": path.name, "size_bytes": path.stat().st_size}
        for path in sample_paths
    ]
    return {"samples": samples}


@router.get("/analyze-sample/{filename}")
async def analyze_sample_log(filename: str):
    safe_name = Path(filename).name
    file_path = find_sample_file(safe_name)

    if not file_path:
        raise HTTPException(
            status_code=404,
            detail="Sample file not found"
        )

    return analyze_file(file_path, safe_name)


@router.get("/monitoring/live")
async def live_monitoring_feed(limit: int = 30):
    sample_files = get_sample_files()
    combined_events = []
    combined_alerts = []
    combined_iocs = {
        "ips": set(),
        "domains": set(),
        "hashes": set(),
        "urls": set(),
    }

    for sample_file in sample_files:
        analysis = analyze_file(sample_file, sample_file.name)
        combined_events.extend(
            {**event, "dataset": sample_file.name}
            for event in analysis.get("events", [])
        )
        combined_alerts.extend(
            {**alert, "dataset": sample_file.name}
            for alert in analysis.get("alerts", [])
        )
        for key in combined_iocs:
            combined_iocs[key].update(analysis.get("iocs", {}).get(key, []))

    combined_events = sorted(
        combined_events,
        key=lambda event: str(event.get("timestamp") or ""),
        reverse=True,
    )[:limit]
    combined_alerts = sorted(
        combined_alerts,
        key=lambda alert: severity_rank(alert.get("severity")),
        reverse=True,
    )[:limit]

    severity_counts = {}
    for alert in combined_alerts:
        severity = alert.get("severity", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "mode": "demo_monitoring",
        "message": "Simulated live monitoring feed built from preloaded SOC datasets.",
        "datasets": [path.name for path in sample_files],
        "total_events": len(combined_events),
        "total_alerts": len(combined_alerts),
        "severity_counts": severity_counts,
        "events": combined_events,
        "alerts": combined_alerts,
        "iocs": {
            "ips": sorted(combined_iocs["ips"]),
            "domains": sorted(combined_iocs["domains"]),
            "hashes": sorted(combined_iocs["hashes"]),
            "urls": sorted(combined_iocs["urls"]),
            "total_iocs": sum(len(values) for values in combined_iocs.values()),
        },
    }


def analyze_file(file_path, filename):
    parser_result = parse_log_file(file_path)

    if parser_result.get("error"):
        raise HTTPException(
            status_code=400,
            detail=parser_result["error"]
        )

    parsed_logs = parser_result.get(
        "parsed_logs",
        []
    )

    detection_result = run_detection_engine(
        parsed_logs
    )

    alerts = detection_result.get(
        "alerts",
        []
    )

    enriched_alerts = map_alerts_to_mitre(
        alerts
    )

    return {
        "filename": filename,
        "detected_format": parser_result.get("detected_format"),
        "parsed_events": len(parsed_logs),
        "malformed_events": parser_result.get("total_malformed", 0),
        "total_alerts": len(enriched_alerts),
        "alerts": enriched_alerts,
        "events": parsed_logs,
        "summary": detection_result.get("summary", {}),
        "iocs": detection_result.get("iocs", {}),
    }


def get_sample_files():
    sample_files = []
    for directory in [ROOT_SAMPLE_LOG_DIR, SAMPLE_LOG_DIR]:
        if directory.exists():
            sample_files.extend(
                path
                for path in sorted(directory.iterdir())
                if path.suffix.lower() in [".log", ".txt", ".csv", ".json", ".jsonl"]
            )

    unique_files = {}
    for path in sample_files:
        unique_files[path.name] = path
    return list(unique_files.values())


def find_sample_file(filename):
    for sample_file in get_sample_files():
        if sample_file.name == filename:
            return sample_file
    return None


def severity_rank(severity):
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(str(severity).lower(), 0)
