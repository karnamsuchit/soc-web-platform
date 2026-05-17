from fastapi import APIRouter, HTTPException
from pathlib import Path

from config.settings import UPLOAD_DIR
from parser.log_parser import parse_log_file
from detection_engine.detector import run_detection_engine
from mitre_mapper.mapper import map_alerts_to_mitre

router = APIRouter()
SAMPLE_LOG_DIR = Path(__file__).resolve().parent.parent / "sample_logs"

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
    if not SAMPLE_LOG_DIR.exists():
        return {"samples": []}

    samples = [
        {"filename": path.name, "size_bytes": path.stat().st_size}
        for path in sorted(SAMPLE_LOG_DIR.iterdir())
        if path.suffix.lower() in [".log", ".txt", ".csv", ".json", ".jsonl"]
    ]
    return {"samples": samples}


@router.get("/analyze-sample/{filename}")
async def analyze_sample_log(filename: str):
    safe_name = Path(filename).name
    file_path = SAMPLE_LOG_DIR / safe_name

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Sample file not found"
        )

    return analyze_file(file_path, safe_name)


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
