from fastapi import APIRouter, HTTPException

from config.settings import UPLOAD_DIR
from parser.log_parser import parse_log_file
from detection_engine.detector import run_detection_engine
from mitre_mapper.mapper import map_alerts_to_mitre

router = APIRouter()

@router.get("/detect/{filename}")
async def detect_threats(filename: str):

    file_path = UPLOAD_DIR / filename

    if not file_path.exists():

        raise HTTPException(
            status_code=404,
            detail="File not found"
        )

    parser_result = parse_log_file(file_path)

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
        "parsed_events": len(parsed_logs),
        "total_alerts": len(enriched_alerts),
        "alerts": enriched_alerts
    }
