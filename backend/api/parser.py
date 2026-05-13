from fastapi import APIRouter, HTTPException
from pathlib import Path

from parser.log_parser import parse_log_file
from config.settings import UPLOAD_DIR

router = APIRouter()

@router.get("/parse/{filename}")
async def parse_uploaded_log(filename: str):

    file_path = UPLOAD_DIR / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found"
        )

    result = parse_log_file(file_path)

    return result
