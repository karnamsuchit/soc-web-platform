from fastapi import APIRouter, UploadFile, File, HTTPException
from pathlib import Path
import shutil
import uuid

from config.settings import (
    UPLOAD_DIR,
    ALLOWED_EXTENSIONS,
)

router = APIRouter()

UPLOAD_DIR.mkdir(exist_ok=True)

@router.post("/upload")
async def upload_log_file(file: UploadFile = File(...)):

    file_extension = Path(file.filename).suffix.lower()

    if file_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Invalid file type"
        )

    unique_filename = f"{uuid.uuid4()}{file_extension}"

    file_path = UPLOAD_DIR / unique_filename

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "message": "File uploaded successfully",
        "filename": unique_filename,
        "original_filename": file.filename
    }
