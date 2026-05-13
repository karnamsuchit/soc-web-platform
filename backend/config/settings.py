from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

UPLOAD_DIR = BASE_DIR / "uploads"

ALLOWED_EXTENSIONS = [
    ".log",
    ".txt",
    ".csv"
]

MAX_FILE_SIZE = 50 * 1024 * 1024
