from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.upload import router as upload_router
from api.parser import router as parser_router
from api.detection import router as detection_router

app = FastAPI(
    title="SOC Log Analysis Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router)
app.include_router(parser_router)
app.include_router(detection_router)

@app.get("/")
def home():
    return {
        "message": "SOC Platform Backend Running"
    }
