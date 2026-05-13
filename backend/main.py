from fastapi import FastAPI

app = FastAPI(
    title="SOC Log Analysis Platform",
    version="1.0.0"
)

@app.get("/")
def home():
    return {
        "message": "SOC Platform Backend Running"
    }
