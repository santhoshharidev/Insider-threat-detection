from fastapi import FastAPI

from .api import api_router

app = FastAPI(title="Mocktivate API", version="0.1")

app.include_router(api_router, prefix="/api")

@app.get("/")
def root():
    return {"message": "Mocktivate API - backend prototype"}
