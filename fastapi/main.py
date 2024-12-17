from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.interceptor.ExcHandler import ExcHandler
from app.routers import MaliciousURLPredictionRouters

app = FastAPI()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

exceptionHandler = ExcHandler(app)
exceptionHandler.turn_on()

app.include_router(MaliciousURLPredictionRouters.router)
