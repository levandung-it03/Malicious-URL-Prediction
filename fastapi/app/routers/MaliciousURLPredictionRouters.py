from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api_helpers.ApiResponse import ApiResponse
from app.api_helpers.SucceedCodes import SucceedCodes
from app.machines import MaliciousURLPrediction

router = APIRouter()

class URLPredictionDto(BaseModel):
    url: str = Field(..., min_length=1, description="URL must not be empty")

@router.post("/malicious-url-predict")
def predict_malicious_url(request: URLPredictionDto):
    return ApiResponse(SucceedCodes.PREDICT_URL, MaliciousURLPrediction.predict_url(request.url))