import time
from typing import Any

from starlette.responses import JSONResponse

from app.api_helpers.ErrorCodes import BodyCode


def get_response_time() -> float:
    """Capture the current time in seconds since the epoch."""
    return time.time()


class ApiResponse(JSONResponse):
    def __init__(self, error_codes: BodyCode, data: Any):
        self.content = {
            "applicationCode": error_codes.code,
            "message": error_codes.message,
            "httpStatusCode": error_codes.httpStatus.value,  # Use the integer value of the HTTP status
            "data": data,
            "responseTime": get_response_time()
        }
        super().__init__(
            content=self.content,
            status_code=error_codes.httpStatus.value,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Ngrok-Skip-Browser-Warning": "true"
            }
        )