from fastapi import FastAPI, Request

from app.api_helpers.ApiResponse import ApiResponse
from app.api_helpers.CustomeExc import ApplicationException
from app.api_helpers.ErrorCodes import ErrorCodes


class ExcHandler:
    def __init__(self, app: FastAPI):
        self.app = app

    def turn_on(self):
        self.application_exception_filter()

    def application_exception_filter(self):
        @self.app.exception_handler(Exception)
        async def handle_application_exception(request: Request, exc: ApplicationException):
            try:
                return ApiResponse(exc.errorCodes, None)
            except AttributeError:
                return ApiResponse(ErrorCodes.UNAWARE_ERR, None)