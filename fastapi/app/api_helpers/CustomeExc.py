from app.api_helpers.ErrorCodes import BodyCode


class ApplicationException(Exception):
    """Custom exception class for application errors."""
    def __init__(self, errorCodes: BodyCode):
        self.errorCodes = errorCodes
        super().__init__(errorCodes.message)