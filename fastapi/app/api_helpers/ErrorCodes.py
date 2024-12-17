from http import HTTPStatus


class BodyCode:
    def __init__(self, code, message, httpStatus):
        self.code = code
        self.message = message
        self.httpStatus = httpStatus


class ErrorCodes:
    # --Generals(10)
    UNAWARE_ERR = BodyCode(10000, "Unaware exception's thrown from resource server", HTTPStatus.BAD_REQUEST)
    # --URL(11)
    EMPTY_URL = BodyCode(11000, "Empty URL", HTTPStatus.BAD_REQUEST)
