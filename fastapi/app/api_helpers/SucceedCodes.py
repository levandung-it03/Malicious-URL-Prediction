from http import HTTPStatus


class BodyCode:
    def __init__(self, code, message):
        self.code = code
        self.message = message
        self.httpStatus = HTTPStatus.OK


class SucceedCodes:
    PREDICT_URL = BodyCode(21001, "Predict URL successfully")
