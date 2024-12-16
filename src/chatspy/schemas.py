from ninja import Schema


class ErrorResponse(Schema):
    message: str
    detail: str | None = None


class BaseResponseSchema(Schema):
    success: bool = True
    error: ErrorResponse | None = None
