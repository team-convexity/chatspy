from ninja import Schema


class ErrorResponse(Schema):
    message: str
    detail: str | None = None
