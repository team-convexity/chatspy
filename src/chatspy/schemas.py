from ninja import ModelSchema, Schema


class ErrorResponse(Schema):
    message: str
    detail: str | None = None