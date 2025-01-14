from pydantic import BaseModel


class ErrorResponse(BaseModel):
    message: str
    detail: str | None = None


class BaseResponseSchema(BaseModel):
    success: bool = True
    error: ErrorResponse | None = None

class IdentityVerificationSchema(BaseModel):
    firstname: str
    lastname: str
    dob: str | None = None
    gender: str | None = None
