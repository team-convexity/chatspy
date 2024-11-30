class MicroserviceError(Exception):
    """
    Base exception for microservice errors
    """

    ...


class ConfigurationError(MicroserviceError):
    """
    Raised when configuration is invalid
    """

    def __init__(self, message: str):
        super().__init__(message, status_code=500)


class AuthenticationError(MicroserviceError):
    """
    Raised during authentication failures
    """

    def __init__(self, message: str):
        super().__init__(message, status_code=401)


class PermissionDeniedError(MicroserviceError):
    """
    Raised when access is forbidden
    """

    def __init__(self, message: str):
        super().__init__(message, status_code=403)


class ValidationError(Exception):
    """
    Raised when a validation error occured.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(message)
