import re
from typing import Optional, Tuple
from functools import singledispatch


class ContractErrorContext:
    __slots__ = ("function", "args", "raw_error", "simulation_result")

    def __init__(self, function: str, args: list, raw_error: str, simulation_result: Optional[dict] = None):
        self.function = function
        self.args = tuple(args)
        self.raw_error = raw_error
        self.simulation_result = simulation_result

    def as_dict(self) -> dict:
        return {
            "function": self.function,
            "args": self.args,
            "raw_error": self.raw_error,
            "simulation_result": self.simulation_result,
        }


class ContractError(Exception):
    """Base exception for all contract-related errors"""

    def __init__(self, message: str, context: ContractErrorContext):
        super().__init__(message)
        self.context = context

    def __str__(self) -> str:
        return (
            f"{super().__str__()}\n"
            f"Context: {self.context.function}()\n"
            f"Args: {self.context.args}\n"
            f"Raw Error: {self.context.raw_error}"
        )


class ContractInvocationError(ContractError):
    """Error during contract function invocation"""


class ContractSimulationError(ContractError):
    """Error during transaction simulation"""


class ContractParsingError(ContractError):
    """Error parsing contract response"""


class ErrorHandler:
    """Abstract error handler following Chain of Responsibility"""

    def __init__(self, successor: Optional["ErrorHandler"] = None):
        self.successor = successor

    def handle(self, context: ContractErrorContext) -> Optional[ContractError]:
        handled = self._try_handle(context)
        if not handled and self.successor:
            return self.successor.handle(context)
        return handled

    def _try_handle(self, context: ContractErrorContext) -> Optional[ContractError]:
        raise NotImplementedError

    @singledispatch
    def parse_error(raw_error: str) -> Tuple[Optional[int], str]:
        """Base parser for unknown error types"""
        return None, str(raw_error)

    @parse_error.register(str)
    def _(raw_error: str) -> Tuple[Optional[int], str]:
        """Parse string-based Soroban errors"""
        match = re.search(r"#(\d+)", raw_error)
        return (int(match.group(1)), raw_error) if match else (None, raw_error)

    @parse_error.register(dict)
    def _(raw_error: dict) -> Tuple[Optional[int], str]:
        """Parse dictionary-based errors"""
        return raw_error.get("code"), raw_error.get("message", "Unknown error")


class SorobanErrorHandler(ErrorHandler):
    """Handles structured Soroban contract errors"""

    ERROR_REGEX = re.compile(r"Error\(Contract, #(\d+)\)")

    def _try_handle(self, context: ContractErrorContext) -> Optional[ContractError]:
        if not context.raw_error:
            return None

        match = self.ERROR_REGEX.search(context.raw_error)
        if not match:
            return None

        code = int(match.group(1))
        return self.map_error_code(code, context)

    @staticmethod
    def map_error_code(code: int, context: ContractErrorContext) -> ContractError:
        mapping = {
            1001: (UnauthorizedError, "Unauthorized operation"),
            1002: (InsufficientFundsError, "Insufficient funds"),
            1003: (AllowanceNotFoundError, "Allowance not found"),
            1004: (InvalidRoleError, "Invalid role specified"),
            1005: (ContractPausedError, "Contract operations paused"),
            1006: (ExpiredAllowanceError, "Allowance expired"),
        }

        exc_type, message = mapping.get(code, (ContractError, "Unknown contract error"))
        return exc_type(message, context)


class SimulationErrorHandler(ErrorHandler):
    """Handles transaction simulation errors"""

    def _try_handle(self, context: ContractErrorContext) -> Optional[ContractError]:
        if context.simulation_result and "error" in context.simulation_result:
            return ContractSimulationError("Transaction simulation failed", context)
        return None


class FallbackErrorHandler(ErrorHandler):
    """Handles all remaining errors"""

    def _try_handle(self, context: ContractErrorContext) -> ContractError:
        return ContractError("Unhandled contract error", context)


class ConfigurationError(Exception):
    """Raised when configuration is invalid"""

    def __init__(self, message: str):
        super().__init__(f"Configuration Error: {message}")
        self.status_code = 500


class AuthenticationError(Exception):
    """Raised during authentication failures"""

    def __init__(self, message: str):
        super().__init__(f"Authentication Error: {message}")
        self.status_code = 401


class PermissionDeniedError(Exception):
    """Raised when access is forbidden"""

    def __init__(self, message: str):
        super().__init__(f"Permission Denied: {message}")
        self.status_code = 403


class ValidationError(Exception):
    """Raised when validation fails"""

    def __init__(self, message: str):
        super().__init__(f"Validation Error: {message}")
        self.status_code = 400


class ContractError(Exception):
    """Base class for contract-specific business logic errors"""

    def __init__(self, message: str, code: int, context: Optional[ContractErrorContext] = None):
        super().__init__(f"Contract Error [{code}]: {message}")
        self.code = code
        self.context = context
        self.status_code = self._code_to_status(code)

    @staticmethod
    def _code_to_status(code: int) -> int:
        return {
            1001: 403,  # Unauthorized
            1002: 400,  # InsufficientFunds
            1003: 404,  # AllowanceNotFound
            1004: 400,  # InvalidRole
            1005: 403,  # ContractPaused
            1006: 400,  # ExpiredAllowance
        }.get(code, 500)  # default to 500 if unknown code


class UnauthorizedError(ContractError):
    """Raised when operation is not authorized"""

    def __init__(self, message: str = "Unauthorized operation", context: Optional[ContractErrorContext] = None):
        super().__init__(message, 1001, context)


class InsufficientFundsError(ContractError):
    """Raised when account has insufficient funds"""

    def __init__(self, message: str = "Insufficient funds", context: Optional[ContractErrorContext] = None):
        super().__init__(message, 1002, context)


class AllowanceNotFoundError(ContractError):
    """Raised when requested allowance doesn't exist"""

    def __init__(self, message: str = "Allowance not found", context: Optional[ContractErrorContext] = None):
        super().__init__(message, 1003, context)


class InvalidRoleError(ContractError):
    """Raised when invalid role is specified"""

    def __init__(self, message: str = "Invalid role specified", context: Optional[ContractErrorContext] = None):
        super().__init__(message, 1004, context)


class ContractPausedError(ContractError):
    """Raised when contract operations are paused"""

    def __init__(self, message: str = "Contract operations are paused", context: Optional[ContractErrorContext] = None):
        super().__init__(message, 1005, context)


class ExpiredAllowanceError(ContractError):
    """Raised when trying to use expired allowance"""

    def __init__(self, message: str = "Allowance has expired", context: Optional[ContractErrorContext] = None):
        super().__init__(message, 1006, context)


class PaymentError(Exception):
    def __init__(self, message: str, client: str, original_exception: Optional[Exception] = None):
        super().__init__(f"[{client}] {message}")
        self.client = client
        self.original_exception = original_exception
