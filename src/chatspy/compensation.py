from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from stellar_sdk.soroban_rpc import SendTransactionResponse

from .utils import logger


@dataclass
class CompensationAction:
    """Represents a compensation action to reverse a blockchain operation"""

    operation: str
    args: Dict[str, Any]
    execute: Callable[[], Any]


class BlockchainCompensationManager:
    """Manages compensation transactions for blockchain operations that cannot be rolled back."""

    def __init__(self):
        self.compensation_stack: List[CompensationAction] = []
        self.successful_operations: List[Dict[str, Any]] = []

    def execute_with_compensation(
        self,
        forward_fn: Callable[[], SendTransactionResponse],
        compensation_fn: Callable[[], SendTransactionResponse],
        operation_name: str,
        compensation_args: Optional[Dict[str, Any]] = None,
    ) -> SendTransactionResponse:
        """Execute a blockchain operation and register its compensation."""
        try:
            result = forward_fn()

            if result.status == "ERROR":
                raise Exception(f"Blockchain operation failed: {operation_name}")

            compensation = CompensationAction(
                operation=operation_name,
                args=compensation_args or {},
                execute=compensation_fn,
            )
            self.compensation_stack.append(compensation)

            self.successful_operations.append(
                {
                    "operation": operation_name,
                    "status": result.status,
                    "hash": result.hash,
                }
            )

            logger.i(f"Blockchain operation succeeded: {operation_name}, hash: {result.hash}")
            return result

        except Exception as e:
            logger.e(f"Blockchain operation failed: {operation_name}, error: {e}")
            raise

    def compensate_all(self) -> List[Dict[str, Any]]:
        """Execute all compensation actions in reverse order (LIFO)."""
        results = []

        while self.compensation_stack:
            compensation = self.compensation_stack.pop()
            try:
                logger.i(f"Executing compensation for: {compensation.operation}")
                result = compensation.execute()
                results.append(
                    {
                        "operation": compensation.operation,
                        "status": "compensated",
                        "result": result,
                    }
                )
            except Exception as e:
                logger.e(f"Compensation failed for {compensation.operation}", description=f"{e}")
                results.append(
                    {
                        "operation": compensation.operation,
                        "status": "compensation_failed",
                        "error": str(e),
                    }
                )

        return results

    def clear(self):
        """Clear compensation stack after successful commit"""
        self.compensation_stack.clear()
        self.successful_operations.clear()


class BatchedCompensationManager(BlockchainCompensationManager):
    """Optimized compensation manager for batch operations."""

    def __init__(self, batch_size: int = 50):
        super().__init__()
        self.batch_size = batch_size
        self.pending_batch: List[Any] = []

    def add_to_batch(self, item: Any, contract_method: str, reverse_method: str, **kwargs):
        """
        Add item to pending batch. Auto-flushes when batch size reached.

        Args:
            item: Item to add (e.g., beneficiary allowance tuple)
            contract_method: Method name to call for forward operation
            reverse_method: Method name to call for compensation
            **kwargs: Additional args for contract call
        """
        self.pending_batch.append(
            {
                "item": item,
                "contract_method": contract_method,
                "reverse_method": reverse_method,
                "kwargs": kwargs,
            }
        )

        if len(self.pending_batch) >= self.batch_size:
            self.flush_batch()

    def flush_batch(self):
        """Execute pending batch as single blockchain transaction"""
        if not self.pending_batch:
            return

        batch_items = [item["item"] for item in self.pending_batch]
        first_item = self.pending_batch[0]

        contract = first_item["kwargs"].get("contract")
        if not contract:
            raise ValueError("Contract must be provided in kwargs")

        def forward():
            method = getattr(contract, first_item["contract_method"])
            return method(
                allowances=batch_items,
                **{k: v for k, v in first_item["kwargs"].items() if k != "contract"},
            )

        def compensate():
            method = getattr(contract, first_item["reverse_method"])
            return method(
                allowances=batch_items,
                **{k: v for k, v in first_item["kwargs"].items() if k != "contract"},
            )

        self.execute_with_compensation(
            forward_fn=forward,
            compensation_fn=compensate,
            operation_name=f"batch_{first_item['contract_method']}_{len(batch_items)}_items",
        )

        self.pending_batch.clear()

    def finalize(self):
        """Flush any remaining items in pending batch"""
        self.flush_batch()


def create_zero_allowances_for_compensation(
    successful_allowances: List[tuple[str, str, int, int | None]],
) -> List[tuple[str, str, int, int | None]]:
    """
    Create zero-value allowances to effectively reverse allocations.
    The contract uses individual storage keys, setting to 0 removes the allowance.
    """
    return [(addr, item_id, 0, None) for addr, item_id, _, _ in successful_allowances]
