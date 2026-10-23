"""Multi-endpoint EVM RPC access for signed transactions and reads."""

from threading import Lock
from typing import Callable, Sequence, TypeVar

from requests.exceptions import RequestException
from web3 import Web3
from web3.exceptions import ProviderConnectionError, TransactionNotFound, Web3RPCError


T = TypeVar("T")


def _transient_rpc_error(error: Web3RPCError) -> bool:
    message = str(error).lower()
    return any(marker in message for marker in (
        "rate limit", "too many requests", "429", "temporarily unavailable", "timeout", "503",
    ))


class EvmRpcUnavailable(RuntimeError):
    """No configured endpoint could complete the RPC operation."""


class EvmRpcPool:
    """Rotate RPCs, validate their chain, and fail over on transport failures.

    Semantic RPC errors are returned to the caller. A raw transaction is safe to
    retry on another endpoint because its signed bytes and hash do not change.
    """

    def __init__(self, urls: Sequence[str], chain_id: int, timeout: int = 20):
        self.urls = tuple(url.strip() for url in urls if url.strip())
        if not self.urls or any(not url.startswith("https://") for url in self.urls):
            raise ValueError("At least one HTTPS EVM RPC URL is required")
        self.chain_id = chain_id
        self.clients = tuple(Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout})) for url in self.urls)
        self._index = 0
        self._lock = Lock()

    def _ordered_clients(self):
        with self._lock:
            start = self._index
            self._index = (self._index + 1) % len(self.clients)
        return (self.clients[(start + offset) % len(self.clients)] for offset in range(len(self.clients)))

    def call(self, operation: Callable[[Web3], T], *, retry_not_found: bool = False) -> T:
        missing = None
        for client in self._ordered_clients():
            try:
                if client.eth.chain_id != self.chain_id:
                    continue
                return operation(client)
            except TransactionNotFound as error:
                if not retry_not_found:
                    raise
                missing = error
            except Web3RPCError as error:
                if not _transient_rpc_error(error):
                    raise
            except (RequestException, ProviderConnectionError, ConnectionError, TimeoutError, OSError):
                continue
        if missing is not None:
            raise missing
        raise EvmRpcUnavailable("EVM RPC endpoints are unavailable or on the wrong chain")

    def pending_nonce(self, address: str) -> int:
        """Use the highest visible pending nonce across healthy endpoints."""
        nonces = []
        for client in self._ordered_clients():
            try:
                if client.eth.chain_id == self.chain_id:
                    nonces.append(client.eth.get_transaction_count(address, "pending"))
            except Web3RPCError as error:
                if not _transient_rpc_error(error):
                    raise
            except (RequestException, ProviderConnectionError, ConnectionError, TimeoutError, OSError):
                continue
        if not nonces:
            raise EvmRpcUnavailable("EVM RPC endpoints are unavailable or on the wrong chain")
        return max(nonces)

    def broadcast(self, raw_transaction: bytes):
        """Rebroadcast identical signed bytes; accepted duplicate hashes are success."""
        tx_hash = Web3.keccak(raw_transaction)

        def send(client):
            try:
                returned_hash = client.eth.send_raw_transaction(raw_transaction)
                if returned_hash != tx_hash:
                    raise ValueError("RPC returned a different transaction hash")
                return returned_hash
            except (ValueError, Web3RPCError) as error:
                message = str(error).lower()
                if "already known" in message or "known transaction" in message:
                    return tx_hash
                if "nonce too low" in message:
                    try:
                        if client.eth.get_transaction(tx_hash):
                            return tx_hash
                    except TransactionNotFound:
                        pass
                raise

        return self.call(send)

    def receipt_with_height(self, tx_hash):
        """Read receipt and block height from the same endpoint."""
        return self.call(
            lambda client: (client.eth.get_transaction_receipt(tx_hash), client.eth.block_number),
            retry_not_found=True,
        )
