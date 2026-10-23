from types import SimpleNamespace

import pytest
from requests.exceptions import ConnectionError, HTTPError
from web3 import Web3
from web3.exceptions import TransactionNotFound, Web3RPCError

from chatspy.evm_rpc import EvmRpcPool, EvmRpcUnavailable


def pool_with(*clients):
    pool = EvmRpcPool([f"https://rpc-{i}.example" for i in range(len(clients))], 84532)
    pool.clients = clients
    return pool


def test_read_rotates_after_transport_failure_and_ignores_wrong_chain():
    def offline():
        raise ConnectionError("offline")

    pool = pool_with(
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, block_number=0)),
        SimpleNamespace(eth=SimpleNamespace(chain_id=1, block_number=99)),
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, block_number=42)),
    )
    assert pool.call(lambda client: offline() if client is pool.clients[0] else client.eth.block_number) == 42


def test_pending_nonce_uses_highest_healthy_provider():
    pool = pool_with(
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_count=lambda *_: 7)),
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_count=lambda *_: 9)),
    )
    assert pool.pending_nonce("0xabc") == 9


def test_duplicate_raw_broadcast_returns_signed_hash():
    def known(_):
        raise Web3RPCError({"code": -32000, "message": "already known"})

    pool = pool_with(SimpleNamespace(eth=SimpleNamespace(chain_id=84532, send_raw_transaction=known)))
    raw = bytes.fromhex("0102")
    assert pool.broadcast(raw) == Web3.keccak(raw)


def test_rate_limited_provider_fails_over():
    def limited(_):
        raise Web3RPCError({"code": -32005, "message": "rate limit exceeded"})

    pool = pool_with(
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_balance=limited)),
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_balance=lambda _: 10)),
    )
    assert pool.call(lambda client: client.eth.get_balance("0xabc")) == 10


def test_nonce_too_low_only_succeeds_for_the_same_transaction():
    raw = bytes.fromhex("0102")
    tx_hash = Web3.keccak(raw)

    def nonce_used(_):
        raise Web3RPCError({"code": -32000, "message": "nonce too low"})

    pool = pool_with(SimpleNamespace(eth=SimpleNamespace(
        chain_id=84532, send_raw_transaction=nonce_used,
        get_transaction=lambda _: {"hash": tx_hash},
    )))
    assert pool.broadcast(raw) == tx_hash

    pool.clients = (SimpleNamespace(eth=SimpleNamespace(
        chain_id=84532, send_raw_transaction=nonce_used,
        get_transaction=lambda _: (_ for _ in ()).throw(TransactionNotFound("missing")),
    )),)
    with pytest.raises(Web3RPCError, match="nonce too low"):
        pool.broadcast(raw)


def test_receipt_checks_second_provider_when_first_has_not_seen_tx():
    def missing(_):
        raise TransactionNotFound("pending")

    receipt = {"blockNumber": 10}
    pool = pool_with(
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_receipt=missing)),
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_receipt=lambda _: receipt, block_number=13)),
    )
    assert pool.receipt_with_height("0x123") == (receipt, 13)


def test_receipt_stays_pending_when_one_provider_restricts_receipts():
    def restricted(_):
        raise HTTPError("403 archive token required")

    def missing(_):
        raise TransactionNotFound("pending")

    pool = pool_with(
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_receipt=restricted)),
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_receipt=missing)),
    )
    with pytest.raises(TransactionNotFound):
        pool.receipt_with_height("0x123")


def test_receipt_fails_over_from_restricted_provider():
    def restricted(_):
        raise HTTPError("403 archive token required")

    receipt = {"blockNumber": 10}
    pool = pool_with(
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_receipt=restricted)),
        SimpleNamespace(eth=SimpleNamespace(chain_id=84532, get_transaction_receipt=lambda _: receipt, block_number=13)),
    )
    assert pool.receipt_with_height("0x123") == (receipt, 13)


def test_wrong_chain_is_unavailable():
    pool = pool_with(SimpleNamespace(eth=SimpleNamespace(chain_id=1)))
    with pytest.raises(EvmRpcUnavailable):
        pool.call(lambda client: 5)
