import os
from stellar_sdk.exceptions import BadResponseError
from stellar_sdk import Server, Network, TransactionBuilder, Keypair

from .celery_config import app
from .clients import RedisClient
from .faucet import StellarFaucet
from redis.cluster import ClusterNode
from redis.exceptions import LockError
from .utils import logger, is_production


def _build_mainnet_transaction(builder: TransactionBuilder, account_keypair: Keypair) -> TransactionBuilder:
    return (
        builder.append_begin_sponsoring_future_reserves_op(sponsored_id=account_keypair.public_key)
        .append_create_account_op(destination=account_keypair.public_key, starting_balance="1")
        .append_end_sponsoring_future_reserves_op(source=account_keypair.public_key)
    )


def _build_testnet_transaction(builder: TransactionBuilder, account_keypair: Keypair) -> TransactionBuilder:
    return (
        builder.append_begin_sponsoring_future_reserves_op(sponsored_id=account_keypair.public_key)
        .append_create_account_op(destination=account_keypair.public_key, starting_balance="1")
        .append_end_sponsoring_future_reserves_op(source=account_keypair.public_key)
    )


def _should_retry(error: BadResponseError) -> bool:
    """Determine if transaction should be retried based on error"""
    if error.type == "tx_bad_seq":
        return True

    if error.status == 504:  # Gateway timeout
        return True

    if "timeout" in error.message.lower():
        return True

    return False


def _get_redis_client() -> RedisClient:
    redis_nodes = [
        ClusterNode(host=os.getenv("REDIS_CLUSTER_A_STRING"), port=os.getenv("REDIS_CLUSTER_A_PORT", 10397)),
    ]
    return RedisClient(
        startup_nodes=redis_nodes,
        password=os.getenv("REDIS_PASSWORD"),
        cluster_enabled=os.getenv("REDIS_CLUSTER_ENABLED", "false").lower() == "true",
        decode_responses=True,
    )


@app.task(bind=True, max_retries=3)
def activate_wallet(self, account_private: str):
    """Create wallet with sponsored transactions using sequence locking"""
    from .ccrypto import STELLAR_USDC_ACCOUNT_ID, Contract

    try:
        redis_client = _get_redis_client()
        network = Network.PUBLIC_NETWORK_PASSPHRASE if is_production() else Network.TESTNET_NETWORK_PASSPHRASE
        server = Server(
            horizon_url="https://horizon.stellar.org" if is_production() else "https://horizon-testnet.stellar.org"
        )
        contract_owner_seed = Contract.decrypt_key(os.environ["STELLAR_CONTRACT_OWNER_SEED_PHRASE"])
        contract_owner_keypair = Keypair.from_mnemonic_phrase(contract_owner_seed)
        account_keypair = Keypair.from_secret(Contract.decrypt_key(account_private))

        # distributed lock
        lock = redis_client.client.lock(name="stellar:contract_owner:seq_lock", timeout=60, blocking_timeout=30)

        try:
            if not lock.acquire(blocking=True):
                logger.warning("Failed to acquire sequence lock, retrying...")
                raise self.retry(countdown=2)

            # lock - only one process at a time
            source_account = server.load_account(contract_owner_keypair.public_key)
            base_fee = server.fetch_base_fee()

            # build
            builder = TransactionBuilder(
                source_account=source_account,
                network_passphrase=network,
                base_fee=base_fee,
            )

            if is_production():
                builder = _build_mainnet_transaction(builder, account_keypair)

            else:
                builder = _build_testnet_transaction(builder, account_keypair)

            transaction = builder.set_timeout(18000).build()
            transaction.sign(contract_owner_keypair)
            transaction.sign(account_keypair)

            response = server.submit_transaction(transaction)
            logger.info(f"Transaction successful: {response['hash']}")

            # post-transaction operations
            faucet = StellarFaucet()
            if is_production():
                faucet.create_trustline(
                    account_keypair,
                    asset_code="USDC",
                    asset_issuer=STELLAR_USDC_ACCOUNT_ID,
                    sponsor_keypair=contract_owner_keypair,
                )
            else:
                faucet.create_trustline(account_keypair, sponsor_keypair=contract_owner_keypair)
                faucet.send_chats_usdc(
                    amount=1,
                    has_trustline=True,
                    recipient_secret=account_keypair.secret,
                    recipient_public=account_keypair.public_key,
                )

        except BadResponseError as e:
            if _should_retry(e):
                logger.warning(f"Retryable error: {e}, retrying...")
                raise self.retry(exc=e, countdown=5)

            raise

        finally:
            try:
                lock.release()

            except LockError:
                logger.warning("Failed to release Redis lock")
                pass

    except Exception as e:
        logger.error(f"Wallet activation failed: {str(e)}")
        raise
