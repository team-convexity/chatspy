import os
from stellar_sdk.exceptions import NotFoundError, BadResponseError
from stellar_sdk.asset import Asset as StellarAsset
from stellar_sdk.soroban_rpc import SendTransactionStatus
from stellar_sdk import Server, SorobanServer, Network, TransactionBuilder, Keypair

from .celery_config import app
from .faucet import StellarFaucet
from .utils import logger, is_production


@app.task
def cactivate_wallet(account_private: str):
    """celery version of activate wallet"""
    from .ccrypto import Contract

    account_keypair = Keypair.from_secret(Contract.decrypt_key(account_private))
    _activate_wallet(account_private=account_keypair.secret)


def activate_wallet(account_private: str):
    return _activate_wallet(account_private)


def _activate_wallet(account_private: str):
    """Create the wallet on mainnet or testnet depending on env mode by sponsoring trustline creations etc"""

    from .ccrypto import STELLAR_USDC_ACCOUNT_ID, Contract, Asset, Chain

    try:
        # determine the network based on the environment
        network = Network.PUBLIC_NETWORK_PASSPHRASE if is_production() else Network.TESTNET_NETWORK_PASSPHRASE
        server = (
            SorobanServer(server_url="https://mainnet.sorobanrpc.com")
            if is_production()
            else Server(horizon_url="https://horizon-testnet.stellar.org")
        )
        contract_owner_seed = os.getenv("STELLAR_CONTRACT_OWNER_SEED_PHRASE")
        if not contract_owner_seed:
            raise ValueError("stellar_contract_owner_seed_phrase is not set in the environment.")

        decrypted_seed = Contract.decrypt_key(contract_owner_seed)
        contract_owner_keypair = Keypair.from_mnemonic_phrase(decrypted_seed)
        source_account = server.load_account(contract_owner_keypair.public_key)
        account_keypair = Keypair.from_secret(account_private)

        if is_production():
            try:
                create_tx = (
                    TransactionBuilder(
                        source_account=source_account,
                        network_passphrase=network,
                        base_fee=100,
                    )
                    .append_create_account_op(destination=account_keypair.public_key, starting_balance="1")
                    .set_timeout(180)
                    .build()
                )
                create_tx.sign(contract_owner_keypair)
                create_response = server.send_transaction(create_tx)
                logger.info(f"Initial account creation: {create_response.hash}")

                success = Asset.wait_for_transaction_confirmation(
                    timeout=30,
                    poll_interval=3,
                    chain=Chain.STELLAR,
                    tx_hash=create_response.hash,
                )

                if not success:
                    raise Exception("Initial account creation failed")

            except Exception as e:
                logger.error(f"Initial account creation error: {str(e)}")
                raise

            try:
                trustline_tx = (
                    TransactionBuilder(
                        source_account=source_account,
                        network_passphrase=network,
                        base_fee=100,
                    )
                    .append_begin_sponsoring_future_reserves_op(sponsored_id=account_keypair.public_key)
                    .append_change_trust_op(
                        asset=StellarAsset("USDC", STELLAR_USDC_ACCOUNT_ID), source=account_keypair.public_key
                    )
                    .append_end_sponsoring_future_reserves_op(source=account_keypair.public_key)
                    .set_timeout(180)
                    .build()
                )

                trustline_tx.sign(contract_owner_keypair)
                trustline_tx.sign(account_keypair)

                trustline_response = server.send_transaction(trustline_tx)
                logger.info("Sponsored USDC trustline created")
                return trustline_response

            except Exception as e:
                logger.error(f"Trustline setup error: {str(e)}")
                raise

        else:
            transaction = (
                TransactionBuilder(
                    source_account=source_account,
                    network_passphrase=network,
                    base_fee=100,
                )
                .append_begin_sponsoring_future_reserves_op(sponsored_id=account_keypair.public_key)
                .append_create_account_op(destination=account_keypair.public_key, starting_balance="1")
                .append_end_sponsoring_future_reserves_op(source=account_keypair.public_key)
                .set_timeout(18000)
                .build()
            )

            # sponsor
            transaction.sign(contract_owner_keypair)
            transaction.sign(account_keypair)
            response = server.submit_transaction(transaction)
            logger.info(f"sponsored testnet activation for {account_keypair.public_key}: {response}")

            # sponsor ChatsUSDC trustline
            faucet = StellarFaucet()
            faucet.create_trustline(account_keypair, sponsor_keypair=contract_owner_keypair)
            logger.info(f"sponsored ChatsUSDC trustline for {account_keypair.public_key}")

            # send test asset
            response = faucet.send_chats_usdc(
                recipient_public=account_keypair.public_key,
                recipient_secret=account_keypair.secret,
                amount=1,
                has_trustline=True,
            )
            logger.info(f"sent 1 ChatsUSDC to {account_keypair.public_key}")
            return response

    except NotFoundError as e:
        logger.error(f"account not found: {e}")

    except BadResponseError as e:
        logger.error(f"bad response from stellar network: {e}")

    except Exception as e:
        logger.error(f"an error occurred: {e}")
