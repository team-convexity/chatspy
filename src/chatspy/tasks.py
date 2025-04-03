import os
from stellar_sdk.exceptions import NotFoundError, BadResponseError
from stellar_sdk import Server, Network, TransactionBuilder, Keypair

from .celery_config import app
from .faucet import StellarFaucet
from .utils import logger, is_production


# @app.task
def activate_wallet(account_private: str):
    """Create the wallet on mainnet or testnet depending on env mode by sponsoring trustline creations etc"""
    logger.info("Activating wallet...")

    from .ccrypto import STELLAR_USDC_ACCOUNT_ID, Contract

    try:
        # determine the network based on the environment
        network = Network.PUBLIC_NETWORK_PASSPHRASE if is_production() else Network.TESTNET_NETWORK_PASSPHRASE
        server = Server(
            horizon_url="https://horizon.stellar.org" if is_production() else "https://horizon-testnet.stellar.org"
        )

        # load the contract owner's wallet
        contract_owner_seed = os.getenv("STELLAR_CONTRACT_OWNER_SEED_PHRASE")
        if not contract_owner_seed:
            raise ValueError("stellar_contract_owner_seed_phrase is not set in the environment.")

        decrypted_seed = Contract.decrypt_key(contract_owner_seed)
        contract_owner_keypair = Keypair.from_mnemonic_phrase(decrypted_seed)
        source_account = server.load_account(contract_owner_keypair.public_key)
        account_keypair = Keypair.from_secret(account_private)
        logger.info(f"{account_keypair.public_key}")

        if is_production():
            transaction = (
                TransactionBuilder(
                    source_account=source_account,
                    network_passphrase=network,
                    base_fee=100,
                )
                .append_begin_sponsoring_future_reserves_op(sponsored_id=account_keypair.public_key)
                .append_create_account_op(destination=account_keypair.public_key, starting_balance="1")
                .append_end_sponsoring_future_reserves_op(source=account_keypair.public_key)
                .set_timeout(30)
                .build()
            )
            # sponsor
            transaction.sign(contract_owner_keypair)
            transaction.sign(account_keypair)
            response = server.submit_transaction(transaction)
            logger.info(f"sponsored wallet activation for {account_keypair.public_key}: {response}")

            # sponsor the usdc trustline
            faucet = StellarFaucet()
            faucet.create_trustline(
                account_keypair,
                asset_code="USDC",
                asset_issuer=STELLAR_USDC_ACCOUNT_ID,
                sponsor_keypair=contract_owner_keypair,
            )
            logger.info(f"sponsored usdc trustline for {account_keypair.public_key}")

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
                .set_timeout(30)
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
            faucet.send_chats_usdc(
                recipient_public=account_keypair.public_key,
                recipient_secret=account_keypair.secret,
                amount=1,
                has_trustline=True,
            )
            logger.info(f"sent 1 ChatsUSDC to {account_keypair.public_key}")

    except NotFoundError as e:
        logger.error(f"account not found: {e}")

    except BadResponseError as e:
        logger.error(f"bad response from stellar network: {e}")

    except Exception as e:
        logger.error(f"an error occurred: {e}")
