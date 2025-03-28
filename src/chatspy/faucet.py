import os
import requests
from .utils import logger
from stellar_sdk import Server, Keypair, TransactionBuilder, Asset, Network

BASE_FEE = 100
HORIZON_URL = "https://horizon-testnet.stellar.org"
NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE


class StellarFaucet:
    def __init__(self, issuer_secret=None, distributor_secret=None):
        """Initialize the Stellar Faucet for managing USDC/ChatsUSDC."""

        self.server = Server(horizon_url=HORIZON_URL)
        self.network_passphrase = NETWORK_PASSPHRASE

        issuer_secret = issuer_secret or os.getenv("CHATS_USDC_ISSUER_SECRET")
        distributor_secret = distributor_secret or os.getenv("CHATS_USDC_DISTRIBUTOR_SECRET")

        if not any([distributor_secret, issuer_secret]):
            return logger.debug("\nMissing 'distributor_secret' or 'issuer_secret' or both")

        self.issuer_secret = issuer_secret
        self.issuer_keypair = Keypair.from_secret(self.issuer_secret)
        self.issuer_public = self.issuer_keypair.public_key

        self.distributor_secret = distributor_secret
        self.distributor_keypair = Keypair.from_secret(self.distributor_secret)

        self.distributor_public = self.distributor_keypair.public_key
        self.chats_usdc = Asset("ChatsUSDC", self.issuer_public)
        # self.fund_account(self.issuer_public)
        # self.fund_account(self.distributor_public)

    def fund_account(self, public_key):
        """Fund a Stellar account using Friendbot"""

        url = f"https://friendbot.stellar.org?addr={public_key}"
        response = requests.get(url)
        if response.status_code == 200:
            logger.i(f"Account {public_key} funded successfully!")

            return True
        logger.i(f"Error funding account {public_key}: {response.text}")
        return False

    def create_trustline(self, account_keypair, asset_code=None, asset_issuer=None, sponsor_keypair=None):
        """create a trustline for an account to hold a specific asset.
        if no asset_code or asset_issuer is provided, defaults to chatsusdc.
        """
        try:
            if not sponsor_keypair:
                from .ccrypto import Contract
                contract_owner_seed = os.getenv("STELLAR_CONTRACT_OWNER_SEED_PHRASE")
                if not contract_owner_seed:
                    logger.error("stellar_contract_owner_seed_phrase is not set in the environment.")
                    raise ValueError("stellar_contract_owner_seed_phrase is not set in the environment.")

                decrypted_seed = Contract.decrypt_key(contract_owner_seed)
                sponsor_keypair = Keypair.from_mnemonic_phrase(decrypted_seed)

            account_public = account_keypair.public_key

            # default to chatsusdc if no asset_code/issuer is provided
            asset = self.chats_usdc if (asset_code is None or asset_issuer is None) else Asset(asset_code, asset_issuer)

            # load the SPONSOR'S account (not the sponsored account)
            sponsor_account = self.server.load_account(sponsor_keypair.public_key)

            # build transaction using the SPONSOR'S account as the source
            transaction = (
                TransactionBuilder(
                    source_account=sponsor_account,
                    network_passphrase=self.network_passphrase,
                    base_fee=BASE_FEE,
                )
                .append_begin_sponsoring_future_reserves_op(sponsored_id=account_public)
                .append_change_trust_op(
                    asset=asset,
                    source=account_public,  # operation is performed by the sponsored account
                )
                .append_end_sponsoring_future_reserves_op(source=account_public)
                .set_timeout(30)
                .build()
            )

            # sponsor signs first, then the sponsored account
            transaction.sign(sponsor_keypair)
            transaction.sign(account_keypair)

            response = self.server.submit_transaction(transaction)
            logger.info(f"trustline created for {account_public} to {asset.code}")
            return response

        except Exception as e:
            logger.error(f"failed to create trustline: {str(e)}")
            raise

    def end_sponsorship(self, account_keypair, sponsor_keypair=None):
        """
        end sponsorship for a specific account.
        
        when a wallet, user, or ngo is deactivated/deleted, this removes their sponsorship
        """
        try:
            if not sponsor_keypair:
                from .ccrypto import Contract
                contract_owner_seed = os.getenv("STELLAR_CONTRACT_OWNER_SEED_PHRASE")
                if not contract_owner_seed:
                    raise ValueError("stellar_contract_owner_seed_phrase is not set in the environment.")

                decrypted_seed = Contract.decrypt_key(contract_owner_seed)
                sponsor_keypair = Keypair.from_mnemonic_phrase(decrypted_seed)

            account_public = account_keypair.public_key

            # load the sponsor'S account
            sponsor_account = self.server.load_account(sponsor_keypair.public_key)

            # build transaction to end sponsorship
            transaction = (
                TransactionBuilder(
                    source_account=sponsor_account,
                    network_passphrase=self.network_passphrase,
                    base_fee=BASE_FEE,
                )
                .append_end_sponsoring_future_reserves_op(source=account_public)
                .set_timeout(30)
                .build()
            )

            # sponsor signs the transaction
            transaction.sign(sponsor_keypair)

            response = self.server.submit_transaction(transaction)
            logger.info(f"sponsorship ended for {account_public}")
            return response

        except Exception as e:
            logger.error(f"failed to end sponsorship: {str(e)}")
            raise

    def issue_chats_usdc(self, amount="1000000"):
        """Issue ChatsUSDC from Issuer to Distributor."""

        issuer_account = self.server.load_account(self.issuer_public)

        transaction = (
            TransactionBuilder(
                source_account=issuer_account,
                network_passphrase=self.network_passphrase,
                base_fee=BASE_FEE,
            )
            .append_payment_op(
                destination=self.distributor_public,
                asset=self.chats_usdc,
                amount=amount,
            )
            .set_timeout(30)
            .build()
        )
        transaction.sign(self.issuer_keypair)
        response = self.server.submit_transaction(transaction)
        logger.i(f"Issued {amount} ChatsUSDC to Distributor")
        return response

    def send_chats_usdc(self, recipient_public, recipient_secret, amount="1000", has_trustline=False):
        """Send ChatsUSDC from Distributor to a recipient"""

        recipient_account = self.server.accounts().account_id(recipient_public).call()
        if not has_trustline:
            has_trustline = any(
                balance.get("asset_code") == "ChatsUSDC" and balance.get("asset_issuer") == self.issuer_public
                for balance in recipient_account["balances"]
            )

            if not has_trustline:
                if recipient_secret:
                    recipient_keypair = Keypair.from_secret(recipient_secret)
                    self.create_trustline(recipient_keypair)
                else:
                    raise ValueError(
                        f"Recipient {recipient_public} does not have a trustline and no secret key is available."
                    )

        distributor_account = self.server.load_account(self.distributor_public)

        transaction = (
            TransactionBuilder(
                source_account=distributor_account,
                network_passphrase=self.network_passphrase,
                base_fee=BASE_FEE,
            )
            .append_payment_op(
                destination=recipient_public,
                asset=self.chats_usdc,
                amount=amount,
            )
            .set_timeout(30)
            .build()
        )
        transaction.sign(self.distributor_keypair)
        response = self.server.submit_transaction(transaction)
        logger.i(f"Sent {amount} ChatsUSDC to {recipient_public}")
        return response

    def create_chats_usdc_asset(self):
        """Define and create the ChatsUSDC asset."""

        self.chats_usdc = Asset("ChatsUSDC", self.issuer_public)
        logger.i(f"Defined ChatsUSDC asset with issuer: {self.issuer_public}")
        self.create_trustline(self.distributor_keypair)
        self.issue_chats_usdc()
        logger.i("ChatsUSDC asset created and issued to distributor.")
