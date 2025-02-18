import os
import requests
from .utils import logger
from stellar_sdk import Server, Keypair, TransactionBuilder, Asset, Network

BASE_FEE = 100
HORIZON_URL = "https://horizon-testnet.stellar.org"
NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE


class StellarFaucet:
    def __init__(self, issuer_secret=None, distributor_secret=None):
        """Initialize the Stellar Faucet for managing ChatsUSDC."""
        
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
        """ Fund a Stellar account using Friendbot """

        url = f"https://friendbot.stellar.org?addr={public_key}"
        response = requests.get(url)
        if response.status_code == 200:
            logger.i(f"Account {public_key} funded successfully!")

            return True
        logger.i(f"Error funding account {public_key}: {response.text}")
        return False

    def create_trustline(self, account_keypair):
        """Create a trustline for an account to hold ChatsUSDC."""
        account_public = account_keypair if isinstance(account_keypair, str) else account_keypair.public_key
        account = self.server.load_account(account_public)

        transaction = (
            TransactionBuilder(
                source_account=account,
                network_passphrase=self.network_passphrase,
                base_fee=BASE_FEE,
            )
            .append_change_trust_op(asset=self.chats_usdc)
            .set_timeout(30)
            .build()
        )
        transaction.sign(account_keypair)
        response = self.server.submit_transaction(transaction)
        logger.i(f"Trustline created for {account_public}")
        return response

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

    def send_chats_usdc(self, recipient_public, recipient_secret, amount="1000"):
        """ Send ChatsUSDC from Distributor to a recipient """

        recipient_account = self.server.accounts().account_id(recipient_public).call()
        has_trustline = any(
            balance.get("asset_code") == "ChatsUSDC" and balance.get("asset_issuer") == self.issuer_public
            for balance in recipient_account["balances"]
        )

        if not has_trustline:
            if recipient_secret:
                recipient_keypair = Keypair.from_secret(recipient_secret)
                self.create_trustline(recipient_keypair)
            else:
                raise ValueError(f"Recipient {recipient_public} does not have a trustline and no secret key is available.")

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
