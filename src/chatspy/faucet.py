import os
import requests
from web3 import Web3
from decimal import Decimal
from eth_account import Account
from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
from stellar_sdk import Server, Keypair, TransactionBuilder, Asset, Network

from .utils import logger

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
                .set_timeout(18000)  # 5h
                .append_begin_sponsoring_future_reserves_op(sponsored_id=account_public)
                .append_change_trust_op(
                    asset=asset,
                    source=account_public,  # operation is performed by the sponsored account
                )
                .append_end_sponsoring_future_reserves_op(source=account_public)
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
                .set_timeout(18000)  # 5h
                .append_end_sponsoring_future_reserves_op(source=account_public)
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
            .set_timeout(18000)  # 5h
            .append_payment_op(
                destination=self.distributor_public,
                asset=self.chats_usdc,
                amount=amount,
            )
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
            .set_timeout(18000)  # 5h
            .append_payment_op(
                destination=recipient_public,
                asset=self.chats_usdc,
                amount=amount,
            )
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


class USDTFaucet:
    def __init__(self):
        self.alchemy_key = os.getenv("ALCHEMY_API_KEY")
        if not self.alchemy_key:
            raise ValueError("ALCHEMY_API_KEY environment variable not set")

        self.w3 = Web3(Web3.HTTPProvider(f"https://eth-sepolia.g.alchemy.com/v2/{self.alchemy_key}"))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        self.deployer_key = os.getenv("USDT_DEPLOYER_KEY")
        if not self.deployer_key:
            raise ValueError("USDT_DEPLOYER_KEY environment variable not set")
        self.deployer = Account.from_key(self.deployer_key)

        self.usdt_contract_address = "0xEEAD57cD7D101FC7ae3635d467175B3f9De68312"
        self.usdt_contract = self._load_usdt_contract()

    def _load_usdt_contract(self):
        usdt_abi = [
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "address", "name": "owner", "type": "address"},
                    {"indexed": True, "internalType": "address", "name": "spender", "type": "address"},
                    {"indexed": False, "internalType": "uint256", "name": "value", "type": "uint256"},
                ],
                "name": "Approval",
                "type": "event",
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "address", "name": "from", "type": "address"},
                    {"indexed": True, "internalType": "address", "name": "to", "type": "address"},
                    {"indexed": False, "internalType": "uint256", "name": "value", "type": "uint256"},
                ],
                "name": "Transfer",
                "type": "event",
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "", "type": "address"},
                    {"internalType": "address", "name": "", "type": "address"},
                ],
                "name": "allowance",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "spender", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"},
                ],
                "name": "approve",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [{"internalType": "address", "name": "", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [],
                "name": "decimals",
                "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"},
                ],
                "name": "mint",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [],
                "name": "name",
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [],
                "name": "symbol",
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"},
                ],
                "name": "transfer",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "from", "type": "address"},
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"},
                ],
                "name": "transferFrom",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "nonpayable",
                "type": "function",
            },
        ]

        return self.w3.eth.contract(address=self.usdt_contract_address, abi=usdt_abi)

    def mint_usdt(self, recipient: str, amount: int = 1000) -> str:
        """Mint test USDT to an address"""
        tx = self.usdt_contract.functions.mint(
            recipient,
            int(Decimal(str(amount)) * 10**6),  # USDT 6 decimals
        ).build_transaction(
            {
                "chainId": 11155111,
                "gas": 200000,
                "gasPrice": self.w3.eth.gas_price,
                "nonce": self.w3.eth.get_transaction_count(self.deployer.address),
            }
        )

        signed_tx = self.w3.eth.account.sign_transaction(tx, self.deployer_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt.transactionHash.hex()

    def get_usdt_balance(self, address: str) -> Decimal:
        """Check USDT balance for an address"""
        balance = self.usdt_contract.functions.balanceOf(address).call()
        return Decimal(balance) / Decimal(10**6)
