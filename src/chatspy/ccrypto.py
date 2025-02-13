import os
from enum import Enum
from typing import List, Dict

import boto3
import secrets
from web3 import Web3
from eth_keys import keys
from eth_account import Account
from eth_utils import decode_hex
from botocore.exceptions import ClientError
from bitcoin import random_key, privtopub, pubtoaddr
from stellar_sdk import Server, Keypair as StellarKeypair, Network, TransactionBuilder, Asset as StellarAsset

from .services import Service
from .utils import logger, is_production

STELLAR_USDC_ACCOUNT_ID = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
TEST_STELLAR_USDC_ACCOUNT_ID = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"


def get_stellar_asset_account_id():
    if is_production():
        return STELLAR_USDC_ACCOUNT_ID

    return TEST_STELLAR_USDC_ACCOUNT_ID


class Chain(Enum):
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    STELLAR = "stellar"


class TokenStandard(Enum):
    ERC20 = "ERC20"


class Asset(Enum):
    BTC = ("BTC", "Bitcoin")
    USDT = ("USDT", "Tether (ERC20)", TokenStandard.ERC20)
    USDC = ("USDC", "USD Coin (Stellar)")
    CHATS = ("CHATS", "Chats Token (Stellar)")

    def __init__(self, symbol, display_name, token_standard=None):
        self.symbol = symbol
        self.display_name = display_name
        self._token_standard = token_standard

    @staticmethod
    def get_balance(address: str, chain: Chain):
        match chain:
            case Chain.BITCOIN:
                ...

            case Chain.ETHEREUM:
                ...

            case Chain.STELLAR:
                subdomain = "horizon." if is_production() else "horizon-testnet."
                server = Server(horizon_url=f"https://{subdomain}stellar.org")
                account = server.accounts().account_id(address).call()
                return account["balances"]
            case _:
                logger.warning(f"Unkwown chain: {chain}")

    @staticmethod
    def send_usdc(chain: Chain, source_address: str, destination_address: str, amount: str, source_secret: str):
        match chain:
            case Chain.STELLAR:
                BASE_FEE = 100  # base fee, in stroops
                subdomain = "horizon." if is_production() else "horizon-testnet."
                server = Server(horizon_url=f"https://{subdomain}stellar.org")
                source_keypair = StellarKeypair.from_secret(source_secret)
                source_account = server.load_account(source_keypair.public_key)
                asset = StellarAsset("USDC", get_stellar_asset_account_id())

                transaction = (
                    TransactionBuilder(
                        source_account=source_account,
                        network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE
                        if is_production()
                        else Network.TESTNET_NETWORK_PASSPHRASE,
                        base_fee=BASE_FEE,
                    )
                    .append_payment_op(
                        destination=destination_address,
                        asset=asset,
                        amount=amount
                    )
                    .set_timeout(30)
                    .build()
                )
                transaction.sign(source_keypair)
                response = server.submit_transaction(transaction)
                return response

            case _:
                logger.warning(f"[Submit Transaction]: Unhandled Chain: {chain}")

    @property
    def chain(self) -> Chain:
        """Returns the native chain for this asset."""
        ASSET_TO_CHAIN = {
            self.BTC: Chain.BITCOIN,
            self.USDT: Chain.ETHEREUM,
            self.USDC: Chain.STELLAR,
            self.CHATS: Chain.STELLAR,
        }
        return ASSET_TO_CHAIN[self]

    @property
    def is_token(self) -> bool:
        """Returns True if this is a token rather than a native cryptocurrency."""
        return self._token_standard is not None

    @property
    def token_standard(self) -> TokenStandard:
        """Returns the token standard if this is a token."""
        return self._token_standard


class Contract:
    def __init__(self, contract_address=None, contract_abi=None):
        self.w3 = Web3()
        if all([contract_abi, contract_address]):
            self.instance = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        else:
            logger.w(
                "[Contract Init]: No ABI or Contract address found in the env",
                service=Service.AUTH.value,
                description="[Contract Init]: No ABI or Contract address found in the env",
            )

    @staticmethod
    def generate_wallet(asset: Asset = Asset.CHATS, create_all: bool = False) -> List[Dict[str, str]]:
        """
        Generates a wallet appropriate for the specified asset. If `create_all` is True, generates wallets for all supported assets.

        :param asset: The asset to generate a wallet for (e.g., Asset.BTC, Asset.USDT)
        :param create_all: Flag to create wallets for all supported assets.
        :return: A list of dictionaries with the wallet details
        """
        if create_all:
            wallets = []
            for asset in Asset:
                wallets.extend(Contract.generate_wallet(asset=asset))
            return wallets

        chain = asset.chain
        wallets = []

        match chain:
            case Chain.BITCOIN:
                private_key = random_key()
                public_key = privtopub(private_key)
                address = pubtoaddr(public_key)

                wallets.append(
                    {
                        "address": address,
                        "chain": chain.value,
                        "asset": asset.symbol,
                        "display_name": asset.display_name,
                        "private_key": Contract.encrypt_key(private_key),
                        "public_key": public_key,
                    }
                )

            case Chain.ETHEREUM:
                # enable HDWallet features
                Account.enable_unaudited_hdwallet_features()
                # extra entropy
                account = Account.create(extra_entropy=secrets.token_hex(32))
                address = account.address
                # get private key and ensure proper format
                private_key = account.key.hex()
                if not private_key.startswith("0x"):
                    private_key = "0x" + private_key

                private_key_obj = keys.PrivateKey(decode_hex(private_key))
                public_key = private_key_obj.public_key
                wallets.append(
                    {
                        "address": address,
                        "chain": chain.value,
                        "asset": asset.symbol,
                        "public_key": public_key.to_hex(),
                        "display_name": asset.display_name,
                        "private_key": Contract.encrypt_key(private_key),
                    }
                )

            case Chain.STELLAR:
                if asset == Asset.USDC or asset == Asset.CHATS:
                    keypair = StellarKeypair.random()
                    private_key = keypair.secret
                    public_key = keypair.public_key
                    address = public_key

                    wallets.append(
                        {
                            "address": address,
                            "chain": chain.value,
                            "asset": asset.symbol,
                            "display_name": asset.display_name,
                            "private_key": Contract.encrypt_key(private_key),
                            "public_key": public_key,
                        }
                    )

            case _:
                logger.error(f"Unsupported chain: {chain}")

        return wallets

    @staticmethod
    def encrypt_key(private_key: str) -> str:
        """
        Encrypts a private key using AWS KMS.

        :param private_key: The private key to encrypt.
        :return: Encrypted private key (hex-encoded ciphertext blob).
        """
        KMS_KEY_ID = os.getenv("KMS_KEY_ID")

        if not KMS_KEY_ID:
            logger.w(
                "[KMS Encryption]: No KMS_KEY_ID is found",
                service=Service.AUTH.value,
                description="[KMS Encryption]: No KMS_KEY_ID is found (private key is not encrypted)",
            )
            return private_key

        kms_client = boto3.client("kms", region_name="us-east-2")

        try:
            response = kms_client.encrypt(KeyId=KMS_KEY_ID, Plaintext=private_key)
            return response["CiphertextBlob"].hex()
        except ClientError as e:
            logger.e(
                f"Error encrypting private key: {e}",
                service=Service.AUTH.value,
                description=f"Error encrypting private key: {e}",
            )
            raise

    @staticmethod
    def decrypt_key(encrypted_key: str) -> str:
        """
        Decrypts an encrypted private key using AWS KMS.

        :param encrypted_key: The encrypted private key (hex-encoded ciphertext blob).
        :return: The decrypted private key.
        """
        kms_client = boto3.client("kms", region_name="us-east-2")

        try:
            encrypted_key_bytes = bytes.fromhex(encrypted_key)
            response = kms_client.decrypt(CiphertextBlob=encrypted_key_bytes)
            return response["Plaintext"].decode("utf-8")
        except ClientError as e:
            logger.e(
                f"Error decrypting private key: {e}",
                service=Service.AUTH.value,
                description=f"Error decrypting private key: {e}",
            )
            raise

    def transfer(self, **kwargs):
        self.instance.functions.getDeployedProjects(**kwargs).call()

    def withdraw(self, **kwargs):
        """Withdraw funds from the project"""
        self.instance.functions.withdraw(**kwargs).call()


class FactoryContract(Contract):
    def create_organization(self, **kwargs):
        self.instance.functions.createOrganization(**kwargs).call()

    def deploy_project(self, **kwargs):
        self.instance.functions.createProject(**kwargs).call()


class ProjectContract(Contract):
    def claim(self, **kwargs):
        """Vendor to claim funds"""
        self.instance.functions.claimFunds(**kwargs).call()

    def add_vendor(self, **kwargs):
        """Add vendor to the project"""
        self.instance.functions.registerVendor(**kwargs).call()

    def remove_vendor(self, **kwargs):
        """Remove vendor from the project"""
        self.instance.functions.deregisterVendor(**kwargs).call()

    def update_max_spend_limit(self, **kwargs):
        """Update the maximum spend limit"""
        self.instance.functions.updateMaxSpendingLimit(**kwargs).call()
