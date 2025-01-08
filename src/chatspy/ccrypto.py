from enum import Enum
from typing import List, Dict

import boto3
import base58
from web3 import Web3
from solders.keypair import Keypair
from xrpl.wallet import Wallet as XRPWallet
from botocore.exceptions import ClientError
from bitcoin import random_key, privtopub, pubtoaddr

from .utils import logger
from .services import Service

class Chain(Enum):
    BNB = "bnb"         # For BNB & USDT BEP20
    BANTU = "bantu"
    SOLANA = "solana"
    RIPPLE = "ripple"
    BITCOIN = "bitcoin"
    CARDANO = "cardano"
    DOGECOIN = "dogecoin"
    ETHEREUM = "ethereum"   # For USDT ERC20
    BITCOIN_CASH = "bitcoin_cash"

class TokenStandard(Enum):
    ERC20 = "ERC20"
    BEP20 = "BEP20"

class Asset(Enum):
    # Native cryptocurrencies
    BTC = ("BTC", "Bitcoin")
    BCH = ("BCH", "Bitcoin Cash")
    BNB = ("BNB", "Binance Coin")
    XRP = ("XRP", "XRP")
    SOL = ("SOL", "Solana")
    ADA = ("ADA", "Cardano")
    XDN = ("XDN", "Bantu")
    DOGE = ("DOGE", "Dogecoin")
    
    # Tokens
    USDT_ERC20 = ("USDT", "Tether", TokenStandard.ERC20)
    USDT_BEP20 = ("USDT", "Tether", TokenStandard.BEP20)
    
    def __init__(self, symbol, name, token_standard=None):
        self.symbol = symbol
        self.name = name
        self._token_standard = token_standard
    
    @property
    def chain(self) -> Chain:
        """Returns the native chain for this asset"""
        ASSET_TO_CHAIN = {
            self.BTC: Chain.BITCOIN,
            self.BCH: Chain.BITCOIN_CASH,
            self.BNB: Chain.BNB,
            self.XRP: Chain.RIPPLE,
            self.SOL: Chain.SOLANA,
            self.ADA: Chain.CARDANO,
            self.XDN: Chain.BANTU,
            self.DOGE: Chain.DOGECOIN,
            self.USDT_ERC20: Chain.ETHEREUM,
            self.USDT_BEP20: Chain.BNB,
        }
        return ASSET_TO_CHAIN[self]
    
    @property
    def is_token(self) -> bool:
        """Returns True if this is a token rather than a native cryptocurrency"""
        return self._token_standard is not None
    
    @property
    def token_standard(self) -> TokenStandard:
        """Returns the token standard if this is a token"""
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
        self.kms_client = boto3.client("kms", region_name="us-east-2")

    def generate_wallet(self, asset: Asset = Asset.BTC, create_all: bool = False) -> List[Dict[str, str]]:
        """
        Generates wallet(s) appropriate for the specified asset or all supported assets.
        For tokens, generates the appropriate chain's wallet.

        :param asset: The asset to generate a wallet for (e.g., Asset.BTC, Asset.USDT_BEP20)
        :param create_all: If True, generates wallets for all supported assets
        :return: A list of dictionaries with the wallet details
        """
        wallets = []
        
        assets_to_create = list(Asset) if create_all else [asset]
        
        for asset in assets_to_create:
            chain = asset.chain
            public_key = None
            
            match chain:
                case Chain.ETHEREUM | Chain.BNB:  # Both use the same wallet format
                    account = self.w3.eth.account.create()
                    address = account.address
                    private_key = account.key.hex()
                    
                case Chain.BITCOIN | Chain.BITCOIN_CASH:
                    private_key = random_key()
                    public_key = privtopub(private_key)
                    address = pubtoaddr(public_key)
                    
                case Chain.SOLANA:
                    keypair = Keypair()
                    private_key = base58.b58encode(bytes(keypair.secret())).decode('ascii')
                    public_key = str(keypair.pubkey())
                    address = public_key
                    
                case Chain.RIPPLE:
                    wallet = XRPWallet.create()
                    address = wallet.classic_address
                    private_key = wallet.seed
                    
                case Chain.CARDANO:
                    # Cardano wallet generation implementation
                    raise NotImplementedError("Cardano wallet generation not implemented")
                    
                case Chain.BANTU:
                    # Bantu wallet generation implementation
                    raise NotImplementedError("Bantu wallet generation not implemented")
                    
                case Chain.DOGECOIN:
                    # Dogecoin uses the same format as Bitcoin
                    private_key = random_key()
                    public_key = privtopub(private_key)
                    address = pubtoaddr(public_key)
                    
                case _:
                    logger.error(f"Unsupported chain: {chain}")
                    continue
            
            # Encrypt the private key
            encrypted_private_key = self.encrypt_key(private_key)
            encrypted_public_key = self.encrypt_key(public_key) if public_key else None
            
            wallet_data = {
                "asset": asset.symbol,
                "name": asset.name,
                "chain": chain.value,
                "address": address,
                "private_key": encrypted_private_key,
            }
            
            if encrypted_public_key:
                wallet_data["public_key"] = encrypted_public_key
                
            # Add token standard information if this is a token
            if asset.is_token:
                wallet_data["token_standard"] = asset.token_standard.value
                
            wallets.append(wallet_data)
        
        return wallets

    def encrypt_key(self, private_key: str) -> str:
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

        try:
            response = self.kms_client.encrypt(KeyId=KMS_KEY_ID, Plaintext=private_key)
            encrypted_key = response["CiphertextBlob"]
            return encrypted_key.hex()  # Convert to hex string for storage
        except ClientError as e:
            logger.e(
                f"Error encrypting private key: {e}",
                service=Service.AUTH.value,
                description=f"Error encrypting private key: {e}",
            )
            raise

    def decrypt_key(self, encrypted_key: str) -> str:
        """
        Decrypts an encrypted private key using AWS KMS.

        :param encrypted_key: The encrypted private key (hex-encoded ciphertext blob).
        :return: The decrypted private key.
        """
        try:
            encrypted_key_bytes = bytes.fromhex(encrypted_key)  # Convert back to bytes
            response = self.kms_client.decrypt(CiphertextBlob=encrypted_key_bytes)
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