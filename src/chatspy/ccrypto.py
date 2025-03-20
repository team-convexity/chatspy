import os
import asyncio
import secrets
from enum import Enum
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

import boto3
from eth_keys import keys
from eth_account import Account
from eth_utils import decode_hex
from botocore.exceptions import ClientError
from bitcoin import random_key, privtopub, pubtoaddr
from stellar_sdk import (
    xdr,
    scval,
    Server,
    Network,
    Address,
    soroban_rpc,
    SorobanServer,
    TransactionBuilder,
    Asset as StellarAsset,
    Keypair as StellarKeypair,
)

from . import tasks
from .services import Service
from .utils import logger, is_production

STELLAR_USDC_ACCOUNT_ID = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"  # mainnet
TEST_STELLAR_USDC_ACCOUNT_ID = "GBMAXTTNYNTJJCNUKZZBJLQD2ASIGZ3VBJT2HHX272LK7W4FPJCBEAYR"  # testnet.


def get_stellar_asset_account_id():
    if is_production():
        return STELLAR_USDC_ACCOUNT_ID

    return TEST_STELLAR_USDC_ACCOUNT_ID


def get_stellar_asset():
    STELLAR_USDC_ACCOUNT_ID = get_stellar_asset_account_id()
    if not is_production():
        return StellarAsset("ChatsUSDC", TEST_STELLAR_USDC_ACCOUNT_ID)

    return StellarAsset("USDC", STELLAR_USDC_ACCOUNT_ID)


@dataclass
class Allowance:
    amount: int
    expiry: Optional[int]


@dataclass
class Roles:
    super_admins: List[str]
    admins: List[str]
    ngos: List[str]
    vendors: List[str]
    beneficiaries: List[str]


class Chain(Enum):
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    STELLAR = "stellar"


class TokenStandard(Enum):
    ERC20 = "ERC20"


class Asset(Enum):
    BTC = ("BTC", "Bitcoin")
    USDC = ("USDC", "USD Coin")
    ETH = ("ETH", "Ethereum Native")
    ChatsUSDC = ("ChatsUSDC", "Chats USD Coin")
    USDT = ("USDT", "Tether (ERC20)", TokenStandard.ERC20)

    def __init__(self, symbol, display_name, token_standard=None):
        self.symbol = symbol
        self.display_name = display_name
        self._token_standard = token_standard

    @staticmethod
    async def get_transaction_history(address: str, chain: Chain):
        match chain:
            case Chain.BITCOIN:
                return []

            case Chain.ETHEREUM:
                return []

            case Chain.STELLAR:
                subdomain = "horizon." if is_production() else "horizon-testnet."
                server = Server(horizon_url=f"https://{subdomain}stellar.org")
                return await asyncio.to_thread(server.transactions().for_account(address).call)

            case _:
                logger.warning(f"Unkwown chain: {chain}")

    @staticmethod
    async def get_stellar_transaction_operations(transaction_id: str):
        """Fetch transaction operations asynchronously."""
        subdomain = "horizon." if is_production() else "horizon-testnet."
        server = Server(horizon_url=f"https://{subdomain}stellar.org")
        return await asyncio.to_thread(lambda: server.operations().for_transaction(transaction_id).call())

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
                asset = get_stellar_asset()

                transaction = (
                    TransactionBuilder(
                        source_account=source_account,
                        network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE
                        if is_production()
                        else Network.TESTNET_NETWORK_PASSPHRASE,
                        base_fee=BASE_FEE,
                    )
                    .append_payment_op(destination=destination_address, asset=asset, amount=amount)
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
            self.ChatsUSDC: Chain.STELLAR,
            self.ETH: Chain.ETHEREUM,
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
    """
    Base class for interacting with smart contracts.
    """

    def initialize(self, owner: StellarKeypair) -> Dict[str, Any]: ...
    def add_role(self, caller: StellarKeypair, project_id: str, role: str, new_member: str) -> Dict[str, Any]: ...
    def remove_role(self, caller: StellarKeypair, project_id: str, role: str, member: str) -> Dict[str, Any]: ...
    def pause_contract(self, caller: StellarKeypair) -> Dict[str, Any]: ...
    def unpause_contract(self, caller: StellarKeypair) -> Dict[str, Any]: ...
    def allocate_cash_allowance(
        self, caller: StellarKeypair, project_id: str, allowee: str, amount: int, currency: str, expiry: Optional[int]
    ) -> Dict[str, Any]: ...
    def claim_cash_allowance(
        self, caller: StellarKeypair, project_id: str, currency: str, amount: int, vendor: Optional[str]
    ) -> Dict[str, Any]: ...
    def allocate_item_allowance(
        self, caller: StellarKeypair, project_id: str, allowee: str, item_id: str, quantity: int, expiry: Optional[int]
    ) -> Dict[str, Any]: ...
    def claim_item_allowance(
        self, caller: StellarKeypair, vendor: str, project_id: str, item_id: str, quantity: int
    ) -> Dict[str, Any]: ...
    def allocate_cash_allowances_batch(
        self, caller: StellarKeypair, project_id: str, allowances: List[Tuple[str, str, int, Optional[int]]]
    ) -> Dict[str, Any]: ...
    def allocate_item_allowances_batch(
        self, caller: StellarKeypair, project_id: str, allowances: List[Tuple[str, str, int, Optional[int]]]
    ) -> Dict[str, Any]: ...
    def transfer_cash_allowance(
        self, caller: StellarKeypair, project_id: str, new_allowee: str, currency: str, amount: int
    ) -> Dict[str, Any]: ...
    def transfer_item_allowance(
        self, caller: StellarKeypair, project_id: str, new_allowee: str, item_id: str, quantity: int
    ) -> Dict[str, Any]: ...
    def redeem_item_claims(
        self, vendor: StellarKeypair, project_id: Optional[str], item_id: str, quantity: int
    ) -> Dict[str, Any]: ...
    def redeem_cash_claims(
        self, vendor: StellarKeypair, project_id: Optional[str], currency: str, amount: int
    ) -> Dict[str, Any]: ...
    def get_cash_allowance(self, project_id: str, allowee: str, currency: str) -> Dict[str, Any]: ...
    def get_item_allowance(self, project_id: str, allowee: str, item_id: str) -> Dict[str, Any]: ...
    def get_all_cash_allowances(self, project_id: str) -> Dict[str, Any]: ...
    def get_all_item_allowances(self, project_id: str) -> Dict[str, Any]: ...
    def get_total_cash_allowance(self, beneficiary: str, project_ids: List[str]) -> Dict[str, Any]: ...
    def get_total_item_allowance(self, beneficiary: str, project_ids: List[str]) -> Dict[str, Any]: ...
    def get_roles(self, project_id: str) -> Dict[str, Any]: ...

    @staticmethod
    def generate_wallet(asset: Asset = Asset.ChatsUSDC, create_all: bool = False) -> List[Dict[str, str]]:
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
                if asset == Asset.USDC or asset == Asset.ChatsUSDC:
                    keypair = StellarKeypair.random()
                    private_key = Contract.encrypt_key(keypair.secret)
                    public_key = keypair.public_key
                    address = public_key

                    wallets.append(
                        {
                            "address": address,
                            "chain": chain.value,
                            "asset": asset.symbol,
                            "display_name": asset.display_name,
                            "private_key": private_key,
                            "public_key": public_key,
                        }
                    )
                    tasks.activate_wallet.apply_async(kwargs={"account_private": private_key}, queue="walletQ")

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


class SorbanResultParser:
    """
    A class to parse results returned by Soroban smart contract queries.
    """

    def parse_allowances(self, response: soroban_rpc.SimulateTransactionResponse, project_id: str) -> Dict[str, Any]:
        """Parse the response from a contract call."""
        data = {}
        if response.results:
            for result in response.results:
                if result.xdr:
                    sc_val = xdr.SCVal.from_xdr(result.xdr)
                    allowances = self._extract_allowances(sc_val)
                    data["allowances"] = {project_id: allowances}

        if response.events:
            data["events"] = self._parse_events(response.events)

        return data

    def _extract_allowances(self, sc_val: xdr.SCVal) -> Dict[str, Any]:
        """Extract allowances from the SCVal"""
        allowances = {}
        if sc_val.type == xdr.SCValType.SCV_MAP:
            for map_entry in sc_val.map.sc_map:
                key: list[Address, str] = scval.to_native(map_entry.key)
                value = scval.to_native(map_entry.val)
                allowances[key[0].address] = value

        return allowances

    def _parse_events(self, events: list) -> list:
        """Parse events emitted by the contract."""
        decoded_events = []
        for event in events:
            decoded_event = xdr.SCVal.from_xdr(event)
            decoded_events.append(decoded_event)
        return decoded_events


class StellarProjectContract(Contract):
    def __init__(
        self,
        contract_id: str,
        network_passphrase: Optional[str] = None,
        rpc_url: Optional[str] = None,
    ):
        self.contract_id = contract_id
        self.network_passphrase = network_passphrase
        if is_production() and not all([network_passphrase, rpc_url]):
            logger.error("RPC URL is required for production environment")
            raise ValueError("RPC URL is required for production environment")

        else:
            self.network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
            self.rpc_url = "https://soroban-testnet.stellar.org"

        self.server = SorobanServer(self.rpc_url)
        self.parser = SorbanResultParser()

    def _invoke(self, fn_name: str, args: list[xdr.SCVal], signer: StellarKeypair):
        """Generic function invoker"""
        source = self.server.load_account(signer.public_key)
        tx = (
            TransactionBuilder(source, self.network_passphrase)
            .add_time_bounds(0, 0)
            .append_invoke_contract_function_op(contract_id=self.contract_id, function_name=fn_name, parameters=args)
            .build()
        )

        sim = self.server.simulate_transaction(tx)
        if sim.error:
            raise Exception(f"Simulation failed: {sim.error}")

        prepared_tx = self.server.prepare_transaction(tx, sim)

        prepared_tx.sign(signer)
        response = self.server.send_transaction(prepared_tx)

        return response

    async def _query(self, function_name: str, args: list, caller, project_id) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        trx_args = (
            TransactionBuilder(
                base_fee=100,
                source_account=caller,
                network_passphrase=self.network_passphrase,
            )
            .add_time_bounds(0, 0)
            .append_invoke_contract_function_op(
                parameters=args,
                function_name=function_name,
                contract_id=self.contract_id,
            )
            .build()
        )
        response = await loop.run_in_executor(None, self.server.simulate_transaction, trx_args)
        return self.parser.parse_allowances(response, project_id)

    def initialize(self, owner: StellarKeypair) -> Dict[str, Any]:
        """Initialize the contract with an owner address"""
        return self._invoke("initialize", [scval.to_address(owner.public_key)], owner)

    def pause_contract(self, caller: StellarKeypair) -> Dict[str, Any]:
        """Pause all contract operations"""
        return self._invoke("pause_contract", [Address(caller.public_key).to_scval()], caller)

    def unpause_contract(self, caller: StellarKeypair) -> Dict[str, Any]:
        """Resume contract operations"""
        return self._invoke("unpause_contract", [Address(caller.public_key).to_scval()], caller)

    def add_role(self, caller: StellarKeypair, project_id: str, role: str, member: str) -> Dict[str, Any]:
        """Add member to a specific project role"""
        return self._invoke(
            "add_role",
            [
                scval.to_address(caller.public_key),
                scval.to_string(project_id),
                scval.to_string(role),
                scval.to_address(member),
            ],
            caller,
        )

    def remove_role(self, caller: StellarKeypair, project_id: str, role: str, member: str) -> Dict[str, Any]:
        """Remove member from a project role"""
        return self._invoke(
            "remove_role",
            [
                Address(caller.public_key).to_scval(),
                scval.from_string(project_id),
                scval.from_string(role),
                Address(member).to_scval(),
            ],
            caller,
        )

    def allocate_cash_allowance(
        self,
        caller: StellarKeypair,
        project_id: str,
        allowee: str,
        amount: int,
        currency: str,
        expiry: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create or update a cash allowance"""
        args = [
            Address(caller.public_key).to_scval(),
            scval.from_string(project_id),
            Address(allowee).to_scval(),
            scval.from_u64(amount),
            scval.from_string(currency),
            scval.from_u64(expiry) if expiry else scval.from_void(),
        ]
        return self._invoke("allocate_cash_allowance", args, caller)

    def allocate_item_allowance(
        self,
        caller: StellarKeypair,
        project_id: str,
        allowee: str,
        item_id: str,
        quantity: int,
        expiry: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create or update an item allowance"""
        args = [
            Address(caller.public_key).to_scval(),
            scval.from_string(project_id),
            Address(allowee).to_scval(),
            scval.from_string(item_id),
            scval.from_u64(quantity),
            scval.from_u64(expiry) if expiry else scval.from_void(),
        ]
        return self._invoke("allocate_item_allowance", args, caller)

    def allocate_cash_allowances_batch(
        self,
        project_id: str,
        caller_secret: str,
        allowances: List[Tuple[str, str, int, Optional[int]]],
    ) -> Dict[str, Any]:
        """Batch create/update cash allowances"""

        caller = StellarKeypair.from_secret(caller_secret)
        allowances_vec = scval.to_vec(
            [
                scval.to_vec(
                    [
                        scval.to_address(allowee),
                        scval.to_string(currency),
                        scval.to_uint64(int(amount * (10**7))),
                        scval.to_timepoint(expiry) if expiry else scval.to_void(),
                    ]
                )
                for allowee, currency, amount, expiry in allowances
            ]
        )

        args = [scval.to_address(caller.public_key), scval.to_string(project_id), allowances_vec]

        return self._invoke("allocate_cash_allowances_batch", args, caller)

    def allocate_item_allowances_batch(
        self, caller: StellarKeypair, project_id: str, allowances: List[Tuple[str, str, int, Optional[int]]]
    ) -> Dict[str, Any]:
        """Batch create/update item allowances"""
        args = [scval.from_string(project_id)]
        args = [project_id]
        for allowee, item_id, quantity, expiry in allowances:
            args.extend(
                [
                    Address(allowee),
                    item_id,
                    quantity,
                    expiry if expiry else None,
                ]
            )
        return self._invoke("allocate_item_allowances_batch", args, caller)

    def transfer_cash_allowance(
        self, caller: StellarKeypair, project_id: str, new_allowee: str, currency: str, amount: int
    ) -> Dict[str, Any]:
        """Transfer cash allowance between beneficiaries"""
        return self._invoke(
            "transfer_cash_allowance",
            [
                scval.to_address(caller.public_key),
                scval.to_string(project_id),
                scval.to_address(new_allowee),
                scval.to_string(currency),
                scval.to_uint64(int(amount * (10**7))),
            ],
            caller,
        )

    def transfer_item_allowance(
        self, caller: StellarKeypair, project_id: str, new_allowee: str, item_id: str, quantity: int
    ) -> Dict[str, Any]:
        """Transfer item allowance between beneficiaries"""
        return self._invoke(
            "transfer_item_allowance",
            [
                Address(caller.public_key).to_scval(),
                scval.from_string(project_id),
                Address(new_allowee).to_scval(),
                scval.from_string(item_id),
                scval.from_u64(quantity),
            ],
            caller,
        )

    def redeem_item_claims(
        self, vendor: StellarKeypair, project_id: Optional[str], item_id: str, quantity: int
    ) -> Dict[str, Any]:
        """Redeem vendor item claims"""
        args = [
            Address(vendor.public_key).to_scval(),
            scval.from_string(project_id) if project_id else scval.from_void(),
            scval.from_string(item_id),
            scval.from_u64(quantity),
        ]
        return self._invoke("redeem_item_claims", args, vendor)

    def redeem_cash_claims(
        self, vendor: StellarKeypair, project_id: Optional[str], currency: str, amount: int
    ) -> Dict[str, Any]:
        """Redeem vendor cash claims"""
        args = [
            Address(vendor.public_key).to_scval(),
            scval.from_string(project_id) if project_id else scval.from_void(),
            scval.from_string(currency),
            scval.from_u64(amount),
        ]
        return self._invoke("redeem_cash_claims", args, vendor)

    def get_cash_allowance(self, project_id: str, allowee: str, currency: str) -> Allowance:
        """Retrieve cash allowance details"""
        key = xdr.LedgerKey.contract_data(
            contract_id=xdr.ScAddress.from_string(self.contract_id),
            key=scval.from_symbol("cash"),
            durability=xdr.ContractDataDurability.PERSISTENT,
        )
        entry = self.server.get_ledger_entry(key)
        return Allowance(amount=entry.data.get("amount", 0), expiry=entry.data.get("expiry"))

    def get_total_cash_allowance(self, beneficiary: str, project_ids: List[str]) -> int:
        caller = StellarKeypair.from_public_key(beneficiary)
        args = [Address(beneficiary), scval.to_vec(project_ids)]
        return self._query("get_total_cash_allowance", args, caller)

    def get_roles(self, project_id: str) -> Roles:
        """Retrieve role assignments for a project"""

        key = xdr.LedgerKey.contract_data(
            contract_id=xdr.ScAddress.from_string(self.contract_id),
            key=scval.from_symbol("roles"),
            durability=xdr.ContractDataDurability.PERSISTENT,
        )
        entry = self.server.get_ledger_entry(key)
        return Roles(
            super_admins=entry.data.get("super_admins", []),
            admins=entry.data.get("admins", []),
            ngos=entry.data.get("ngos", []),
            vendors=entry.data.get("vendors", []),
            beneficiaries=entry.data.get("beneficiaries", []),
        )

    async def get_all_cash_allowances(self, project_id: str, caller) -> Dict[str, Any]:
        args = [scval.to_string(project_id)]
        return await self._query("get_all_cash_allowances", args, caller, project_id)
