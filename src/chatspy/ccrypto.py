import os
import re
import time
import asyncio
import secrets
import requests
from enum import Enum
from decimal import Decimal
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple, Literal, NoReturn, overload

import boto3
from eth_keys import keys
from eth_account import Account
from eth_utils import decode_hex
from botocore.exceptions import ClientError
from stellar_sdk.exceptions import NotFoundError, AccountNotFoundException
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
from web3 import Web3
from bitcoin import params
from bitcoin import SelectParams
from bitcoin.core import x, b2x, lx
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoin.core.script import CScript, SignatureHash, SIGHASH_ALL
from bitcoin.core import CMutableTransaction, CMutableTxIn, CMutableTxOut
from stellar_sdk.soroban_rpc import GetTransactionResponse, GetTransactionStatus


from . import tasks
from .exceptions import (
    ErrorHandler,
    ContractError,
    SorobanErrorHandler,
    ContractErrorContext,
    FallbackErrorHandler,
    ContractParsingError,
    SimulationErrorHandler,
)
from .services import Service
from .clients import BTCClient, EthereumClient, TokenInfo
from .utils import logger, is_production

STELLAR_USDC_ACCOUNT_ID = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"  # mainnet
TEST_STELLAR_USDC_ACCOUNT_ID = "GBMAXTTNYNTJJCNUKZZBJLQD2ASIGZ3VBJT2HHX272LK7W4FPJCBEAYR"  # testnet.

ETHEREUM_USDT_CONTRACT_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7"  # mainnet
SEPOLIA_ETHEREUM_USDT_CONTRACT_ADDRESS = "0xEEAD57cD7D101FC7ae3635d467175B3f9De68312"  # testnet.


@overload
def get_server() -> Server | SorobanServer: ...


@overload
def get_server(chain: Literal["stellar"]) -> Server | SorobanServer: ...


@overload
def get_server(chain: Literal["bitcoin"]) -> BTCClient: ...


@overload
def get_server(chain: Literal["ethereum"]) -> EthereumClient: ...


def get_server(
    chain: Optional[Literal["bitcoin", "ethereum", "stellar"]] = "stellar",
) -> Server | BTCClient | EthereumClient | None:
    if chain == "stellar":
        return (
            SorobanServer(server_url="https://mainnet.sorobanrpc.com")
            if is_production()
            else Server(horizon_url="https://horizon-testnet.stellar.org")
        )

    elif chain == "bitcoin":
        return BTCClient(
            "https://blockstream.info/api/" if is_production() else "https://blockstream.info/testnet/api/"
        )

    elif chain == "ethereum":
        api_key = os.getenv("ALCHEMY_API_KEY")
        base_url = "https://eth-mainnet.g.alchemy.com/v2" if is_production() else "https://eth-sepolia.g.alchemy.com/v2"
        provider_url = f"{base_url}/{api_key}"
        return EthereumClient(Web3(Web3.HTTPProvider(provider_url)))

    return (
        Server(horizon_url="https://horizon-testnet.stellar.org")
        if not is_production()
        else SorobanServer(server_url="https://mainnet.sorobanrpc.com")
    )


def get_stellar_asset_account_id():
    if is_production():
        return STELLAR_USDC_ACCOUNT_ID

    return TEST_STELLAR_USDC_ACCOUNT_ID


def get_usdt_contract_address():
    if is_production():
        return ETHEREUM_USDT_CONTRACT_ADDRESS

    return SEPOLIA_ETHEREUM_USDT_CONTRACT_ADDRESS


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
    super_admins: list[str]
    admins: list[str]
    ngos: list[str]
    vendors: list[str]
    beneficiaries: list[str]


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
                client = get_server(Chain.BITCOIN.value)
                raw_txs = await asyncio.to_thread(lambda: client.transactions().address(address).call())
                return [
                    {
                        "txid": tx["txid"],
                        "block_height": tx.get("status", {}).get("block_height"),
                        "timestamp": tx.get("status", {}).get("block_time"),
                        "inputs": [vin["prevout"]["scriptpubkey_address"] for vin in tx["vin"] if "prevout" in vin],
                        "outputs": [
                            {"address": vout["scriptpubkey_address"], "value": vout["value"]} for vout in tx["vout"]
                        ],
                        "fee": sum(vin["prevout"]["value"] for vin in tx["vin"] if "prevout" in vin)
                        - sum(vout["value"] for vout in tx["vout"]),
                    }
                    for tx in raw_txs
                ]

            case Chain.ETHEREUM:
                client = get_server("ethereum")
                w3 = client.web3
                txs = await asyncio.to_thread(lambda: w3.eth.get_transactions_by_address(address))

                history = []
                for tx in txs:
                    receipt = await asyncio.to_thread(lambda: w3.eth.get_transaction_receipt(tx["hash"]))
                    block = await asyncio.to_thread(lambda: w3.eth.get_block(tx["blockNumber"]))
                    is_token_transfer = len(tx["input"]) > 10 and receipt and len(receipt["logs"]) > 0
                    history.append(
                        {
                            "to": tx["to"],
                            "from": tx["from"],
                            "hash": tx["hash"].hex(),
                            "value": str(tx["value"]),
                            "gas_price": str(tx["gasPrice"]),
                            "block_number": tx["blockNumber"],
                            "is_token_transfer": is_token_transfer,
                            "status": receipt["status"] if receipt else None,
                            "timestamp": block["timestamp"] if block else None,
                            "gas_used": receipt["gasUsed"] if receipt else None,
                        }
                    )

                # sort by block number (descending)
                history.sort(key=lambda x: x["block_number"] or 0, reverse=True)

                return history

            case Chain.STELLAR:
                server = get_server()
                return await asyncio.to_thread(server.transactions().for_account(address).call)

            case _:
                logger.warning(f"Unkwown chain: {chain}")

    @staticmethod
    async def get_stellar_transaction_operations(transaction_id: str):
        """Fetch transaction operations asynchronously."""
        server = get_server()
        return await asyncio.to_thread(lambda: server.operations().for_transaction(transaction_id).call())

    @staticmethod
    def get_balance(address: str, chain: Chain, token: Optional[TokenInfo] = None):
        match chain:
            case Chain.BITCOIN:
                client = get_server("bitcoin")
                balance_data = client.address(address).call()
                return {
                    "confirmed": balance_data["chain_stats"]["funded_txo_sum"]
                    - balance_data["chain_stats"]["spent_txo_sum"],
                    "unconfirmed": balance_data["mempool_stats"]["funded_txo_sum"]
                    - balance_data["mempool_stats"]["spent_txo_sum"],
                }
            case Chain.ETHEREUM:
                client = get_server(Chain.ETHEREUM.value)
                balance = client.get_balance(address, token)
                return {token.symbol if token else "ETH": balance}

            case Chain.STELLAR:
                server = get_server()
                account = server.accounts().account_id(address).call()
                return account["balances"]
            case _:
                logger.warning(f"Unkwown chain: {chain}")

    @staticmethod
    def transfer_funds(
        chain: Chain,
        source_address: str,
        destination_address: str,
        amount: str,
        source_secret: str,
        token: Optional[TokenInfo] = None,
    ):
        match chain:
            case Chain.STELLAR:
                BASE_FEE = 100  # base fee, in stroops
                server = get_server()
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
                    .set_timeout(18000)  # 5h
                    .append_payment_op(destination=destination_address, asset=asset, amount=amount)
                    .build()
                )
                transaction.sign(source_keypair)
                response = server.submit_transaction(transaction)
                return response

            case Chain.BITCOIN:
                try:
                    client = get_server("bitcoin")

                    amount_sat = int(Decimal(amount) * 10**8)
                    secret = CBitcoinSecret(source_secret)

                    expected_address = str(P2PKHBitcoinAddress.from_pubkey(secret.pub))
                    if expected_address != source_address:
                        raise ValueError("Private key does not match source address")

                    fee_rate = client.get_recommended_fee(target_blocks=3)
                    if not is_production():
                        fee_rate = min(fee_rate, 5)  # max 5 sat/vByte on testnet

                    utxos = client.address(source_address).utxo().call()
                    if not utxos:
                        raise ValueError("No spendable UTXOs found")

                    tx = CMutableTransaction()
                    total_input = 0

                    for utxo in utxos:
                        tx.vin.append(CMutableTxIn(lx(utxo["txid"]), utxo["vout"]))
                        total_input += utxo["value"]
                        if total_input >= amount_sat:  # simple UTXO selection
                            break

                    estimated_size = 10 + (148 * len(tx.vin)) + (34 * 2)  # base + inputs + outputs
                    estimated_fee = int(estimated_size * fee_rate)

                    if total_input < amount_sat + estimated_fee:
                        raise ValueError(
                            f"Insufficient funds. Need {amount_sat + estimated_fee} satoshis, "
                            f"have {total_input} satoshis available"
                        )

                    tx.vout.append(
                        CMutableTxOut(amount_sat, P2PKHBitcoinAddress(destination_address).to_scriptPubKey())
                    )

                    change = total_input - amount_sat - estimated_fee
                    if change > 0:
                        tx.vout.append(CMutableTxOut(change, P2PKHBitcoinAddress(source_address).to_scriptPubKey()))

                    # sign
                    for i, utxo in enumerate(utxos[: len(tx.vin)]):
                        tx.vin[i].scriptSig = CScript(
                            [
                                secret.sign(
                                    SignatureHash(
                                        P2PKHBitcoinAddress(source_address).to_scriptPubKey(), tx, i, SIGHASH_ALL
                                    )
                                )
                                + bytes([SIGHASH_ALL]),
                                secret.pub,
                            ]
                        )

                    # serialize and broadcast
                    raw_tx = bytes(tx).hex()
                    txid = client.submit_transaction(raw_tx)

                    return {
                        "txid": txid,
                        "fee_satoshis": estimated_fee,
                        "size_bytes": len(raw_tx) // 2,
                        "inputs": [{"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in utxos[: len(tx.vin)]],
                        "outputs": [
                            {"address": destination_address, "value": amount_sat},
                            *([{"address": source_address, "value": change}] if change > 0 else []),
                        ],
                    }

                except Exception as e:
                    logger.error(f"Bitcoin transfer failed: {str(e)}", exc_info=True)
                    raise RuntimeError(f"Transaction failed: {str(e)}") from e

            case Chain.ETHEREUM:
                try:
                    client = get_server("ethereum")
                    web3 = client.web3

                    # validate pk
                    account = web3.eth.account.from_key(source_secret)
                    if account.address.lower() != source_address.lower():
                        raise ValueError("Private key does not match source address")

                    nonce = web3.eth.get_transaction_count(source_address, "pending")
                    chain_id = web3.eth.chain_id
                    gas_price = web3.eth.gas_price

                    if token is None:
                        # eth transfer
                        value = web3.to_wei(Decimal(amount), "ether")
                        gas_limit = 21000  # base

                        tx_params = {
                            "to": destination_address,
                            "value": value,
                            "gas": gas_limit,
                            "gasPrice": gas_price,
                            "nonce": nonce,
                            "chainId": chain_id,
                        }
                    else:
                        # erc20 transfer
                        contract = web3.eth.contract(
                            address=token.contract_address,
                            abi=[
                                {
                                    "constant": False,
                                    "inputs": [
                                        {"name": "_to", "type": "address"},
                                        {"name": "_value", "type": "uint256"},
                                    ],
                                    "name": "transfer",
                                    "outputs": [{"name": "", "type": "bool"}],
                                    "type": "function",
                                }
                            ],
                        )
                        amount_wei = int(Decimal(amount) * (10**token.decimals))

                        # build transaction
                        transfer_tx = contract.functions.transfer(destination_address, amount_wei)
                        gas_limit = transfer_tx.estimate_gas({"from": source_address})

                        tx_params = transfer_tx.build_transaction(
                            {"gas": gas_limit, "gasPrice": gas_price, "nonce": nonce, "chainId": chain_id}
                        )

                    # sign and send
                    signed_tx = web3.eth.account.sign_transaction(tx_params, source_secret)
                    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

                    # get fee estimation
                    fee_wei = tx_params["gas"] * tx_params["gasPrice"]

                    return {
                        "nonce": nonce,
                        "fee_wei": fee_wei,
                        "txid": tx_hash.hex(),
                        "gas_limit": tx_params["gas"],
                        "gas_price": tx_params["gasPrice"],
                        "token": token.symbol if token else "ETH",
                    }

                except Exception as e:
                    logger.e(message="Ethereum transfer failed", description=str(e))
                    raise RuntimeError(f"Transaction failed: {str(e)}") from e

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

    @staticmethod
    def wait_for_transaction_confirmation(
        chain: Chain, tx_hash: str, timeout: int = 8, poll_interval: int = 2
    ) -> Optional[bool]:
        """
        Wait for transaction confirmation
        """
        match chain:
            case Chain.BITCOIN:
                try:
                    client = get_server("bitcoin")
                    start_time = time.time()
                    while time.time() - start_time < timeout:
                        try:
                            tx_data = client.transactions(tx_hash).call()
                            if "status" in tx_data and "confirmed" in tx_data["status"]:
                                if tx_data["status"]["confirmed"]:
                                    confirmations = tx_data.get("confirmations", 0)
                                    logger.i(f"BTC tx {tx_hash[:8]} confirmed with {confirmations} confirmations")
                                    return True

                            # if transaction was dropped from mempool
                            mempool = client.transactions().call(params={"txid": tx_hash})
                            if not mempool:
                                logger.w(f"BTC tx {tx_hash[:8]} not found in mempool or blocks")
                                return False

                            time.sleep(poll_interval)
                        except requests.exceptions.RequestException as e:
                            logger.w(f"BTC tx {tx_hash[:8]} check failed (retrying): {str(e)}")
                            time.sleep(poll_interval)
                            continue

                        except Exception as e:
                            logger.e(f"BTC tx {tx_hash[:8]} monitoring error", exc_info=True, description=str(e))
                            return None

                    logger.w(f"BTC tx {tx_hash[:8]} monitoring timeout after {timeout} minutes")
                    return None

                except Exception as e:
                    logger.e(f"BTC tx {tx_hash[:8]} monitoring failed", exc_info=True, description=str(e))
                    return None

            case Chain.ETHEREUM:
                required_confirmations = 1
                try:
                    client = get_server("ethereum")
                    start_time = time.time()
                    while time.time() - start_time < timeout:
                        try:
                            receipt = client.web3.eth.get_transaction_receipt(tx_hash)

                            if receipt is not None:
                                # if successful
                                if receipt.status == 0:
                                    logger.w(f"ETH tx {tx_hash[:8]} failed (status=0)")
                                    return False

                                current_block = client.web3.eth.block_number
                                confirmations = current_block - receipt.blockNumber

                                if confirmations >= required_confirmations:
                                    logger.i(f"ETH tx {tx_hash[:8]} confirmed with {confirmations} blocks")
                                    return True
                                else:
                                    logger.d(
                                        f"ETH tx {tx_hash[:8]} has {confirmations}/{required_confirmations} confirmations"
                                    )

                            # if dropped (not in mempool and no receipt)
                            elif not client.web3.eth.get_transaction(tx_hash):
                                logger.w(f"ETH tx {tx_hash[:8]} not found in mempool")
                                return False

                            time.sleep(poll_interval)
                        except requests.exceptions.RequestException as e:
                            logger.w(f"ETH tx {tx_hash[:8]} check failed (retrying): {str(e)}")
                            time.sleep(poll_interval)
                            continue

                        except Exception as e:
                            logger.e(f"ETH tx {tx_hash[:8]} monitoring error", exc_info=True, description=str(e))
                            return None

                    logger.w(f"ETH tx {tx_hash[:8]} monitoring timeout after {timeout} minutes")
                    return None

                except Exception as e:
                    logger.e(f"ETH tx {tx_hash[:8]} monitoring failed", exc_info=True, description=str(e))
                    return None

            case Chain.STELLAR:
                try:
                    server = get_server()
                    start_time = time.time()
                    while time.time() - start_time < timeout:
                        try:
                            if isinstance(server, Server):
                                tx_data = server.transactions().transaction(transaction_hash=tx_hash).call()
                                if tx_data.get("successful", False):
                                    logger.i(message=f"Stellar tx {tx_hash[:8]} confirmed")
                                    return True

                            else:
                                tx_data: GetTransactionResponse = server.get_transaction(transaction_hash=tx_hash)
                                if tx_data.status == GetTransactionStatus.NOT_FOUND:
                                    logger.i(f"Transaction not found {tx_hash} retrying...")
                                    time.sleep(poll_interval)
                                    continue

                                elif tx_data.status == GetTransactionStatus.SUCCESS:
                                    logger.i(message=f"Stellar tx {tx_hash} confirmed")
                                    return True

                                elif tx_data.status == GetTransactionStatus.FAILED:
                                    logger.e(f"Transaction Failed to succeed: {tx_hash}")
                                    logger.e(tx_data.model_dump())
                                    return False

                            logger.w(message=f"Stellar tx {tx_hash} failed")
                            return False
                        except (NotFoundError, AccountNotFoundException):
                            time.sleep(poll_interval)
                            continue

                        except Exception as e:
                            logger.e(message="Stellar API error", service=Service.PROJECT.value, description=str(e))
                            return None

                    logger.w(message=f"Stellar tx {tx_hash[:8]} timeout", service=Service.PROJECT.value)
                    return None

                except Exception as e:
                    logger.e(message="Stellar monitoring error", description=str(e), service=Service.PROJECT.value)
                    return None

            case _:
                logger.warning(f"Unknown chain: {chain}")
                return None

    @staticmethod
    def is_valid_address(chain: Chain, address: str) -> bool:
        address = address.strip()
        match chain:
            case Chain.BITCOIN:
                network = params.BITCOIN_TESTNET if not is_production() else params.BITCOIN_MAINNET
                try:
                    P2PKHBitcoinAddress(address, network=network)
                    return True
                except Exception:
                    return False

            case Chain.ETHEREUM:
                pattern = r"^0x[a-fA-F0-9]{40}$"
                return re.match(pattern, address) is not None

            case Chain.STELLAR:
                pattern = r"^G[A-Z0-9]{55}$"
                return re.match(pattern, address) is not None

            case _:
                return False

    @staticmethod
    def stellar_is_active(address: str) -> bool:
        try:
            StellarKeypair.from_public_key(address)
        except ValueError:
            return False

        server = get_server()

        try:
            server.accounts().account_id(address).call()
            return True
        except NotFoundError:
            return False

    @staticmethod
    def stellar_has_trustline(address: str, asset: "Asset") -> bool:
        if asset == Asset.USDC:
            issuer = STELLAR_USDC_ACCOUNT_ID

        elif asset == Asset.ChatsUSDC:
            issuer = TEST_STELLAR_USDC_ACCOUNT_ID

        else:
            return False

        server = get_server()
        try:
            account = server.accounts().account_id(address).call()
            for balance in account["balances"]:
                code = balance.get("asset_code", "")
                if code == asset.name and balance["asset_issuer"] == issuer:
                    return True

            return False

        except NotFoundError:
            return False


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
        self, caller: StellarKeypair, project_id: str, allowances: list[Tuple[str, str, int, Optional[int]]]
    ) -> Dict[str, Any]: ...
    def allocate_item_allowances_batch(
        self, caller: StellarKeypair, project_id: str, allowances: list[Tuple[str, str, int, Optional[int]]]
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
    def get_total_cash_allowance(self, beneficiary: str, project_ids: list[str]) -> Dict[str, Any]: ...
    def get_total_item_allowance(self, beneficiary: str, project_ids: list[str]) -> Dict[str, Any]: ...
    def get_roles(self, project_id: str) -> Dict[str, Any]: ...

    @staticmethod
    def generate_wallet(
        asset: Asset = Asset.ChatsUSDC, create_all: bool = False, daemonize_activation: bool = False
    ) -> list[Dict[str, str]]:
        """
        Generates a wallet appropriate for the specified asset. If `create_all` is True, generates wallets for all supported assets.

        :param asset: The asset to generate a wallet for (e.g., Asset.BTC, Asset.USDT)
        :param create_all: Flag to create wallets for all supported assets.
        :return: A list of dictionaries with the wallet details
        """
        logger.info("Generating wallet...")
        if create_all:
            wallets = []
            for asset in Asset:
                wallets.extend(Contract.generate_wallet(asset=asset, daemonize_activation=daemonize_activation))
            return wallets

        # if all([asset == Asset.ChatsUSDC, is_production()]):
        #     asset = Asset.USDC

        chain = asset.chain
        wallets = []

        match chain:
            case Chain.BITCOIN:
                SelectParams("mainnet" if is_production() else "testnet")
                private_key_bytes = secrets.token_bytes(32)
                raw_private_key = b2x(private_key_bytes)
                secret = CBitcoinSecret.from_secret_bytes(x(raw_private_key))
                address = str(P2PKHBitcoinAddress.from_pubkey(secret.pub))
                wallets.append(
                    {
                        "address": address,
                        "chain": chain.value,
                        "asset": asset.symbol,
                        "public_key": address,
                        "display_name": asset.display_name,
                        "private_key": Contract.encrypt_key(str(secret)),
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
                    try:
                        if daemonize_activation:
                            tasks.cactivate_wallet.apply_async(kwargs={"account_private": private_key}, queue="walletQ")
                        else:
                            tasks.activate_wallet(account_private=keypair.secret)

                    except Exception as e:
                        logger.error(f"An error occured while activating wallet: {str(e)}")

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

    def parse(
        self,
        response: soroban_rpc.SimulateTransactionResponse | soroban_rpc.SendTransactionResponse,
        project_id: str = None,
    ):
        """TODO, process different kind of responses depending on the call type (query or invoke) and call corresponding parser method"""
        return response

    def parse_allowances(self, response: soroban_rpc.SimulateTransactionResponse, project_id: str) -> Dict[str, Any]:
        """Parse the response from a contract call."""
        data = {}
        if response.results:
            for result in response.results:
                if result.xdr:
                    sc_value = xdr.SCVal.from_xdr(result.xdr)
                    allowances = self._extract_allowances(sc_value)
                    data["allowances"] = {project_id: allowances}

        if response.events:
            data["events"] = self._parse_events(response.events)

        return data

    def parse_balance(self, response: soroban_rpc.SimulateTransactionResponse):
        data = {"balance": 0}
        if response.results:
            balances = []
            for result in response.results:
                if result.xdr:
                    sc_value = xdr.SCVal.from_xdr(result.xdr)
                    balances.append(scval.to_native(sc_value))

            if balances:
                data["balance"] = sum(balances)

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
        if is_production():
            if not all([network_passphrase, rpc_url]):
                logger.error("RPC URL is required for production environment")
                raise ValueError("RPC URL is required for production environment")

            self.rpc_url = rpc_url
            self.network_passphrase = network_passphrase

        else:
            self.network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
            self.rpc_url = "https://soroban-testnet.stellar.org"

        self.server = SorobanServer(self.rpc_url)
        self.parser = SorbanResultParser()
        self.error_handler = self._create_error_handler()

    def _create_error_handler(self) -> ErrorHandler:
        # chain error handlers
        return SorobanErrorHandler(SimulationErrorHandler(FallbackErrorHandler()))

    def _handle_error(self, context: ContractErrorContext) -> NoReturn:
        """Process error through handler chain"""
        error = self.error_handler.handle(context)
        if not error:
            error = ContractError("Unknown error", context)

        err_desc = error.context.as_dict() if error.context else error

        logger.e(
            message=f"Contract error: {error}",
            description=str(err_desc),
            service=Service.PROJECT.value,
        )
        raise error

    def _parse_response(self, response) -> dict:
        """Parse successful response with error isolation"""
        try:
            return self.parser.parse(response)
        except Exception as e:
            context = ContractErrorContext(function="parse_response", args=[response], raw_error=str(e))

            raise ContractParsingError("Response parsing failed", context) from e

    def _invoke(self, fn_name: str, args: list[xdr.SCVal], signer: StellarKeypair):
        """Generic function invoker"""
        MAX_RETRIES = 1
        retry_count = 0
        context = None

        while retry_count <= MAX_RETRIES:
            try:
                contract_owner_seed = os.getenv("STELLAR_CONTRACT_OWNER_SEED_PHRASE")
                if not contract_owner_seed:
                    raise ValueError("stellar_contract_owner_seed_phrase not set")

                decrypted_seed = Contract.decrypt_key(contract_owner_seed)
                sponsor = StellarKeypair.from_mnemonic_phrase(decrypted_seed)
                signer_account = self.server.load_account(signer.public_key)

                inner_tx = (
                    TransactionBuilder(
                        base_fee=100 * 2,
                        source_account=signer_account,
                        network_passphrase=self.network_passphrase,
                    )
                    .set_timeout(18000)  # 5h
                    .append_invoke_contract_function_op(
                        parameters=args,
                        function_name=fn_name,
                        source=signer.public_key,
                        contract_id=self.contract_id,
                    )
                    .build()
                )

                sim_resp = self.server.simulate_transaction(inner_tx)
                context = ContractErrorContext(
                    function=fn_name, args=args, raw_error=sim_resp.error, simulation_result=sim_resp.results
                )

                if sim_resp.error:
                    self._handle_error(context)

                prepared_tx = self.server.prepare_transaction(inner_tx, sim_resp)
                prepared_tx.sign(signer)

                # sponsor
                fee_bump_tx = TransactionBuilder.build_fee_bump_transaction(
                    fee_source=sponsor.public_key,
                    inner_transaction_envelope=prepared_tx,
                    network_passphrase=self.network_passphrase,
                    base_fee=sim_resp.min_resource_fee + 10_000,
                )
                fee_bump_tx.sign(sponsor)

                # send
                resp = self.server.send_transaction(fee_bump_tx)
                return self._parse_response(resp)

            except AccountNotFoundException as e:
                if retry_count >= MAX_RETRIES:
                    raise AccountNotFoundException(
                        f"{signer.public_key} - Failed to auto activate wallet - retries failed"
                    )

                logger.w(message="AccountNotFoundException: Account not found error occurred", description=str(e))
                logger.i(message=f"Activating account: {signer.public_key}")

                response: dict[str, Any] | None = tasks.activate_wallet(account_private=signer.secret)

                if not response:
                    raise AccountNotFoundException(f"{signer.public_key} - Failed to auto activate wallet")

                hash = response.get("hash", None)
                if not hash:
                    raise AccountNotFoundException(f"{signer.public_key} - Failed to auto activate wallet - {response}")

                success: bool | None = Asset.wait_for_transaction_confirmation(chain=Chain.STELLAR, tx_hash=hash)

                if not success:
                    raise AccountNotFoundException(
                        f"{signer.public_key} - Failed to auto activate wallet - {response} - L3"
                    )

                retry_count += 1
                continue

            except Exception as e:
                if not context:
                    context = ContractErrorContext(function=fn_name, args=args, raw_error=str(e))

                self._handle_error(context)

    async def _query(
        self,
        function_name: str,
        args: list,
        caller,
        project_id,
        result_type: Literal["allowances", "balance"] = "allowances",
    ) -> Dict[str, Any]:
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
        if result_type == "allowances":
            return self.parser.parse_allowances(response, project_id)

        elif result_type == "balance":
            return self.parser.parse_balance(response)

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
        amount: int,
        allowee: str,
        currency: str,
        project_id: str,
        caller_secret: str,
        expiry: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create or update a cash allowance"""
        caller = StellarKeypair.from_secret(caller_secret)
        args = [
            scval.to_address(caller.public_key),
            scval.to_string(project_id),
            scval.to_address(allowee),
            scval.to_uint64(int(amount * (10**7))),
            scval.to_string(currency),
            scval.to_timepoint(expiry) if expiry else scval.to_void(),
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
        allowances: list[Tuple[str, str, int, Optional[int]]],
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
        self, caller: StellarKeypair, project_id: str, allowances: list[Tuple[str, str, int, Optional[int]]]
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
        self, caller_secret: StellarKeypair, project_id: str, new_allowee: str, currency: str, amount: int
    ) -> Dict[str, Any]:
        """Transfer cash allowance between beneficiaries"""
        caller = StellarKeypair.from_secret(caller_secret)
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

    def get_cash_allowance(self, project_id: str, allowee: str, currency: str) -> Allowance:
        """Retrieve cash allowance details"""
        key = xdr.LedgerKey.contract_data(
            contract_id=xdr.ScAddress.from_string(self.contract_id),
            key=scval.from_symbol("cash"),
            durability=xdr.ContractDataDurability.PERSISTENT,
        )
        entry = self.server.get_ledger_entry(key)
        return Allowance(amount=entry.data.get("amount", 0), expiry=entry.data.get("expiry"))

    async def get_total_cash_allowance(self, beneficiary: str, caller: StellarKeypair, project_ids: list[str]) -> int:
        projects = [scval.to_string(id) for id in project_ids]
        args = [scval.to_address(beneficiary), scval.to_vec(projects)]
        return await self._query(
            "get_total_cash_allowance", args, caller, project_id=project_ids[0], result_type="balance"
        )

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

    def claim_cash_allowance(
        self, caller_secret: StellarKeypair, project_id: str, currency: str, amount: int, vendor: Optional[str]
    ) -> Dict[str, Any]:
        """
        Claim cash allowance by beneficiaries

        Vendor is optional, the beneficiary's allowance is debited and the vendor is credited if vendor is supplied, otherwise the beneficiary gets debited and that's it.
        """
        caller_keypair = StellarKeypair.from_secret(caller_secret)
        return self._invoke(
            "claim_cash_allowance",
            [
                scval.to_address(caller_keypair.public_key),
                scval.to_string(project_id),
                scval.to_string(currency),
                scval.to_uint64(int(amount * (10**7))),
                scval.to_address(vendor) if vendor else scval.to_void(),
            ],
            caller_keypair,
        )

    def redeem_cash_claims(
        self, vendor_secret: StellarKeypair, project_id: str, currency: str, amount: int
    ) -> Dict[str, Any]:
        """
        Claim cash allowance by beneficiaries
        """

        caller_keypair = StellarKeypair.from_secret(vendor_secret)
        return self._invoke(
            "redeem_cash_claims",
            [
                scval.to_address(caller_keypair.public_key),
                scval.to_string(project_id),
                scval.to_string(currency),
                scval.to_uint64(int(amount * (10**7))),
            ],
            caller_keypair,
        )
