import re
import os
import sys
import time
import uuid
import json
import hmac
import codecs
import logging
import hashlib
import tempfile
import threading
from enum import Enum, auto
from decimal import Decimal
from collections import defaultdict
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Literal, Optional, Union, Dict, Any

import redis
import requests
from requests import request
from django.db import models
from django.conf import settings
from django.db import transaction
from .schemas import ErrorResponse
from django.core.cache import cache
from django.db.models import ImageField
from django.core.serializers import serialize
from redis.cluster import RedisCluster, ClusterNode
from kafka import KafkaProducer, KafkaConsumer, errors as KafkaErrors

from web3 import Web3
from .services import Service
from .exceptions import PaymentError
from .utils import Logger, is_production
from .schemas import IdentityVerificationSchema
from web3.types import TxParams, TxReceipt, HexStr

logger = Logger.get_logger()


class KafkaEvent(Enum):
    UserCreated = "UserCreated"
    DonorInvited = "DonorInvited"
    ProjectCreated = "ProjectCreated"
    SendNotification = "SendNotification"
    UserProfileUpdated = "UserProfileUpdated"
    OrganizationCreated = "OrganizationCreated"
    BroadcastTransaction = "BroadcastTransaction"
    VendorKycVerification = "VendorKycVerification"
    OrganizationUpdated = "OrganizationUpdated"
    OrganizationDeleted = "OrganizationDeleted"
    UserDeleted = "UserDeleted"


class ClientType(Enum):
    KAFKA = "kafka"
    PRODUCER = "producer"
    ACCOUNT = "account"
    REDIS = "redis"
    IDENTITY = "identity"
    STELLAR_CONTRACT = "stellar_contract"
    CURRENCY_CONVERTER_CLIENT = "currency_converter"
    PAYSTACK_PAYMENT_CLIENT = "paystack_payment_client"
    KORA_PAYMENT_CLIENT = "kora_payment_client"


class ServiceClient:
    def __init__(self, service: Service):
        # self.pubkey = Secret.get_service_key(service=service)
        self.base_url = self.get_service_base_url(service=service)

    def get_service_base_url(self, service: Service):
        """
        return a base url for a service depending on the currently running environment.

        Debug Off (k8s):
            http://<service-name>.<namespace>.svc.cluster.local:<port>/
        Debug On (Docker Compose):
            http://<service-name>:<port>/
        """

        namespace = "default"
        port = os.getenv(f"{service.name}_PORT")
        if not port:
            logger.w(f"cannot find port number for {service.name}")
            raise Exception(f"cannot find port number for {service.name}")

        if settings.DEBUG:
            return f"http://{service.name.lower()}:{port}"

        return f"http://{service.name.lower()}.{namespace}.svc.cluster.local:{port}"

    def get(self, endpoint: str, params: dict = {}):
        url = f"{self.base_url}{endpoint}"
        return request(url=url, method="get", params=params)

    def post(self, endpoint: str, payload: dict = {}):
        url = f"{self.base_url}{endpoint}"
        return request(url=url, method="post", data=payload)


class AccountClient(ServiceClient):
    """
    Client for interfacing the accounting service.
    """

    def create_accounts(self, payload: dict):
        return self.post(endpoint="/create-account/", payload=payload)


class NotificationChannel(Enum):
    SMS = auto()
    EMAIL = auto()
    PUSH = auto()
    IN_APP = auto()
    SLACK = auto()


@dataclass
class NotificationPayload:
    """
    comprehensive notification payload supporting multiple channels
    """

    # recipient auth user IDs or a list of Email strings
    recipients: list[str]  # recipicients' auth user IDs or email strings.

    # notification content
    # when sending SMS, the notification service will only use title (discarding body)
    title: str

    # channel-specific configurations
    channels: list[NotificationChannel]

    # metadata and routing
    priority: int = 3  # default priority (1-5 scale, 1 being highest)

    body: Optional[str] = None

    # template for rendering; Only used for Email channel
    template_name: Optional[str] = None
    template_context: Optional[dict] = None

    # optional advanced routing
    expiration: Optional[datetime] = None
    delay_until: Optional[datetime] = None

    def as_dict(self) -> Dict:
        """
        return a dict version of the payload.
        """
        payload_dict = asdict(self)

        # convert channels to their values
        payload_dict["channels"] = [channel.value for channel in self.channels]

        # handle datetime serialization
        for date_field in ["delay_until", "expiration"]:
            if payload_dict.get(date_field):
                payload_dict[date_field] = payload_dict[date_field].isoformat()

        # remove None values
        return {k: v for k, v in payload_dict.items() if v is not None}


class NotificationClient(ServiceClient):
    def send_notification(
        self,
        recipient_id,
        notification_type: Literal["email", "sms", "push"],
        body: str,
        subject: str,
        email_template: str = None,
    ):
        """
        Send notication to users (sms, email, and push)

        Args:
            notification_type (Literal[&#39;email&#39;, &#39;sms&#39;, &#39;push&#39;]): The notification type.
            body (str): The notication message (email body if email).
            subject (str): The subject of the notification. Ignored if message notification_type is 'sms'.
            email_template (str, optional): Template name (if the email is templated). Defaults to None.
        """
        payload = {"recipient": recipient_id}

        match notification_type:
            case "email":
                payload.update({"subject": subject, "body": body, "template": email_template})
            case "sms":
                payload.update({"message": body})
            case "push":
                payload.update({"subject": subject, "body": body})

        self.post("/send-notification/", payload=payload)


class RedisClient:
    """
    Base class for Redis Cluster connection
    """

    def __init__(
        self,
        startup_nodes: list[ClusterNode],
        decode_responses: bool = True,
        skip_full_coverage_check: bool = True,
        password=None,
        cluster_enabled=False,
    ):
        """
        Initialize Redis Cluster connection

        :param startup_nodes: list of initial cluster nodes
        :param decode_responses: Convert responses to strings
        :param skip_full_coverage_check: Helps with partial cluster setups
        :password: password
        :cluster_enabled: whether we are connecting as a cluster or not
        """

        if cluster_enabled:
            self.client = RedisCluster(
                password=password,
                startup_nodes=startup_nodes,
                decode_responses=decode_responses,
                skip_full_coverage_check=skip_full_coverage_check,
            )

        cluster = startup_nodes[0]
        self.client = redis.Redis(host=cluster.host, port=cluster.port, password=password, db=0)

        try:
            self.client.ping()
            logger.i(f"[Redis] Successfully connected to {cluster.host}")

        except redis.exceptions.ConnectionError as e:
            logger.e(f"[Redis] Cannot establish connection to Redis: {e}")
            raise

    def set(self, key: str, value: Union[str, int, float], expire: Optional[int] = None) -> bool:
        """
        Set a key-value pair in the cluster

        :param key: Redis key
        :param value: Value to store
        :param expire: Optional expiration time in seconds
        :return: Boolean indicating success
        """
        try:
            value = json.dumps(value)
            if expire:
                return self.client.setex(key, expire, value)
            return self.client.json(key, value)
        except Exception as e:
            logger.i(f"Error setting key {key}: {e}")
            return False

    def get(self, key: str) -> Optional[str]:
        """
        Get a value from the cluster

        :param key: Redis key to retrieve
        :return: Value or None if key doesn't exist
        """
        try:
            return self.client.get(key)
        except Exception as e:
            logger.i(f"Error getting key {key}: {e}")
            return None

    def delete(self, key: str) -> int:
        """
        Delete a key from the cluster

        :param key: Key to delete
        :return: Number of keys deleted
        """
        try:
            return self.client.delete(key)
        except Exception as e:
            logger.i(f"Error deleting key {key}: {e}")
            return 0


class SafeConsumer(KafkaConsumer):
    def __init__(self, *topics, message_handler=None, **kwargs):
        super().__init__(*topics, **kwargs)
        assert message_handler is not None, "message_handler cannot be None"
        self.message_handler = message_handler

    def consume_messages(self):
        logger.i("[Kafka] Consumer Listeners: Active")
        for message in self:
            self._safe_process(message)

    def _safe_process(self, message):
        try:
            with transaction.atomic():
                self.message_handler(message)
                # commit offset only after successful processing
                self.commit()
        except Exception as e:
            logger.e(f"[SafeConsumer] Message processing error: {e}")
            # self.seek() # seek_to_current
            # self.commit()


class BufferedProducer(KafkaProducer):
    """
    BufferedProducer is a subclass of KafkaProducer that buffers events before dispatching them to Kafka.

    Each entry contains a "leader" event and a list of "follower" events.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # buffer per record key
        self.event_buffer = defaultdict(lambda: {"leader": None, "followers": []})

    def add_buffer(self, key: str, value: dict, topic: str, leader: bool = False):
        """
        Add an event to the buffer.

        :param leader (boolean): Whether this is the leader event.
        :param key: The partition key (e.g., user_id).
        :param value: The event payload (dict).
        :param topic: The Kafka topic associated with the event.
        """
        if key not in self.event_buffer:
            self.event_buffer[key] = {"leader": None, "followers": []}

        event = {
            "key": key,
            "value": value,
            "topic": topic,
        }

        if leader:
            if self.event_buffer[key]["leader"] is not None:
                raise ValueError(f"A leader event is already buffered for key: {key}")
            self.event_buffer[key]["leader"] = event
            return

        self.event_buffer[key]["followers"].append(event)

    def dispatch_buffers(self, key):
        """
        Dispatch buffered events for a specific key.

        :param key: The partition key (e.g., user_id).
        """
        buffer = self.event_buffer[key]

        # dispatch leader event first
        if buffer["leader"]:
            essential_event = buffer["leader"]
            self.send(essential_event["topic"], key=essential_event["key"], value=essential_event["value"])

            # ensure the leader event is sent
            self.flush()
            # clear leader event after dispatch
            buffer["leader"] = None

        # dispatch non-leader events
        for event in buffer["followers"]:
            self.send(event["topic"], key=event["key"], value=event["value"])
        # ensure all events are sent
        self.flush()

        # clear the buffer for this key
        del self.event_buffer[key]

    def clear_buffer(self, key):
        """
        clear the buffer for a specific key without dispatching events.

        :param key: the partition key (e.g., user_id).
        """
        if key in self.event_buffer:
            del self.event_buffer[key]


class KafkaClient:
    def __init__(self, bootstrap_servers):
        """
        Kafka Client for interacting with AWS MSK using TLS Authentication.

        Parameters:
        - bootstrap_servers (str): Comma-separated list of Kafka bootstrap servers.
        """

        # retrieve certificate strings from environment variables
        access_key = os.getenv("KAFKA_ACCESS_KEY")
        access_cert = os.getenv("KAFKA_ACCESS_CERTIFICATE")
        ca_cert = os.getenv("KAFKA_CA_CERTIFICATE")
        password = os.getenv("KAFKA_AUTH_PASSWORD")

        if not access_key or not access_cert or not ca_cert:
            raise ValueError(
                "[Kafka] Certificate strings must be set in environment variables: ACCESS_KEY, ACCESS_CERT, CA_CERT"
            )

        # write the certificate strings to temporary files
        self.temp_files = []
        ssl_keyfile = self._write_to_temp_file(access_key, "key")
        ssl_certfile = self._write_to_temp_file(access_cert, "cert")
        ssl_cafile = self._write_to_temp_file(ca_cert, "ca")

        # common configuration for TLS Authentication
        self.common_config = {
            "security_protocol": "SSL",
            "ssl_password": password,
            "ssl_cafile": ssl_cafile,
            "ssl_keyfile": ssl_keyfile,
            "ssl_certfile": ssl_certfile,
            "bootstrap_servers": bootstrap_servers,
        }
        # write temp file names/dir to a text file for clean up later.
        with open("/tmp/chats-events-log.txt", "w") as log_file:
            json.dump(self.temp_files, log_file, indent=4)

        self._producer = None
        self._consumer = None

    def _write_to_temp_file(self, content, suffix):
        """
        Write content to a temporary file and return the file path.

        Parameters:
        - content (str): Content to write to the file.
        - suffix (str): Suffix for the temporary file.

        Returns:
        - str: Path to the temporary file.
        """
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f".{suffix}")
        # convert escaped newlines (\\n) into actual newlines before writing to file. Fargate escapes newlines in environment variables.
        temp_file.write(codecs.escape_decode(content.encode("utf-8"))[0])
        temp_file.close()
        self.temp_files.append(temp_file.name)
        return temp_file.name

    @staticmethod
    def cleanup():
        """
        Cleanup temporary files on object destruction.
        """
        logger.i("[Kafka] Cleaning temp files...")

        try:
            with open("/tmp/chats-events-log.txt", "r") as log_file:
                files_to_delete = json.loads(log_file.read())

            for file in files_to_delete:
                try:
                    os.unlink(file)
                    logger.i(f"[Kafka] Successfully cleaned: {file}")
                except OSError as e:
                    logger.w(f"[Kafka] Failed to delete temporary file {file}: {e}")

        except FileNotFoundError as e:
            logger.w(f"[Kafka] Error: temp_files_log.json not found: {e}")

    def json_serializer(self, v):
        """
        serializer for various field types and other objects.
        """

        match v:
            case datetime():
                result = v.isoformat()
            case ImageField() if v:
                result = v.url
            case ImageField():
                result = None
            case timezone():
                result = str(v)
            case models.Model():
                result = serialize("json", [v])
            case list() | tuple() if all(isinstance(item, models.Model) for item in v):
                result = serialize("json", v)
            case dict():
                result = {key: self.json_serializer(value) for key, value in v.items()}
            case _:
                result = json.dumps(v, default=str)

        result = json.dumps(result, default=str)
        return result if result is not None else None

    def create_producer(self, bufferd_producer: bool = False) -> KafkaProducer | BufferedProducer:
        try:
            if bufferd_producer:
                self._producer = BufferedProducer(
                    **self.common_config,
                    api_version=(0, 11, 5),
                    compression_type="gzip",
                    key_serializer=lambda k: str(k).encode("utf-8"),
                    value_serializer=lambda v: self.json_serializer(v).encode("utf-8"),
                )
            else:
                self._producer = KafkaProducer(
                    **self.common_config,
                    api_version=(0, 11, 5),
                    compression_type="gzip",
                    key_serializer=lambda k: str(k).encode("utf-8"),
                    value_serializer=lambda v: self.json_serializer(v).encode("utf-8"),
                )

            logger.i("[Kafka] Producer created successfully.")
            return self._producer

        except KafkaErrors.NoBrokersAvailable as e:
            logger.e(f"[Kafka] No brokers available: {e}")
            raise

        except Exception as e:
            logger.e(f"[Kafka] Failed to create Kafka Producer: {e}")
            raise

    def create_consumer(self, topics, group_id, message_handler, auto_offset_reset="latest") -> SafeConsumer | None:
        try:
            consumer_config = {**self.common_config, "group_id": group_id, "auto_offset_reset": auto_offset_reset}
            self._consumer = SafeConsumer(*topics, message_handler=message_handler, **consumer_config)
            logger.i(f"Kafka Consumer created for topics: {topics}")
            return self._consumer
        except Exception as e:
            logger.e(f"Failed to create Kafka Consumer: {e}")
            raise


class Services:
    clients = {}

    @staticmethod
    def initialize_soroban():
        from .ccrypto import StellarProjectContract

        contract = os.getenv("STELLAR_CONTRACT_ID")
        if not contract:
            raise ValueError("Cannot initialize stellar contract client; STELLAR_CONTRACT_ID env not found")

        rpc = os.getenv("STELLAR_CONTRACT_RPC_URL")
        network_phrase = os.getenv("STELLAR_CONTRACT_NETWORK_PASSPHRASE")
        return StellarProjectContract(contract_id=contract, network_passphrase=network_phrase, rpc_url=rpc)

    @classmethod
    def initialize_clients(
        cls,
        kafka_topics: list[KafkaEvent] | None = None,
        group_id: str = None,
        message_handler=None,
        bufferd_producer=False,
        http_clients: list[ClientType]
        | list[None] = [],  # list of clients to initialize. kafka and redis are initialized by default.
    ):
        """
        Args:
            kafka_topics (list[KafkaEvent] | None, optional): A list of topics to consume. Defaults to None.
        """
        logging.getLogger("kafka").setLevel(logging.WARN)
        if len(sys.argv) > 1:
            if "celery" in sys.argv[0]:
                # return if running celery
                return

            command = sys.argv[1]

        else:
            command = None

        if command in [
            "migrate",
            "makemigrations",
            "showmigrations",
            "collectstatic",
            "sqlmigrate",
            "dbshell",
            "dumpdata",
            "loaddata",
            "flush",
            "shell",
            "check",
            "setup_service",
            "test",
            "inspectdb",
            "compilemessages",
        ]:
            # skip initialization of clients when running manage.py commands
            return

        cls.clients["redis"] = RedisClient(
            startup_nodes=[
                ClusterNode(os.getenv("REDIS_CLUSTER_A_STRING"), os.getenv("REDIS_CLUSTER_A_PORT", 10397)),
            ],
            password=os.getenv("REDIS_PASSWORD"),
        )
        cls.clients["kafka"] = KafkaClient(bootstrap_servers=os.getenv("KAFKA_SERVICE_URI"))
        cls.clients["producer"] = cls.clients["kafka"].create_producer(bufferd_producer=bufferd_producer)

        if ClientType.ACCOUNT in http_clients:
            cls.clients[ClientType.ACCOUNT.value] = AccountClient(service=Service.ACCOUNT)

        if ClientType.IDENTITY in http_clients:
            cls.clients[ClientType.IDENTITY.value] = IdentityClient(
                secret=os.getenv("QORE_SECRET"),
                base_url=os.getenv("QORE_BASE_URL"),
                client_id=os.getenv("QORE_CLIENT_ID"),
                login_url=os.getenv("QORE_LOGIN_URL"),
            )

        if ClientType.STELLAR_CONTRACT in http_clients:
            cls.clients[ClientType.STELLAR_CONTRACT.value] = cls.initialize_soroban()

        if ClientType.PAYSTACK_PAYMENT_CLIENT in http_clients:
            cls.clients[ClientType.PAYSTACK_PAYMENT_CLIENT.value] = PaystackPaymentClient()

        if ClientType.KORA_PAYMENT_CLIENT in http_clients:
            cls.clients[ClientType.KORA_PAYMENT_CLIENT.value] = KoraPaymentClient()

        if ClientType.CURRENCY_CONVERTER_CLIENT in http_clients:
            cls.clients[ClientType.CURRENCY_CONVERTER_CLIENT.value] = CurrencyConverter.configure(
                fiat_api_key=os.getenv("EXCHANGE_RATE_API_KEY")
            )

        if kafka_topics:
            consumer = cls.clients["kafka"].create_consumer(
                group_id=group_id, topics=kafka_topics, message_handler=message_handler
            )

            consumer_thread = threading.Thread(target=consumer.consume_messages)
            consumer_thread.start()

    @classmethod
    def reinitialize(cls, name: ClientType, buffer=False):
        match name:
            case ClientType.IDENTITY.value:
                cls.clients[ClientType.IDENTITY.value] = IdentityClient(
                    secret=os.getenv("QORE_SECRET"),
                    base_url=os.getenv("QORE_BASE_URL"),
                    client_id=os.getenv("QORE_CLIENT_ID"),
                    login_url=os.getenv("QORE_LOGIN_URL"),
                )
                return cls.clients.get(name)

            case ClientType.KAFKA.value:
                cls.clients["kafka"] = KafkaClient(bootstrap_servers=os.getenv("KAFKA_SERVICE_URI"))
                cls.clients["producer"] = cls.clients["kafka"].create_producer(bufferd_producer=buffer)

                return cls.clients["producer"]

            case ClientType.STELLAR_CONTRACT.value:
                client = cls.initialize_soroban()
                cls.clients[ClientType.STELLAR_CONTRACT.value] = client
                return client

            case ClientType.KORA_PAYMENT_CLIENT.value:
                client = cls.clients[ClientType.KORA_PAYMENT_CLIENT.value] = KoraPaymentClient()
                return client

            case _:
                logger.warning(f"[Reinitialize]: No client match found: {name}")

    @classmethod
    def get_client(cls, name: ClientType):
        return cls.clients.get(name)


class IdentityClient:
    def __init__(self, base_url: str, client_id: str, secret: str, login_url: str):
        self.url = base_url
        self.secret = secret
        self.client_id = client_id
        self.login_url = login_url
        self.request_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.init_header = self.login()
        self.login_headers = self.init_header

    def build_url(self, stub: str) -> str:
        """Build a URL by combining the stub with the endpoint"""
        return f"{self.url}{stub}"

    def login(self):
        if not self.secret or not self.client_id or not self.login_url:
            raise ValueError("[IdentityClient]: Missing required parameters")

        url = self.build_url(self.login_url)
        try:
            payload = {
                "secret": self.secret,
                "clientId": self.client_id,
            }
            data = requests.post(url, headers=self.request_headers, data=json.dumps(payload))
            auth = None
            bearerType = None
            if data.ok:
                res = data.json()
                auth = res.get("accessToken")
                bearerType = res.get("tokenType")

            header = {"Authorization": f"{bearerType} {auth}"}
            return self.request_headers.update(**header)
        except Exception as e:
            raise ValueError(e)

    def verify_nin(self, id_number: str, payload: dict):
        try:
            identity = IdentityVerificationSchema.model_validate(payload)
            return self.verify_identity(f"v1/ng/identities/virtual-nin/{id_number}", identity)
        except Exception as e:
            return self.error_response(e)

    def verify_bvn(self, id_number: str, payload: dict):
        try:
            identity = IdentityVerificationSchema.model_validate(payload)
            return self.verify_identity(f"v1/ng/identities/bvn-basic/{id_number}", identity)
        except Exception as e:
            return self.error_response(e)

    def verify_driver_license(self, id_number: str, payload: dict):
        try:
            identity = IdentityVerificationSchema.model_validate(payload)
            return self.verify_identity(f"v1/ng/identities/drivers-license/{id_number}", identity)
        except Exception as e:
            return self.error_response(e)

    def verify_international_passport(self, id_number: str, payload: dict):
        try:
            identity = IdentityVerificationSchema.model_validate(payload)
            return self.verify_identity(f"v1/ng/identities/passport/{id_number}", identity)
        except Exception as e:
            return self.error_response(e)

    def verify_identity(self, url: str, data: IdentityVerificationSchema):
        """
        Send the data to the endpoint and return the response.
        The data will be encrypted before posting and the response will be properly handled.
        """
        post_url = self.build_url(url)
        header = self.request_headers
        response = requests.post(post_url, data=json.dumps(data.model_dump()), headers=header)
        response_json = response.json()
        if response_json.get("status") == 401:
            response = requests.post(
                post_url,
                headers=self.request_headers,
                data=json.dumps(data.model_dump()),
            )
            response_json = response.json()

        return self.prepare_response(**response_json)

    def prepare_response(self, **kwargs):
        """Ingest all attributes on the dictionary and set it as parameters"""
        for k, v in kwargs.items():
            setattr(self, k, v)
        return kwargs

    def error_response(self, error):
        """Prepare error response data object"""
        _error = dict(status=False, data={"message": str(error), "status": "failed"})
        return self.prepare_response(**_error)

    @staticmethod
    def perform_identity_check(
        document_type: str,
        document_number: str,
        payload: dict,
        client: Optional["IdentityClient"] = None,
    ) -> dict | None:
        response = None
        identity = client

        if not client:
            identity: IdentityClient = Services.get_client(ClientType.IDENTITY.value)
        match document_type:
            case "NIN":
                response = identity.verify_nin(document_number, payload)
            case "BVN":
                response = identity.verify_bvn(document_number, payload)
            case "DRIVER_LICENSE":
                response = identity.verify_driver_license(document_number, payload)
            case "INTERNATIONAL_PASSPORT":
                response = identity.verify_international_passport(document_number, payload)
            case _:
                return 400, ErrorResponse(message="Invalid verification type")

        if response.get("message") == "Expired Session":
            # reinitialize client and retry.
            new_client = Services.reinitialize(ClientType.IDENTITY.value)
            response = IdentityClient.perform_identity_check(document_type, document_number, payload, new_client)

        return response


class PaymentClient:
    ...

    def transfer(): ...
    def initialize(): ...
    def get_banks(): ...
    def resolve_account(): ...
    def calculate_hmac(): ...
    def finalize_transfer(): ...
    def verify_transaction(): ...
    def check_transfer_status(): ...
    def create_transfer_recipient(): ...


class PaystackPaymentClient(PaymentClient):
    def __init__(self, **kwargs):
        self.secret_key = os.getenv("PAYSTACK_SECRET_KEY")
        self.client = requests.Session()
        self.client.headers.update({"Content-Type": "application/json", "Authorization": f"Bearer {self.secret_key}"})

    def initialize(self, data: Dict[str, Any]) -> requests.Response:
        try:
            res = self.client.post("https://api.paystack.co/transaction/initialize", json=data)
            res.raise_for_status()
            logger.info(f"Transaction initialized: {res.json()}")
            return res
        except requests.exceptions.RequestException as e:
            logger.error(f"Error initializing transaction: {e}")
            raise PaymentError(str(e), "paystack", e, status_code=e.response.status_code if e.response else None)

    def verify_transaction(self, reference: str) -> Dict[str, Any]:
        try:
            res = self.client.get(f"https://api.paystack.co/transaction/verify/{reference}")
            res.raise_for_status()
            logger.info(f"Transaction verified: {res.json()}")
            return res.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error verifying transaction: {e}")
            raise PaymentError(str(e), "paystack", e, status_code=e.response.status_code if e.response else None)

    def transfer(
        self, amount: int, recipient_code: str, reason: str, currency: str = "NGN", account_reference: str = ""
    ) -> Dict[str, Any]:
        try:
            payload = {
                "amount": amount,
                "reason": reason,
                "source": "balance",
                "currency": currency,
                "reference": uuid.uuid4(),
                "recipient": recipient_code,
                "account_reference": account_reference,
            }
            res = self.client.post("https://api.paystack.co/transfer", json=payload)
            res.raise_for_status()
            logger.info(f"Transfer initiated: {res.json()}")
            return res.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error initiating transfer: {e}")
            raise PaymentError(str(e), "paystack", e, status_code=e.response.status_code if e.response else None)

    def get_banks(self, currency: str = "NGN") -> requests.Response:
        try:
            res = self.client.get(f"https://api.paystack.co/bank?currency={currency}")
            res.raise_for_status()
            return res
        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving banks: {e}")
            raise PaymentError(str(e), "paystack", e, status_code=e.response.status_code if e.response else None)

    def resolve_account(self, acc_number: str, bank_code: str) -> Dict[str, Any]:
        try:
            res = self.client.get(
                f"https://api.paystack.co/bank/resolve?account_number={acc_number}&bank_code={bank_code}"
            )
            res.raise_for_status()
            logger.info(f"Account resolved: {res.json()}")
            return res.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error resolving account: {e}")
            raise PaymentError(str(e), "paystack", e, status_code=e.response.status_code if e.response else None)

    @staticmethod
    def calculate_hmac(data: bytes, secret: str) -> str:
        return hmac.new(secret.encode("utf-8"), data, digestmod=hashlib.sha512).hexdigest()

    def create_transfer_recipient(
        self, bank_code: str, account_name: str, account_number: str, currency: str = "NGN"
    ) -> Dict[str, Any]:
        try:
            payload = {
                "type": "nuban",
                "name": account_name,
                "account_number": account_number,
                "bank_code": bank_code,
                "currency": currency,
            }
            res = self.client.post("https://api.paystack.co/transferrecipient", json=payload)
            res.raise_for_status()
            return res.json()["data"]
        except requests.exceptions.RequestException as e:
            raise PaymentError(str(e), "paystack", e, status_code=e.response.status_code if e.response else None)

    def finalize_transfer(self, transfer_code: str, otp: str) -> Dict[str, Any]:
        try:
            res = self.client.post(
                "https://api.paystack.co/transfer/finalize_transfer", json={"transfer_code": transfer_code, "otp": otp}
            )
            res.raise_for_status()
            return res.json()["data"]
        except requests.exceptions.RequestException as e:
            raise PaymentError(str(e), "paystack", e, status_code=e.response.status_code if e.response else None)

    def check_transfer_status(self, reference: str, max_retries: int = 5, retry_delay: int = 3) -> Dict[str, Any]:
        for attempt in range(max_retries):
            try:
                res = self.client.get(f"https://api.paystack.co/transfer/{reference}")
                res.raise_for_status()
                data = res.json()["data"]

                if data["status"].lower() == "success":
                    return data
                if data["status"].lower() in ["failed", "reversed"]:
                    raise PaymentError(f"Transfer failed: {data['status']}", "paystack", status_code=400)

                time.sleep(retry_delay)
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    raise PaymentError(
                        str(e), "paystack", e, status_code=e.response.status_code if e.response else None
                    )

        raise PaymentError("Transfer status check timed out", "paystack", status_code=408)


class KoraPaymentClient(PaymentClient):
    """
    Koral payment client
    """

    def __init__(self, **kwargs):
        self.secret_key = os.getenv("KORA_SECRET_KEY")
        self.public_key = os.getenv("KORA_PUBLIC_KEY")
        self.client = requests.Session()
        self.client.headers.update({"Content-Type": "application/json", "Authorization": f"Bearer {self.secret_key}"})
        self.base_url = "https://api.korapay.com/merchant/api/v1"
        self.set_auth_header(self.secret_key)

    def set_auth_header(self, key):
        self.client.headers.update({"Content-Type": "application/json", "Authorization": f"Bearer {key}"})

    def _send_api_request(
        self,
        endpoint: str,
        method: str = "POST",
        max_retries: int = 3,
        payload: dict = None,
        use_public_key: bool = False,
        **kwargs,
    ):
        """
        Send an API request with retry and re-authentication on 403 errors.
        """
        key = self.public_key if use_public_key else self.secret_key
        self.set_auth_header(key)
        for attempt in range(max_retries):
            try:
                response = self.client.request(method, endpoint, json=payload, **kwargs)
                response.raise_for_status()
                logger.info(f"API request to {endpoint} succeeded: {response.json()}")
                return response.json()
            except requests.exceptions.RequestException as e:
                status_code = getattr(e.response, "status_code", None)
                if status_code == 403:
                    logger.warning(
                        f"Authentication failed for {endpoint} (attempt {attempt + 1}/{max_retries}). Reinitializing client..."
                    )
                    Services.reinitialize(ClientType.KORA_PAYMENT_CLIENT.value)
                    if attempt == max_retries - 1:
                        logger.error(f"Max retries reached. Unable to authenticate for {endpoint}.")
                        raise PaymentError(
                            "Unable to authenticate with Korapay after multiple attempts",
                            "kora",
                            e,
                            status_code=status_code,
                        )
                else:
                    logger.error(f"HTTP error occurred: {str(e)}")
                    raise PaymentError(str(e), "kora", e, status_code=status_code)

    def initialize(self, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}/charges/initialize"
        print(payload)
        return self._send_api_request(endpoint=url, payload=payload)

    def query_charge(self, refrence):
        try:
            res = self.client.post(self.base_url + "charges/" + refrence)
            res.raise_for_status()
            return res.json()
        except requests.exceptions.RequestException as e:
            logger.e(f"Query charge failed: {str(e)}")
            raise PaymentError(str(e), "kora", e, status_code=e.response.status_code if e.response else None)

    def verify_payment(self, reference):
        pass

    def single_payout(self, payload):
        endpoint = f"{self.base_url}/payouts/single"
        return self._send_api_request(endpoint=endpoint, payload=payload)

    def bulk_payout(self, payload):
        endpoint = f"{self.base_url}/payouts/bulk"
        return self._send_api_request(endpoint=endpoint, payload=payload)

    def query_bulk_payout(self, reference):
        endpoint = f"{self.base_url}/payouts/bulk/{reference}"
        return self._send_api_request(endpoint=endpoint, method="GET")

    def bulk_payout_details(self, reference):
        endpoint = f"{self.base_url}/payouts/bulk/{reference}/transactions"
        return self._send_api_request(endpoint=endpoint, method="GET")

    def verify_payout(self, transaction_reference: str):
        endpoint = f"{self.base_url}/transactions/{transaction_reference}"
        return self._send_api_request(endpoint=endpoint, method="GET")

    def resolve_account(self, payload) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/misc/banks/resolve"
        return self._send_api_request(endpoint=endpoint, payload=payload)

    @staticmethod
    def calculate_hmac(data: dict, secret: str) -> str:
        """Calculate HMAC SHA256 signature for Korapay webhook data."""
        serialized_data = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return hmac.new(key=secret.encode("utf-8"), msg=serialized_data, digestmod=hashlib.sha256).hexdigest()

    def get_banks(self, country_code: str = "NG", use_public_key: bool = True) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/misc/banks"
        params = {"countryCode": country_code}
        return self._send_api_request(endpoint=endpoint, method="GET", params=params, use_public_key=use_public_key)

    def verify_bvn(self, payload) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/identities/ng/bvn"
        return self._send_api_request(endpoint=endpoint, payload=payload)

    def verify_nin(self, payload) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/identities/ng/nin"
        return self._send_api_request(endpoint=endpoint, payload=payload)

    def verify_vnin(self, payload) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/identities/ng/vnin"
        return self._send_api_request(endpoint=endpoint, payload=payload)

    def verify_cac(self, payload) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/identities/ng/cac"
        return self._send_api_request(endpoint=endpoint, payload=payload)


class SMSClient:
    """Base SMS client class providing common interface for SMS services."""

    def __init__(self) -> None: ...
    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mmake authenticated API calls to the client.

        Args:
            endpoint: API endpoint (e.g., "sms/send")
            payload: Dictionary of parameters to send

        Returns:
            API response as dictionary

        Raises:
            requests.exceptions.HTTPError: If API request fails
        """
        raise NotImplementedError("subclasses must implement post method")

    def send_sms(
        self,
        message: str,
        source: str,
        phone: Union[str, list[str]],
        type: str = "plain",
        channel: Literal["dnd", "whatsapp", "generic"] = "generic",
    ) -> Dict[str, Any]:
        """
        Base method for sending SMS messages.

        Args:
            phone: Recipient phone number(s) in international format
            message: Text message content
            source: Sender ID or phone number
            channel: Delivery channel (dnd, whatsapp, generic)
            type: Message type (plain, etc.)

        Returns:
            Dictionary containing API response

        """
        raise NotImplementedError("subclasses must implement send_sms method")

    @staticmethod
    def format_phone_number(phone_number: str, country_code: str = "NG") -> str:
        """
        Format phone numbers according to country specifications, with support for extensions.
        Currently only supports Nigeria (NG).
        """
        cleaned = re.sub(r"(?!^\+)[^\d]", "", str(phone_number))

        if country_code.upper() == "NG":
            if cleaned.startswith("+234"):
                formatted = cleaned  # already in international format

            elif cleaned.startswith("234"):
                formatted = f"+{cleaned}"

            elif cleaned.startswith("0"):
                formatted = f"+234{cleaned[1:]}"

            else:
                # for numbers without prefix, we assume they're missing country code
                if len(cleaned) == 10:
                    formatted = f"+234{cleaned}"

                else:
                    raise ValueError(f"Invalid Nigerian phone number format: {phone_number}")

            if len(formatted) != 14:
                raise ValueError(f"Invalid Nigerian phone number length: {phone_number}")
        else:
            raise ValueError(f"Unsupported country code: {country_code}. Currently only 'NG' is supported")

        return formatted


class TermiClient(SMSClient):
    def __init__(self) -> None:
        self.api_key = os.getenv("TERMII_API_KEY")
        self.base_url = os.getenv("TERMII_BASE_URL")
        self.api_secret = os.getenv("TERMII_API_SECRET")

        if not self.base_url or not self.api_key:
            raise ValueError("Missing required environment variables. Please set TERMII_BASE_URL and TERMII_API_KEY")

        self.base_url = self.base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json"}

    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        authenticated_payload = payload.copy()
        authenticated_payload["api_key"] = self.api_key
        if self.api_secret:
            authenticated_payload["api_secret"] = self.api_secret

        response = requests.post(url, headers=self.headers, json=authenticated_payload)
        response.raise_for_status()
        return response.json()

    def send_sms(
        self,
        phone: Union[str, list[str]],
        message: str,
        source: str,
        channel: Literal["dnd", "whatsapp", "generic"] = "dnd",
        type: str = "plain",
        media_url: Optional[str] = None,
        media_caption: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send SMS/MMS message through Termii API"""

        if not phone or not message or not source:
            raise ValueError("phone, message, and source parameters are required")

        if isinstance(source, str) and len(source) > 11:
            raise ValueError("Sender ID must be 11 characters or less")

        recipients = [phone] if isinstance(phone, str) else phone
        payload = {
            "to": recipients,
            "type": type,
            "from": source,
            "sms": message,
            "channel": channel,
        }

        if media_url or media_caption:
            if not (media_url and media_caption):
                raise ValueError("Both media_url and media_caption required for MMS")
            payload["media"] = {"url": media_url, "caption": media_caption}

        return self.post("sms/send", payload)


class TwilioClient(SMSClient): ...


class EndpointBuilder:
    """Chainable endpoint paths"""

    def __init__(self, client: "BTCClient", path: str = ""):
        self.client = client
        self.path = path

    def __getattr__(self, name: str) -> "EndpointBuilder":
        return EndpointBuilder(self.client, f"{self.path}/{name}")

    def __call__(self, *args) -> "EndpointBuilder":
        """Handle path arguments like .address('...')"""
        new_path = f"{self.path}/{'/'.join(str(arg) for arg in args)}"
        return EndpointBuilder(self.client, new_path.lstrip("/"))

    def call(self, **params) -> Any:
        """Execute the request"""
        return self.client._request(self.path, params)


class BTCClient:
    """Support Blockstream, Mempool.space, and local RPC Node"""

    def __init__(self, host: str, *, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = host.rstrip("/") + "/"

        self.fees = EndpointBuilder(self, "fee")
        self.blocks = EndpointBuilder(self, "block")
        self.address = EndpointBuilder(self, "address")
        self.transactions = EndpointBuilder(self, "tx")

    def _request(self, path: str, params: Optional[dict] = None) -> Any:
        """Generic request handler"""
        url = f"{self.base_url}{path}"
        headers = {"Accept": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            raise Exception(f"API request failed: {e}")

    def get_fee_estimates(self) -> Dict[str, float]:
        """
        Get current fee estimates (sat/vByte)
        """
        try:
            try:
                # blockstream format
                return self._request("fee-estimates")

            except Exception:
                # mempool.space

                return self._request("v1/fees/recommended")
        except Exception as e:
            raise Exception(f"Fee estimation unavailable: {str(e)}")

    def get_recommended_fee(self, target_blocks: int = 6) -> float:
        """
        Get recommended fee for target confirmation blocks
        Returns sat/vByte
        """
        estimates = self.get_fee_estimates()

        if all(isinstance(k, str) for k in estimates.keys()):
            # blockstream format
            return estimates.get(str(target_blocks), estimates.get("6"))
        else:
            # mempool.space format
            if target_blocks <= 1:
                return estimates.get("fastestFee", 1.0)

            elif target_blocks <= 3:
                return estimates.get("halfHourFee", 1.0)

            else:
                return estimates.get("hourFee", 1.0)

    def submit_transaction(self, tx_hex: str) -> str:
        """Broadcast transaction"""

        url = f"{self.base_url}tx"
        response = requests.post(url, data=tx_hex)

        return response.json()


@dataclass(frozen=True)
class TokenInfo:
    symbol: str
    contract_address: str
    decimals: int = 6


class EthereumClient:
    def __init__(self, web3: Web3):
        self.web3 = web3

    def get_balance(self, address: str, token: Optional[TokenInfo] = None) -> Decimal:
        if token is None:
            balance = self.web3.eth.get_balance(address)
            return Decimal(str(self.web3.from_wei(balance, "ether")))

        contract = self.web3.eth.contract(
            address=token.contract_address,
            abi=[
                {
                    "inputs": [{"name": "_owner", "type": "address"}],
                    "name": "balanceOf",
                    "outputs": [{"name": "balance", "type": "uint256"}],
                    "type": "function",
                }
            ],
        )
        balance = contract.functions.balanceOf(address).call()
        return Decimal(balance) / (10**token.decimals)

    def send_transaction(self, tx_params: TxParams, private_key: str) -> HexStr:
        signed_tx = self.web3.eth.account.sign_transaction(tx_params, private_key)
        return self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)

    def wait_for_transaction(self, tx_hash: HexStr, timeout: int = 120) -> TxReceipt:
        return self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)

    def get_transaction_history(self, address: str) -> list[Dict]:
        return self.web3.eth.get_transactions_by_address(address)


class CurrencyConverter:
    _fiat_api_key = None
    _fiat_base_url = "https://v6.exchangerate-api.com/v6"
    _crypto_apis = ["https://api.coinlore.net/api", "https://api.coincap.io/v2"]
    _crypto_id_map = {
        "BTC": {"coinlore": "90", "coincap": "bitcoin"},
        "ETH": {"coinlore": "80", "coincap": "ethereum"},
        "USDT": {"coinlore": "518", "coincap": "tether"},
        "USDC": {"coinlore": "33285", "coincap": "usd-coin"},
        "ChatsUSDC": {"coinlore": "33285", "coincap": "usd-coin"},
    }
    _timeout = 5

    @classmethod
    def configure(cls, *, fiat_api_key=None, fiat_base_url=None, crypto_apis=None, crypto_id_map=None, timeout=None):
        if fiat_api_key is not None:
            cls._fiat_api_key = fiat_api_key
        if fiat_base_url is not None:
            cls._fiat_base_url = fiat_base_url
        if crypto_apis is not None:
            cls._crypto_apis = crypto_apis
        if crypto_id_map is not None:
            cls._crypto_id_map.update(crypto_id_map)
        if timeout is not None:
            cls._timeout = timeout
        return cls

    @classmethod
    def get_rate(cls, base_currency: str, target_currency: str, date: datetime = None) -> Decimal | None:
        if base_currency == target_currency:
            return Decimal("1.0")

        cache_key = f"rate_{base_currency}_{target_currency}_{date.date() if date else 'current'}"
        if cached := cache.get(cache_key):
            return Decimal(cached)

        rate = cls._fetch_rate(base_currency, target_currency)
        if rate:
            cache.set(cache_key, str(rate), 86400)  # 24h
        return rate

    @classmethod
    def _fetch_rate(cls, base: str, target: str) -> Decimal | None:
        if base in cls._crypto_id_map:
            usd_rate = cls._fetch_crypto_rate(base)
            if not usd_rate:
                return None
            return usd_rate * cls._fetch_fiat_rate("USD", target)
        return cls._fetch_fiat_rate(base, target)

    @classmethod
    def _fetch_crypto_rate(cls, base: str) -> Decimal | None:
        for api_url in cls._crypto_apis:
            try:
                if "coinlore" in api_url:
                    rate = cls._fetch_coinlore_rate(base)
                elif "coincap" in api_url:
                    rate = cls._fetch_coincap_rate(base)

                if rate:
                    return rate
            except Exception as e:
                logger.warning(f"Crypto API failed: {str(e)}")
        return None

    @classmethod
    def _fetch_coinlore_rate(cls, base: str) -> Decimal | None:
        coin_id = cls._crypto_id_map.get(base, {}).get("coinlore")
        if not coin_id:
            return None

        response = requests.get(f"{cls._crypto_apis[0]}/ticker/?id={coin_id}", timeout=cls._timeout)
        response.raise_for_status()
        data = response.json()
        return Decimal(data[0]["price_usd"]) if data else None

    @classmethod
    def _fetch_coincap_rate(cls, base: str) -> Decimal | None:
        coin_id = cls._crypto_id_map.get(base, {}).get("coincap")
        if not coin_id:
            return None

        response = requests.get(f"{cls._crypto_apis[1]}/assets/{coin_id}", timeout=cls._timeout)
        response.raise_for_status()
        data = response.json()
        return Decimal(data["data"]["priceUsd"]) if data.get("data") else None

    @classmethod
    def _fetch_fiat_rate(cls, base: str, target: str) -> Decimal | None:
        if not cls._fiat_api_key:
            return None

        response = requests.get(f"{cls._fiat_base_url}/{cls._fiat_api_key}/latest/{base}", timeout=cls._timeout)
        response.raise_for_status()
        data = response.json()
        return Decimal(str(data["conversion_rates"][target])) if data.get("result") == "success" else None
