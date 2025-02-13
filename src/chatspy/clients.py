import os
import sys
import json
import codecs
import logging
import tempfile
import threading
from enum import Enum, auto
from collections import defaultdict
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Literal, Optional, Union, List, Dict

import redis
import requests
from requests import request
from django.db import models
from django.conf import settings
from django.db import transaction
from django.db.models import ImageField
from django.core.serializers import serialize
from redis.cluster import RedisCluster, ClusterNode
from kafka import KafkaProducer, KafkaConsumer, errors as KafkaErrors

from .utils import Logger
from .services import Service
from .schemas import IdentityVerificationSchema

logger = Logger.get_logger()


class KafkaEvent(Enum):
    UserCreated = "UserCreated"
    DonorInvited = "DonorInvited"
    ProjectCreated = "ProjectCreated"
    SendNotification = "SendNotification"
    OrganizationCreated = "OrganizationCreated"
    BroadcastTransaction = "BroadcastTransaction"


class ClientType(Enum):
    KAFKA = "kafka"
    PRODUCER = "producer"
    ACCOUNT = "account"
    REDIS = "redis"
    IDENTITY = "identity"


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
    recipients: List[str]  # recipicients' auth user IDs or email strings.

    # notification content
    # when sending SMS, the notification service will only use title (discarding body)
    title: str

    # channel-specific configurations
    channels: List[NotificationChannel]

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

        :param startup_nodes: List of initial cluster nodes
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

        if kafka_topics:
            consumer = cls.clients["kafka"].create_consumer(
                group_id=group_id, topics=kafka_topics, message_handler=message_handler
            )

            consumer_thread = threading.Thread(target=consumer.consume_messages)
            consumer_thread.start()
    
    @classmethod
    def reinitialize(cls, name: ClientType):
        match name:
            case ClientType.IDENTITY.value:
                cls.clients[ClientType.IDENTITY.value] = IdentityClient(
                    secret=os.getenv("QORE_SECRET"),
                    base_url=os.getenv("QORE_BASE_URL"),
                    client_id=os.getenv("QORE_CLIENT_ID"),
                    login_url=os.getenv("QORE_LOGIN_URL"),
                )
                return cls.clients.get(name)

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
