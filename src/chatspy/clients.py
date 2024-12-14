import os
import json
import tempfile
from enum import Enum
from django.db import models
from datetime import datetime, timezone
from django.db.models import ImageField
from typing import Literal, Optional, Union
from django.core.serializers import serialize

import redis
import logging
from requests import request
from django.conf import settings
from redis.cluster import RedisCluster, ClusterNode
from kafka import KafkaProducer, KafkaConsumer, errors as KafkaErrors

from .services import Service

logger = logging.getLogger("gunicorn.info")

class KafkaEvent(Enum):
    UserCreated = "UserCreated"
    ProjectCreated = "ProjectCreated"
    SendNotification = "SendNotification"
    OrganizationCreated = "OrganizationCreated"

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
            logger.warning(f"cannot find port number for {service.name}")
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

    def __init__(self, startup_nodes: list[ClusterNode], decode_responses: bool = True, skip_full_coverage_check: bool = True, password=None, cluster_enabled=False):
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
            logger.info(f"[Redis] Successfully connected to {cluster.host}")
        
        except redis.exceptions.ConnectionError as e:
            logger.error(f"[Redis] Cannot establish connection to Redis: {e}")
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
            if expire:
                return self.client.setex(key, expire, value)
            return self.client.set(key, value)
        except Exception as e:
            logger.info(f"Error setting key {key}: {e}")
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
            logger.info(f"Error getting key {key}: {e}")
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
            logger.info(f"Error deleting key {key}: {e}")
            return 0


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
            raise ValueError("[Kafka] Certificate strings must be set in environment variables: ACCESS_KEY, ACCESS_CERT, CA_CERT")

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
        with open('temp_files_log.txt', 'w') as log_file:
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
        temp_file.write(content.encode("utf-8"))
        temp_file.close()
        self.temp_files.append(temp_file.name)
        return temp_file.name
    
    @staticmethod
    def cleanup():
        """
        Cleanup temporary files on object destruction.
        """
        logger.info("[Kafka] Cleaning temp files...")

        try:
            with open('temp_files_log.txt', 'r') as log_file:
                files_to_delete = json.loads(log_file.read())

            for file in files_to_delete:
                try:
                    os.unlink(file)
                    logger.info(f"[Kafka] Successfully cleaned: {file}")
                except OSError as e:
                    logger.warning(f"[Kafka] Failed to delete temporary file {file}: {e}")
        
        except FileNotFoundError as e:
            logger.warning(f"[Kafka] Error: temp_files_log.json not found: {e}")

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
                result = serialize('json', [v])
            case (list() | tuple()) if all(isinstance(item, models.Model) for item in v):
                result = serialize('json', v)
            case dict():
                result = {key: self.json_serializer(value) for key, value in v.items()}
            case _:
                result = json.dumps(v, default=str)
        
        result = json.dumps(result, default=str)
        return result if result is not None else None

    def create_producer(self):
        try:
            self._producer = KafkaProducer(
                **self.common_config,
                api_version=(0,11,5),
                compression_type='gzip',
                key_serializer=lambda k: str(k).encode('utf-8'),
                value_serializer=lambda v: self.json_serializer(v).encode("utf-8")
            )
            logger.info("[Kafka] Producer created successfully.")
            return self._producer
            
        except KafkaErrors.NoBrokersAvailable as e:
            logger.error(f"No brokers available: {e}")
            raise
        
        except Exception as e:
            logger.error(f"Failed to create Kafka Producer: {e}")
            raise

    def create_consumer(self, topics, group_id, auto_offset_reset="latest"):
        try:
            consumer_config = {**self.common_config, "group_id": group_id, "auto_offset_reset": auto_offset_reset}
            self._consumer = KafkaConsumer(*topics, **consumer_config)
            logger.info(f"Kafka Consumer created for topics: {topics}")
            return self._consumer
        except Exception as e:
            logger.error(f"Failed to create Kafka Consumer: {e}")
            raise
