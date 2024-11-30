import os
from typing import Literal

import redis
from .logger import get_logger
from requests import request
from django.conf import settings

from .secret import Secret
from .services import Service

logger = get_logger(__name__)


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


class RedisClient:
    """
    Base class for redis connection
    """

    def __init__(self):
        self.client = redis.StrictRedis(host="localhost", port=6379, db=0)

    def set(self): ...

    def get(self): ...

    def delete(self, key: str): ...


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
