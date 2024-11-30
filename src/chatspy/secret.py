import os

import structlog
from django.conf import settings

from .logger import get_logger
from .services import Service

logger: structlog.BoundLogger = get_logger(__name__)

class Secret:
    @classmethod
    def get_service_key(cls, service: Service, private: bool = False):
        if settings.DEBUG:
            if private:
                cert = os.getenv(f"{service.value}_PRI_CERT")
                logger.wa(f"Pricert for {service.name} is not found")
                return cert

            cert = os.environ.get(f"{service.value}_PUB_CERT")
            logger.warning(f"Pubcert for {service.name} is not found")
            return cert

        # get cert from aws sec on staging, prod and qa.
        return ...
