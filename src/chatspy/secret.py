import os
import codecs

from logging import getLogger
from .services import Service
from django.conf import settings

logger = getLogger("gunicorn.info")

class Secret:
    @classmethod
    def get_service_key(cls, service: Service, private: bool = False):
        if private:
            cert = os.getenv(f"{service.value}_PRI_CERT")
            if not cert:
                logger.warning(f"private cert for {service.name} is not found")
            return codecs.escape_decode(cert.encode("utf-8"))[0]
        
        cert = os.getenv(f"{service.value}_PUB_CERT")
        if not cert:
            logger.warning(f"public cert for {service.name} is not found in the env")
        
        return codecs.escape_decode(cert.encode("utf-8"))[0]
