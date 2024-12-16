import jwt
from gunicorn.config import Config
from gunicorn.glogging import Logger
from django.http import HttpResponse

from .secret import Secret
from .services import Service


def verify_auth_token(token: str):
    return jwt.decode(
        token,
        Secret.get_service_pubkey(service=Service.AUTH),
        algorithms=["RS256"],
    )

def health_check(req):
    return HttpResponse()


class Logger(Logger):
    def d(self, message):
        return self.debug(msg=message)

    def e(self, message):
        return self.error(msg=message)

    def i(self, message):
        return self.info(msg=message)

    def w(self, message):
        return self.warning(msg=message)
    
    @staticmethod
    def get_logger():
        return Logger(Config())

logger = Logger.get_logger()
