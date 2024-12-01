import jwt
from django.http import HttpResponse

from .services import Service
from .secret import Secret


def verify_auth_token(token: str):
    return jwt.decode(
        token,
        Secret.get_service_pubkey(service=Service.AUTH),
        algorithms=["RS256"],
    )

def health_check(req):
    return HttpResponse()
