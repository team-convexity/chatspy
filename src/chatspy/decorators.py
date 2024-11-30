from functools import wraps

from django.http import JsonResponse
from django.db.transaction import Atomic
from asgiref.sync import sync_to_async

from .utils import verify_auth_token

def permission_required(required_permission):
    """
    @permission_required("delete:projects")
    def delete_project(request):
        ...
    """

    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            token = request.headers.get("Authorization", "").split(" ")[1]
            roles_permissions = verify_auth_token(token)

            if required_permission not in roles_permissions["permissions"]:
                return JsonResponse({"error": "Permission denied"}, status=403)

            return func(request, *args, **kwargs)
        return wrapper
    return decorator



class AsyncAtomicContextManager(Atomic):
    def __init__(self, using=None, savepoint=True, durable=False):
        super().__init__(using, savepoint, durable)

    async def __aenter__(self):
        await sync_to_async(super().__enter__)()
        return self
    
    async def __aexit__(self, exc_type, exc_value, traceback):
        await sync_to_async(super().__exit__)(exc_type, exc_value, traceback)

def aatomic(fun, *args, **kwargs):
    async def wrapper():
        async with AsyncAtomicContextManager():
            await fun(*args, **kwargs)

    return wrapper
