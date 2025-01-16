import json
import asyncio
from functools import wraps
from typing import Callable, Any, Literal

from typing import Dict, List
from enum import Enum, EnumMeta
from django.http import JsonResponse
from chatspy.clients import Services
from chatspy.clients import RedisClient


from .utils import verify_auth_token


class RoleValueMixin(str, Enum):
    """Mixin to add string behavior to Enum."""

    def __str__(self):
        return self.value


class InvitedRole(RoleValueMixin):
    """These are users who got in through an invitation."""

    SUB_ADMIN = "subadmin"
    POWER_USER = "poweruser"
    FIELD_AGENT = "fieldagent"
    PROGRAM_LEAD = "programlead"
    PROGRAM_CO_LEAD = "programcolead"
    FINANCE_OFFICER = "financeofficer"
    M_AND_E_OFFICER = "m_and_e_officer"


class RegistrationRole(RoleValueMixin):
    """These are users capable of registering themselves."""

    NGO = "ngo"
    VENDOR = "vendor"
    BENEFICIARY = "beneficiary"
    ADMIN_INDIVIDUAL = "adminindividual"
    DONOR_CORPORATE = "donor_corporate"
    DONOR_INDIVIDUAL = "donor_individual"


class MergedEnumMeta(EnumMeta):
    """Custom metaclass for merging roles."""

    def __new__(metacls, clsname, bases, clsdict):
        cls = super().__new__(metacls, clsname, bases, clsdict)
        # Dynamically add members from InvitedRole and RegistrationRole
        for role in list(InvitedRole) + list(RegistrationRole):
            cls._value2member_map_[role.value] = role
            setattr(cls, role.name, role)

        return cls


class SystemRole(RoleValueMixin, metaclass=MergedEnumMeta):
    """Combined roles from InvitedRole and RegistrationRole."""

    ...


class PermissionType(Enum):
    VIEW = "view"
    MANAGE = "manage"


class Resource(Enum):
    USERS = "users"
    VENDOR = "vendor"
    PROJECT = "project"
    ACCOUNT = "account"
    ADMIN_USER = "admin_users"
    FIELD_AGENT = "field_agents"
    BENEFICIARY = "beneficiary"
    MARKETPLACE = "marketplace"
    CASH_FOR_WORK = "cash_for_work"


class PermissionMapping:
    @classmethod
    def get_all_permissions(cls):
        return

    @classmethod
    def generate_permissions(
        cls,
        permission_types: List[PermissionType] | None = None,
        resources: List[Resource | None] = None,
    ) -> List[dict]:
        """
        Generate permissions dynamically based on permission types and resources
        """

        def codify(perm, resource):
            return {
                "name": f"can_{perm.value}_{resource.value}",
                "code": f"{perm.value}:{resource.value}",
            }

        if not all([permission_types, resources]):
            return [codify(perm, resource) for perm in PermissionType for resource in Resource]

        return [codify(perm, resource) for perm in permission_types for resource in resources]

    @classmethod
    def get_default_permissions(cls) -> Dict[SystemRole, List[dict]]:
        """
        Generate mapping of roles and permissions:

        return
            {
            "admin": [
                {"name": "can_view_vendor", "code": "view:vendor"},
                {"name": "can_view_project", "code": "view:project"},
            ],
            "subadmin": [...]
            ...
        }
        """

        return {
            SystemRole.ADMIN_INDIVIDUAL.value: cls.generate_permissions(
                permission_types=list(PermissionType), resources=list(Resource)
            ),
            SystemRole.NGO.value: cls.generate_permissions(
                permission_types=list(PermissionType), resources=list(Resource)
            ),
            SystemRole.SUB_ADMIN.value: cls.generate_permissions(
                permission_types=[PermissionType.VIEW, PermissionType.MANAGE],
                resources=[Resource.VENDOR, Resource.PROJECT, Resource.BENEFICIARY],
            ),
            SystemRole.FIELD_AGENT.value: cls.generate_permissions(
                permission_types=[PermissionType.VIEW],
                resources=[Resource.BENEFICIARY],
            ),
            SystemRole.FIELD_AGENT.value: cls.generate_permissions(
                permission_types=[PermissionType.MANAGE],
                resources=[Resource.BENEFICIARY],
            ),
            SystemRole.M_AND_E_OFFICER.value: cls.generate_permissions(
                permission_types=[PermissionType.VIEW],
                resources=[Resource.PROJECT, Resource.BENEFICIARY, Resource.ACCOUNT],
            ),
            SystemRole.PROGRAM_CO_LEAD.value: cls.generate_permissions(
                permission_types=[PermissionType.VIEW],
                resources=[Resource.PROJECT, Resource.BENEFICIARY, Resource.ACCOUNT],
            ),
            SystemRole.FINANCE_OFFICER.value: cls.generate_permissions(
                permission_types=[PermissionType.VIEW],
                resources=[Resource.PROJECT, Resource.BENEFICIARY, Resource.ACCOUNT],
            ),
        }


class Permissions(str, Enum):
    MANAGE_USERS = f"{PermissionType.MANAGE.value}:{Resource.USERS.value}"
    VIEW_USERS = f"{PermissionType.VIEW.value}:{Resource.USERS.value}"

    MANAGE_VENDOR = f"{PermissionType.MANAGE.value}:{Resource.VENDOR.value}"
    VIEW_VENDOR = f"{PermissionType.VIEW.value}:{Resource.VENDOR.value}"

    MANAGE_PROJECT = f"{PermissionType.MANAGE.value}:{Resource.PROJECT.value}"
    VIEW_PROJECT = f"{PermissionType.VIEW.value}:{Resource.PROJECT.value}"

    MANAGE_ACCOUNT = f"{PermissionType.MANAGE.value}:{Resource.ACCOUNT.value}"
    VIEW_ACCOUNT = f"{PermissionType.VIEW.value}:{Resource.ACCOUNT.value}"

    MANAGE_FIELD_AGENT = f"{PermissionType.MANAGE.value}:{Resource.FIELD_AGENT.value}"
    VIEW_FIELD_AGENT = f"{PermissionType.VIEW.value}:{Resource.FIELD_AGENT.value}"

    MANAGE_BENEFICIARY = f"{PermissionType.MANAGE.value}:{Resource.BENEFICIARY.value}"
    VIEW_BENEFICIARY = f"{PermissionType.VIEW.value}:{Resource.BENEFICIARY.value}"

    MANAGE_MARKETPLACE = f"{PermissionType.MANAGE.value}:{Resource.MARKETPLACE.value}"
    VIEW_MARKETPLACE = f"{PermissionType.VIEW.value}:{Resource.MARKETPLACE.value}"

    MANAGE_CASH_FOR_WORK = f"{PermissionType.MANAGE.value}:{Resource.CASH_FOR_WORK.value}"
    VIEW_CASH_FOR_WORK = f"{PermissionType.VIEW.value}:{Resource.CASH_FOR_WORK.value}"

    @staticmethod
    def permission_required(*required_permissions, mode: Literal["any", "all"] = "any"):
        def decorator(func: Callable[..., Any]):
            @wraps(func)
            async def wrapper(request, *args, **kwargs):
                if not hasattr(request, "headers"):
                    return JsonResponse({"message": "Invalid request object", "detail": ""}, status=400)

                # check latest permissions from redis, if not found, fall back to the permissions in the request's header.
                redis_client: RedisClient = Services.get_client("redis")
                user_permissions = redis_client.get(f"user:{request.user.id}:permissions")

                if not user_permissions:
                    token = request.headers.get("Authorization", "").split(" ")[1]
                    roles_permissions = verify_auth_token(token, verify=False)
                    user_roles = roles_permissions.get("roles", [])
                    perms = roles_permissions.get("permissions", [])
                    user_permissions = {
                        "roles": user_roles,
                        "permissions": perms,
                    }

                else:
                    user_permissions = user_permissions.decode("utf-8")

                if isinstance(user_permissions, str):
                    user_permissions = json.loads(user_permissions)

                permissions = user_permissions.get("permissions")
                codenames = [perm.get("codename") for perm in permissions]
                if mode == "any":
                    if not any(permission.value in codenames for permission in required_permissions):
                        return JsonResponse({"message": "Permission denied", "detail": ""}, status=403)

                elif mode == "all":
                    if not all(permission.value in codenames for permission in required_permissions):
                        return JsonResponse({"message": "Permission denied", "detail": ""}, status=403)

                # await the wrapped function properly if it's asynchronous
                if asyncio.iscoroutinefunction(func):
                    return await func(request, *args, **kwargs)
                return func(request, *args, **kwargs)

            return wrapper

        return decorator
