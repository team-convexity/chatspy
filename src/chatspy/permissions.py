from enum import Enum
from typing import Dict, List


class SystemRole(Enum):

    # admin account types (those who owns an organization)
    NGO = "ngo"
    ADMIN_INDIVIDUAL = "adminindividual"

    # Other user types who belongs to an organization configured by an admin above.
    VENDOR = "vendor"
    SUB_ADMIN = "subadmin"
    FIELD_AGENT = "fieldagent"
    PROGRAM_LEAD = "programlead"
    M_AND_E_OFFICER = "m_and_e_officer"
    PROGRAM_CO_LEAD = "programcolead"
    FINANCE_OFFICER = "financeofficer"
    DONOR_INDIVIDUAL = "donor_individual"
    DONOR_CORPORATE = "donor_corporate"


class PermissionType(Enum):
    VIEW = "view"
    MANAGE = "manage"


class Resource(Enum):
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
            return [
                codify(perm, resource)
                for perm in PermissionType
                for resource in Resource
            ]

        return [
            codify(perm, resource)
            for perm in permission_types
            for resource in resources
        ]

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
                permission_types=[PermissionType.VIEW],
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
