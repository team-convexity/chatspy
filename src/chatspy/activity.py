import re
import json
from enum import Enum
from django.utils import timezone
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from .utils import logger


class ActivityCategory(str, Enum):
    AUTH = "AUTH"
    PROJECT = "PROJECT"
    WALLET = "WALLET"
    VERIFICATION = "VERIFICATION"
    DONATION = "DONATION"


class ActionVerb(str, Enum):
    CREATE = "CREATE"
    CREATED = "CREATED"
    READ = "READ"
    UPDATE = "UPDATE"
    UPDATED = "UPDATED"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    SUBMIT = "SUBMIT"
    VERIFY = "VERIFY"
    FUNDED = "FUNDED"
    WITHDREW = "WITHDREW"
    DISBURSED = "DISBURSED"
    ARCHIVED = "ARCHIVED"
    SYNCED = "SYNCED"
    SENT = "SENT"
    CLAIMED = "CLAIMED"


class ActivityStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    CANCELLED = "cancelled"


class AuthActivityType(str, Enum):
    USER_LOGIN = "UserLogin"
    USER_REGISTRATION = "UserRegistration"


class ProjectActivityType(str, Enum):
    PROJECT_CREATED = "ProjectCreated"
    PROJECT_FUNDED = "ProjectFunded"
    PROJECT_WITHDRAWAL = "ProjectWithdrawal"
    PROJECT_ARCHIVED = "ProjectArchived"
    STATUS_UPDATED = "StatusUpdated"
    BENEFICIARY_ADDED = "BeneficiaryAdded"
    ITEMS_DISBURSED = "ItemsDisbursed"
    DONATION_CREATED = "DonationCreated"


class WalletActivityType(str, Enum):
    WALLET_FUNDED = "WalletFunded"


class VerificationActivityType(str, Enum):
    KYC_SUBMITTED = "KYCSubmitted"


@dataclass
class ActivityData:
    activity_type: str
    activity_category: str
    action_verb: str
    activity_status: str
    description: str
    short_description: str
    resource_type: str
    resource_id: Optional[Any] = None
    project_id: Optional[str] = None
    amount: Optional[Any] = None
    currency: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: Optional[Any] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ActivityExtractor(ABC):
    @abstractmethod
    def can_handle(self, view_name: str) -> bool:
        pass

    @abstractmethod
    def extract(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]] = None
    ) -> ActivityData:
        pass


class RequestContextExtractor:
    @staticmethod
    def extract_common_fields(request: Any) -> Dict[str, Any]:
        now = timezone.now()

        ip_address = None
        if hasattr(request, "META"):
            x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(",")[0].strip()
            else:
                ip_address = request.META.get("REMOTE_ADDR")

        user_agent = None
        if hasattr(request, "META"):
            user_agent = request.META.get("HTTP_USER_AGENT")

        path = getattr(request, "path", None)
        method = getattr(request, "method", None)

        return {
            "timestamp": now.isoformat(),
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_path": path,
            "request_method": method,
        }

    @staticmethod
    def merge_activity_data(request: Any, activity_data: ActivityData) -> ActivityData:
        common_fields = RequestContextExtractor.extract_common_fields(request)

        activity_data.timestamp = common_fields.get("timestamp")
        activity_data.ip_address = common_fields.get("ip_address")
        activity_data.user_agent = common_fields.get("user_agent")
        activity_data.endpoint = common_fields.get("request_path")

        if activity_data.metadata is None:
            activity_data.metadata = {}

        activity_data.metadata.update(
            {
                "ip_address": common_fields.get("ip_address"),
                "user_agent": common_fields.get("user_agent"),
                "request_path": common_fields.get("request_path"),
                "request_method": common_fields.get("request_method"),
            }
        )

        return activity_data


class ActivityRegistry:
    def __init__(self):
        self._extractors: list[ActivityExtractor] = []

    def register(self, extractor: ActivityExtractor) -> None:
        self._extractors.append(extractor)

    def get_extractor(self, view_name: str) -> Optional[ActivityExtractor]:
        for extractor in self._extractors:
            if extractor.can_handle(view_name):
                return extractor
        return None


class ActivityMetadataService:
    def __init__(self, registry: ActivityRegistry):
        self.registry = registry
        logger.i("ActivityMetadataService initialized")

    def extract_activity_metadata(self, request: Any, response_data: Dict[str, Any]) -> Optional[ActivityData]:
        view_name = self._get_view_name(request)
        if not view_name:
            return None

        extractor = self.registry.get_extractor(view_name)
        if not extractor:
            return None

        try:
            route_params = self._get_route_params(request)
            activity_data = extractor.extract(request, response_data, route_params)
            logger.d(f"Activity extracted: {activity_data.activity_type} - {view_name}")
            return activity_data
        except Exception as e:
            logger.e(f"Failed to extract activity for {view_name}", description=str(e))
            return None

    @staticmethod
    def _get_view_name(request: Any) -> Optional[str]:
        if hasattr(request, "resolver_match") and request.resolver_match:
            func = request.resolver_match.func
            if hasattr(func, "__module__") and hasattr(func, "__name__"):
                return f"{func.__module__}.{func.__name__}"
        return None

    @staticmethod
    def _get_route_params(request: Any) -> Optional[Dict[str, Any]]:
        if hasattr(request, "resolver_match") and request.resolver_match:
            return request.resolver_match.kwargs
        return None

    def should_track_endpoint(self, request: Any) -> bool:
        view_name = self._get_view_name(request)
        return view_name is not None and self.registry.get_extractor(view_name) is not None


class AuthActivityExtractor(ActivityExtractor):
    HANDLED_VIEWS = {
        "core.api.login",
        "core.api.register",
    }

    def can_handle(self, view_name: str) -> bool:
        return view_name in self.HANDLED_VIEWS

    def extract(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]] = None
    ) -> ActivityData:
        view_name = ActivityMetadataService._get_view_name(request)

        if view_name == "core.api.login":
            return self._extract_login(request, response_data)
        elif view_name == "core.api.register":
            return self._extract_registration(request, response_data)

        return ActivityData(
            activity_type="",
            activity_category="",
            action_verb="",
            activity_status="",
            description="",
            short_description="",
            resource_type="",
        )

    def _extract_login(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        data = response_data.get("data", {})
        user_profile = data.get("user_profile", {})
        user = user_profile.get("user", {})

        activity_data = ActivityData(
            activity_type=AuthActivityType.USER_LOGIN.value,
            activity_category=ActivityCategory.AUTH.value,
            action_verb=ActionVerb.READ.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"User {user.get('email', 'unknown')} logged in successfully",
            short_description="User logged in",
            resource_type="User",
            resource_id=user.get("id"),
            metadata={
                "user_type": user.get("user_type"),
                "login_method": "password",
                "user_email": user.get("email"),
                "user_id": user.get("id"),
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_registration(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        data = response_data.get("data", {})
        user_profile = data.get("user_profile", {})
        user = user_profile.get("user", {})

        activity_data = ActivityData(
            activity_type=AuthActivityType.USER_REGISTRATION.value,
            activity_category=ActivityCategory.AUTH.value,
            action_verb=ActionVerb.CREATE.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"New user registered: {user.get('email', 'unknown')}",
            short_description="User registered",
            resource_type="User",
            resource_id=user.get("id"),
            metadata={
                "user_type": user.get("user_type"),
                "user_email": user.get("email"),
                "user_id": user.get("id"),
                "account_type": user.get("user_type"),
                "organization_id": user.get("organization", {}).get("id") if user.get("organization") else None,
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)


class ProjectActivityExtractor(ActivityExtractor):
    HANDLED_VIEWS = {
        "core.api.create_project",
        "core.api.update_project_status",
        "core.api.archive_project",
    }

    def can_handle(self, view_name: str) -> bool:
        return view_name in self.HANDLED_VIEWS

    def extract(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]] = None
    ) -> ActivityData:
        view_name = ActivityMetadataService._get_view_name(request)

        if view_name == "core.api.create_project":
            return self._extract_project_created(request, response_data)
        elif view_name == "core.api.update_project_status":
            return self._extract_status_update(request, response_data, route_params)
        elif view_name == "core.api.archive_project":
            return self._extract_archive(request, response_data, route_params)

        return ActivityData(
            activity_type="",
            activity_category="",
            action_verb="",
            activity_status="",
            description="",
            short_description="",
            resource_type="",
        )

    def _extract_project_created(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        project = response_data.get("data", {})

        activity_data = ActivityData(
            activity_type=ProjectActivityType.PROJECT_CREATED.value,
            activity_category=ActivityCategory.PROJECT.value,
            action_verb=ActionVerb.CREATE.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"Created project '{project.get('name', 'Unknown')}'",
            short_description="Project created",
            resource_type="Project",
            resource_id=project.get("id"),
            project_id=project.get("id"),
            amount=project.get("target_amount"),
            currency=project.get("currency", "NGN"),
            metadata={
                "project_name": project.get("name"),
                "project_type": project.get("project_type"),
                "project_id": project.get("id"),
                "target_amount": project.get("target_amount"),
                "organization_id": project.get("organization", {}).get("id"),
                "organization_name": project.get("organization", {}).get("org_name"),
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_status_update(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]]
    ) -> ActivityData:
        project_id = None
        if route_params:
            project_id = route_params.get("project_id")

        if not project_id and hasattr(request, "path"):
            match = re.search(r"/([^/]+)/status", request.path)
            if match:
                project_id = match.group(1)

        new_status = None
        old_status = None
        if hasattr(request, "body"):
            try:
                body = json.loads(request.body) if isinstance(request.body, bytes) else request.body
                if isinstance(body, dict):
                    new_status = body.get("status")
                    old_status = body.get("old_status")
            except Exception as e:
                logger.w("Failed to parse request body for status update", description=str(e))
                pass

        activity_data = ActivityData(
            activity_type=ProjectActivityType.STATUS_UPDATED.value,
            activity_category=ActivityCategory.PROJECT.value,
            action_verb=ActionVerb.UPDATE.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"Updated project status to {new_status}" if new_status else "Updated project status",
            short_description="Status updated",
            resource_type="Project",
            resource_id=project_id,
            project_id=project_id,
            metadata={
                "project_id": project_id,
                "new_status": new_status,
                "old_status": old_status,
                "message": response_data.get("data", {}).get("message"),
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_archive(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]]
    ) -> ActivityData:
        """Extract project archive activity metadata"""

        project_id = None
        if route_params:
            project_id = route_params.get("project_id")

        if not project_id and hasattr(request, "path"):
            match = re.search(r"/([^/]+)/archive", request.path)
            if match:
                project_id = match.group(1)

        activity_data = ActivityData(
            activity_type=ProjectActivityType.PROJECT_ARCHIVED.value,
            activity_category=ActivityCategory.PROJECT.value,
            action_verb=ActionVerb.ARCHIVED.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description="Archived project and withdrew remaining funds",
            short_description="Project archived",
            resource_type="Project",
            resource_id=project_id,
            project_id=project_id,
            metadata={
                "project_id": project_id,
                "message": response_data.get("data", {}).get("message"),
                "note": "Archiving automatically triggers fund withdrawal to organization wallet",
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)


class FinancialActivityExtractor(ActivityExtractor):
    """Handles financial operations (Funding, Withdrawal, Disbursement, Donations)."""

    HANDLED_VIEWS = {
        "core.api.fund_project",
        "core.api.withdraw_funds",
        "core.api.disburse_items",
        "core.api.create_unprocessed_donation",
        "core.api.fund_organization_wallet",
        "core.api.create_bulk_beneficiaries",
    }

    def can_handle(self, view_name: str) -> bool:
        return view_name in self.HANDLED_VIEWS

    def extract(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]] = None
    ) -> ActivityData:
        view_name = ActivityMetadataService._get_view_name(request)

        if view_name == "core.api.fund_project":
            return self._extract_project_funded(request, response_data)
        elif view_name == "core.api.withdraw_funds":
            return self._extract_withdrawal(request, response_data, route_params)
        elif view_name == "core.api.disburse_items":
            return self._extract_disbursement(request, response_data)
        elif view_name == "core.api.create_unprocessed_donation":
            return self._extract_donation(request, response_data)
        elif view_name == "core.api.fund_organization_wallet":
            return self._extract_org_funding(request, response_data)
        elif view_name == "core.api.create_bulk_beneficiaries":
            return self._extract_beneficiary_added(request, response_data)

        return ActivityData(
            activity_type="",
            activity_category="",
            action_verb="",
            activity_status="",
            description="",
            short_description="",
            resource_type="",
        )

    def _extract_project_funded(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        """Extract project funding activity metadata"""

        data = response_data.get("data", {})
        amount = None
        currency = None
        project_id = None

        if hasattr(request, "body"):
            try:
                body = json.loads(request.body) if isinstance(request.body, bytes) else request.body
                if isinstance(body, dict):
                    amount = body.get("amount")
                    project_id = body.get("project_id")
            except Exception as e:
                logger.w("Failed to parse request body for project funding", description=str(e))

        activity_data = ActivityData(
            activity_type=ProjectActivityType.PROJECT_FUNDED.value,
            activity_category=ActivityCategory.PROJECT.value,
            action_verb=ActionVerb.EXECUTE.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"Funded project with {currency or 'NGN'} {amount or 'unknown amount'}",
            short_description="Project funded",
            resource_type="Project",
            resource_id=project_id,
            project_id=project_id,
            amount=amount,
            currency=currency,
            metadata={
                "message": data.get("message"),
                "amount": amount,
                "currency": currency or "NGN",
                "project_id": project_id,
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_withdrawal(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]]
    ) -> ActivityData:
        """Extract project withdrawal activity metadata"""

        project_id = None
        if route_params:
            project_id = route_params.get("project_id")

        if not project_id and hasattr(request, "path"):
            match = re.search(r"/account/([^/]+)/withdraw", request.path)
            if match:
                project_id = match.group(1)

        activity_data = ActivityData(
            activity_type=ProjectActivityType.PROJECT_WITHDRAWAL.value,
            activity_category=ActivityCategory.PROJECT.value,
            action_verb=ActionVerb.WITHDREW.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description="Withdrew funds from project",
            short_description="Funds withdrawn",
            resource_type="Project",
            resource_id=project_id,
            project_id=project_id,
            metadata={
                "project_id": project_id,
                "message": response_data.get("data", {}).get("message"),
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_disbursement(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        """Extract item disbursement activity metadata"""

        project_id = None
        beneficiary_count = 0
        disbursement_style = None

        if hasattr(request, "body"):
            try:
                body = json.loads(request.body) if isinstance(request.body, bytes) else request.body
                if isinstance(body, dict):
                    project_id = body.get("project_id")
                    beneficiary_ids = body.get("beneficiary_ids", [])
                    beneficiary_count = len(beneficiary_ids) if beneficiary_ids else 0
                    disbursement_style = body.get("disbursement_style")
            except Exception as e:
                logger.w("Failed to parse request body for disbursement", description=str(e))

        activity_data = ActivityData(
            activity_type=ProjectActivityType.ITEMS_DISBURSED.value,
            activity_category=ActivityCategory.PROJECT.value,
            action_verb=ActionVerb.DISBURSED.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"Disbursed items to {beneficiary_count or 'all'} beneficiar{'ies' if beneficiary_count != 1 else 'y'}",
            short_description="Items disbursed",
            resource_type="Disbursement",
            project_id=project_id,
            metadata={
                "project_id": project_id,
                "beneficiary_count": beneficiary_count,
                "disbursement_style": disbursement_style,
                "message": response_data.get("message"),
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_donation(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        """Extract pending donation creation activity metadata"""

        project_id = None
        amount = None
        currency = None
        payment_method = None

        if hasattr(request, "body"):
            try:
                body = json.loads(request.body) if isinstance(request.body, bytes) else request.body
                if isinstance(body, dict):
                    project_id = body.get("project_id")
                    amount = body.get("amount")
                    currency = body.get("currency")
                    payment_method = body.get("payment_method") or body.get("payment_client_type")
            except Exception as e:
                logger.w("Failed to parse request body for donation", description=str(e))

        data = response_data.get("data", {})
        if not amount and "amount" in data:
            amount = data.get("amount")
        if not currency and "currency" in data:
            currency = data.get("currency")

        activity_data = ActivityData(
            activity_type=ProjectActivityType.DONATION_CREATED.value,
            activity_category=ActivityCategory.DONATION.value,
            action_verb=ActionVerb.CREATED.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"Created pending donation of {amount} {currency}"
            if amount and currency
            else "Created pending donation",
            short_description="Donation created",
            resource_type="Donation",
            project_id=project_id,
            metadata={
                "project_id": project_id,
                "amount": amount,
                "currency": currency,
                "payment_method": payment_method,
                "status": "pending",
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_org_funding(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        """Extract organization wallet funding activity metadata"""

        amount = None
        currency = None
        payment_method = None
        is_donation = False
        project_id = None

        if hasattr(request, "body"):
            try:
                body = json.loads(request.body) if isinstance(request.body, bytes) else request.body
                if isinstance(body, dict):
                    amount = body.get("amount")
                    currency = body.get("currency")
                    payment_method = body.get("payment_client_type")
                    is_donation = body.get("is_donation", False)
                    project_id = body.get("project_id")
            except Exception as e:
                logger.w("Failed to parse request body for organization funding", description=str(e))

        activity_type = WalletActivityType.WALLET_FUNDED.value
        description = (
            f"Initiated organization wallet funding of {amount} {currency}"
            if amount and currency
            else "Initiated organization wallet funding"
        )

        if is_donation and project_id:
            activity_type = ProjectActivityType.DONATION_CREATED.value
            description = (
                f"Initiated donation of {amount} {currency} to project"
                if amount and currency
                else "Initiated project donation"
            )

        activity_data = ActivityData(
            activity_type=activity_type,
            activity_category=ActivityCategory.WALLET.value if not is_donation else ActivityCategory.DONATION.value,
            action_verb=ActionVerb.FUNDED.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=description,
            short_description="Wallet funded" if not is_donation else "Donation initiated",
            resource_type="OrganizationWallet",
            project_id=project_id if is_donation else None,
            amount=amount,
            currency=currency,
            metadata={
                "amount": amount,
                "currency": currency,
                "payment_method": payment_method,
                "is_donation": is_donation,
                "project_id": project_id,
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)

    def _extract_beneficiary_added(self, request: Any, response_data: Dict[str, Any]) -> ActivityData:
        """Extract beneficiary addition activity metadata"""

        data = response_data.get("data", {})
        count = None
        project_id = None

        if hasattr(request, "body"):
            try:
                body = json.loads(request.body) if isinstance(request.body, bytes) else request.body
                if isinstance(body, dict):
                    members = body.get("members", [])
                    count = len(members) if isinstance(members, list) else 1
                    project_id = body.get("project_id")
            except Exception as e:
                logger.w("Failed to parse request body for beneficiary addition", description=str(e))

        count = count or 1

        activity_data = ActivityData(
            activity_type=ProjectActivityType.BENEFICIARY_ADDED.value,
            activity_category=ActivityCategory.PROJECT.value,
            action_verb=ActionVerb.CREATE.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"Added {count} beneficiar{'ies' if count > 1 else 'y'} to project",
            short_description="Beneficiary added",
            resource_type="Beneficiary",
            project_id=project_id,
            metadata={
                "beneficiary_count": count,
                "project_id": project_id,
                "message": data.get("message"),
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)


class VerificationActivityExtractor(ActivityExtractor):
    """Handles KYC/verification activities."""

    HANDLED_VIEWS = {
        "core.api.kyc_identity_verification",
        "core.api.user_kyc",
    }

    def can_handle(self, view_name: str) -> bool:
        return view_name in self.HANDLED_VIEWS

    def extract(
        self, request: Any, response_data: Dict[str, Any], route_params: Optional[Dict[str, Any]] = None
    ) -> ActivityData:
        """Extract KYC submission activity metadata"""

        data = response_data.get("data", response_data)

        kyc_type = "KYC"
        if hasattr(request, "path"):
            if "user/kyc" in request.path:
                kyc_type = "User KYC"
            elif "kyc-identity-verification" in request.path:
                kyc_type = "Beneficiary KYC"

        activity_data = ActivityData(
            activity_type=VerificationActivityType.KYC_SUBMITTED.value,
            activity_category=ActivityCategory.VERIFICATION.value,
            action_verb=ActionVerb.SUBMIT.value,
            activity_status=ActivityStatus.SUCCESS.value,
            description=f"Submitted {kyc_type} verification documents",
            short_description="KYC submitted",
            resource_type="KYCRequest",
            resource_id=data.get("id"),
            metadata={
                "kyc_type": kyc_type,
                "kyc_id": data.get("id"),
                "document_number": data.get("id_number") or data.get("document_number"),
                "verification_status": data.get("status", "in-progress"),
                "provider": data.get("provider"),
            },
        )

        return RequestContextExtractor.merge_activity_data(request, activity_data)


def create_default_registry() -> ActivityRegistry:
    logger.d("Creating activity registry")
    registry = ActivityRegistry()
    registry.register(AuthActivityExtractor())
    registry.register(ProjectActivityExtractor())
    registry.register(FinancialActivityExtractor())
    registry.register(VerificationActivityExtractor())
    logger.i(f"Registry created with {len(registry._extractors)} extractors")
    return registry


_default_service: Optional[ActivityMetadataService] = None


def get_activity_service() -> ActivityMetadataService:
    global _default_service
    if _default_service is None:
        logger.i("Initializing global activity service")
        registry = create_default_registry()
        _default_service = ActivityMetadataService(registry)
    return _default_service
