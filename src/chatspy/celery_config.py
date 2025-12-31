import os
import ssl
from celery import Celery
from kombu import Queue, Exchange

app = Celery("chats", include="chatspy.tasks")


class CeleryConfig:
    def __init__(self):
        self.REDIS_URL = os.getenv("REDIS_LOCATION")

    def get_celery_config(self):
        broker_url = self.REDIS_URL

        config = {
            # Broker settings
            "broker_url": broker_url,
            "result_backend": broker_url,
            # Task settings
            "task_serializer": "json",
            "accept_content": ["json"],  # Ignore other content
            "result_serializer": "json",
            "timezone": "Africa/Lagos",
            "enable_utc": True,
            # Queue settings
            "task_queues": (
                Queue("default", Exchange("default"), routing_key="default"),
                Queue("low_priority", Exchange("low_priority"), routing_key="low_priority"),
                Queue("high_priority", Exchange("high_priority"), routing_key="high_priority"),
                Queue("authQ", Exchange("authQ"), routing_key="authQ"),
                Queue("walletQ", Exchange("walletQ"), routing_key="walletQ"),
                Queue("projectQ", Exchange("projectQ"), routing_key="projectQ"),
                # Queue("notificationQ", Exchange("notificationQ"), routing_key="notificationQ"),
            ),
            "task_routes": {
                "core.tasks.cactivate_wallet": {"queue": "walletQ"},
                "core.tasks.send_email": {"queue": "low_priority"},
                "core.tasks.send_sms": {"queue": "high_priority"},
                "core.models.cgenerate_qrcodes": {"queue": "walletQ"},
                "core.models.cgenerate_qrcodes_chunk": {"queue": "walletQ"},
                "core.models.generate_qrcodes_for_beneficiaries": {"queue": "walletQ"},
                "core.tasks.create_project_wallets": {"queue": "walletQ"},
                "core.tasks.set_beneficiary_role": {"queue": "walletQ"},
                "core.models.cgenerate_bulk_wallets": {"queue": "walletQ"},
                "core.models.requeue_disbursement_actions": {"queue": "walletQ"},
                "core.tasks.retry_create_project_wallets": {"queue": "walletQ"},
                "core.models.send_sms_tokens_async": {"queue": "walletQ"},
                "core.models.send_sms_tokens_batch": {"queue": "walletQ"},
                "core.models.generate_and_send_sms_tokens": {"queue": "walletQ"},
                "core.models.process_synced_beneficiaries": {"queue": "walletQ"},
                "core.models.process_batches_async": {"queue": "projectQ"},
                "core.models.retry_failed_batches": {"queue": "projectQ"},
                "core.tasks.retry_failed_transactions": {"queue": "authQ"},
                "core.tasks.process_unprocessed_donations": {"queue": "projectQ"},
                "core.tasks.index_organization_wallet_transactions": {"queue": "projectQ"},
            },
            # Worker settings
            "worker_concurrency": int(os.getenv("CELERY_WORKER_CONCURRENCY", "8")),
            "worker_prefetch_multiplier": 1,  # Prevents worker from prefetching too many tasks
            "worker_max_tasks_per_child": 1000,  # Restart worker after 1000 tasks
            "worker_pool": "solo" if os.getenv("IS_MACOS", "false").lower() == "true" else "prefork",
            # Task execution settings
            "task_time_limit": 3600,  # Hard time limit (seconds)
            "task_soft_time_limit": 3000,  # Soft time limit (seconds)
            # Retry settings
            "broker_connection_retry": True,
            "broker_connection_retry_on_startup": True,
            "broker_connection_max_retries": 10,
            # Result backend settings
            "result_expires": 3600,  # Expire after 1 hour
            # Error handling
            "task_annotations": {
                "*": {
                    "max_retries": 3,
                    "rate_limit": "50/s",  # Global rate limit
                    "default_retry_delay": 60,  # 1-minute delay between retries
                }
            },
            # Beat settings
            "beat_scheduler": "redbeat.RedBeatScheduler",
            "redbeat_redis_url": broker_url,
            # Logging
            "worker_log_format": "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s",
            "worker_task_log_format": "[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s",
        }

        if self.REDIS_URL and "rediss" in self.REDIS_URL:
            ssl_config = {"ssl_cert_reqs": ssl.CERT_NONE}
            config["broker_use_ssl"] = ssl_config
            config["redis_backend_use_ssl"] = ssl_config

        return config
