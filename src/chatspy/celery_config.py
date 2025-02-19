import os

from celery import Celery
from kombu import Queue, Exchange

app = Celery("chats")
class CeleryConfig:

    def __init__(self):
        self.REDIS_URL = os.getenv("REDIS_LOCATION")

    def get_celery_config(self):
        return {
            # Broker settings
            "broker_url": self.REDIS_URL,
            "result_backend": self.REDIS_URL,
            # Task settings
            "task_serializer": "json",
            "accept_content": ["json"],  # Ignore other content
            "result_serializer": "json",
            "timezone": "Africa/Lagos",
            "enable_utc": True,
            # Queue settings
            "task_queues": (
                Queue("default", Exchange("default"), routing_key="default"),
                Queue("high_priority", Exchange("high_priority"), routing_key="high_priority"),
                Queue("low_priority", Exchange("low_priority"), routing_key="low_priority"),
            ),
            "task_routes": {
                "core.tasks.send_email": {"queue": "high_priority"},
                # "core.tasks.default_task": {"queue": "default"},
                # "core.tasks.background_task": {"queue": "low_priority"},
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
            "redbeat_redis_url": self.REDIS_URL,
            # Logging
            "worker_log_format": "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s",
            "worker_task_log_format": "[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s",
    }
