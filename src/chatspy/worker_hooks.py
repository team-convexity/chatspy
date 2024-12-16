import logging

from .clients import KafkaClient

loglevel = "DEBUG"

worker_class = "uvicorn.workers.UvicornWorker"
timeout = 4000

logconfig = ".service/logging.conf"

def clean(worker=None, server=None):
    logger = logging.getLogger("gunicorn.error")
    try:
        workerid = worker.pid if worker else ""
        serverpid = server.pid if server else ""
        logger.info(
            f"Cleaning up temp kafka files for Worker PID: {workerid} / Server PID: {serverpid}"
        )
        KafkaClient.cleanup()
    except Exception as e:
        logger.error(f"Error in worker_exit hook: {e}")


def worker_exit(server, worker):
    """
    gunicorn worker exit hook with full server and worker context.
    """
    clean(server=server, worker=worker)


def worker_abort(worker):
    """
    called when a worker received the SIGABRT signal.
    """
    clean(worker=worker)


def on_exit(server):
    """
    called just before exiting Gunicorn.
    """
    clean(server=server)
