"""
Distributed Redis-based lock for coordinating alert processing across HA instances.

When Keep runs in geo-redundancy (multiple instances sharing one DB), two instances
can process the same alert fingerprint concurrently.  The deduplication check
(get_last_alert_hashes_by_fingerprints) and the write (set_last_alert) are not
atomic, so both see "no duplicate" and both insert.

This module provides a context-manager that acquires a short-lived Redis lock
keyed by tenant_id + fingerprint before the critical section.  The lock blocks
(up to a timeout) until acquired, serializing per-fingerprint processing.

When Redis is not configured or unreachable, it fails open (no lock) —
single-instance deployments are unaffected.
"""

import logging
import time
from contextlib import contextmanager
from typing import Optional

from keep.api.core.config import config
from keep.api.consts import REDIS

logger = logging.getLogger(__name__)

# TTL for the alert-processing lock.  process_event typically completes in
# well under 5 seconds; 30 s is a safety margin so a crashed worker's lock
# auto-expires without blocking subsequent processing.
ALERT_LOCK_TTL = config("KEEP_ALERT_LOCK_TTL", cast=int, default=30)

# How long to wait (seconds) for a lock held by another instance before
# giving up and failing open.  Covers the normal case where the other
# instance finishes processing within a few seconds.
ALERT_LOCK_WAIT_TIMEOUT = config("KEEP_ALERT_LOCK_WAIT_TIMEOUT", cast=int, default=10)

# Polling interval (seconds) when waiting for a lock.
ALERT_LOCK_POLL_INTERVAL = 0.1

_alert_lock_redis = None


def _get_alert_lock_redis():
    """Lazy-init a sync Redis client for alert-processing locks."""
    global _alert_lock_redis
    if _alert_lock_redis is not None:
        return _alert_lock_redis
    import redis as redis_lib

    _alert_lock_redis = redis_lib.Redis(
        host=config("REDIS_HOST", default="localhost"),
        port=config("REDIS_PORT", cast=int, default=6379),
        username=config("REDIS_USERNAME", default=None),
        password=config("REDIS_PASSWORD", default=None),
        ssl=config("REDIS_SSL", cast=bool, default=False),
        socket_timeout=5,
        socket_connect_timeout=5,
        decode_responses=True,
    )
    return _alert_lock_redis


def _alert_lock_key(tenant_id: str, fingerprint: str) -> str:
    return f"lock:alert:process:{tenant_id}:{fingerprint}"


def _try_acquire(lock_key: str) -> bool:
    """Single attempt to SET NX.  Returns True if acquired."""
    client = _get_alert_lock_redis()
    return bool(client.set(lock_key, "1", nx=True, ex=ALERT_LOCK_TTL))


def _release(lock_key: str):
    """Best-effort delete."""
    client = _get_alert_lock_redis()
    client.delete(lock_key)


@contextmanager
def alert_processing_lock(tenant_id: str, fingerprint: Optional[str]):
    """
    Context manager that acquires a distributed Redis lock keyed by
    tenant_id + fingerprint, blocking up to ALERT_LOCK_WAIT_TIMEOUT seconds
    until the lock is acquired.

    Yields True if the lock was acquired (or Redis is not configured / failed —
    fail-open).  The lock is automatically released on exit.

    When REDIS is not enabled (single-instance deployment), the context
    manager is a no-op and always yields True.
    """
    if not REDIS or not fingerprint:
        # Single-instance or no fingerprint — no lock needed
        yield True
        return

    lock_key = _alert_lock_key(tenant_id, fingerprint)
    acquired = False
    deadline = time.monotonic() + ALERT_LOCK_WAIT_TIMEOUT

    # First attempt
    try:
        acquired = _try_acquire(lock_key)
    except Exception:
        logger.exception(
            "Failed to acquire alert processing lock from Redis, failing open",
            extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
        )
        # Fail open: allow processing without lock
        yield True
        return

    # If not acquired, poll until deadline
    if not acquired:
        logger.info(
            "Alert processing lock held by another instance, waiting",
            extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
        )
        while not acquired and time.monotonic() < deadline:
            time.sleep(ALERT_LOCK_POLL_INTERVAL)
            try:
                acquired = _try_acquire(lock_key)
            except Exception:
                logger.exception(
                    "Failed to retry acquiring alert processing lock, failing open",
                    extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
                )
                # Fail open
                yield True
                return

    if not acquired:
        logger.warning(
            "Timed out waiting for alert processing lock, failing open",
            extra={
                "tenant_id": tenant_id,
                "fingerprint": fingerprint,
                "wait_timeout": ALERT_LOCK_WAIT_TIMEOUT,
            },
        )
        # Fail open: allow processing without lock to avoid dropping events
        yield True
        return

    try:
        yield acquired
    finally:
        if acquired:
            try:
                _release(lock_key)
            except Exception:
                logger.exception(
                    "Failed to release alert processing lock",
                    extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
                )