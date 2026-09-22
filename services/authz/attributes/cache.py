"""Bounded-TTL, positive-only cache in front of a live IamTenantResolver
(typically DynamoDbIamTenantResolver) -- every /v1/authorize call
resolves a principal on the hot path (api/routes.py), so an uncached
GetItem per request adds DynamoDB cost/latency that scales with
traffic for no real benefit: a principal's tenant/application/roles
change only on an onboarding event, not per request.

Same bounded-TTL shape as platform-control-plane's own
policy/cache.py's PolicySnapshotCache, minus its push-invalidation
half: that cache's invalidate(tenant_id) is called synchronously by
its own admin endpoint in the same process. Onboarding writes here
land in DynamoDB from a DIFFERENT service entirely
(bedrock-runtime-gateway-app's onboarding/provisioning.py), with no
call path back into this process to push an invalidation -- so ttl_s
alone bounds staleness, same as this platform's other cross-service
cache of this shape (bedrock-runtime-gateway-app's own JWKS cache).

Deliberately caches only successful resolutions, never an AuthzError
(unknown principal): caching a miss would mean a principal onboarded
moments ago could keep seeing UNKNOWN_IAM_PRINCIPAL for up to ttl_s
after they're actually mapped, which is a worse failure mode than the
plain latency/cost this cache exists to cut. An unmapped principal is
already the fast, no-I/O-savings-lost path in DynamoDB terms (a
GetItem for a nonexistent key is not meaningfully cheaper to skip than
one for an existing item), so there's no real tradeoff being given up
here.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict

from .resolver import IamPrincipalGrant, IamTenantResolver


@dataclass
class _CachedGrant:
    grant: IamPrincipalGrant
    cached_at: float


class CachedIamTenantResolver:
    def __init__(
        self,
        wrapped: IamTenantResolver,
        *,
        ttl_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._wrapped = wrapped
        self._ttl_s = ttl_s
        self._clock = clock
        self._cache: Dict[str, _CachedGrant] = {}
        self._lock = threading.Lock()

    def resolve(self, principal_arn: str) -> IamPrincipalGrant:
        with self._lock:
            cached = self._cache.get(principal_arn)
            if cached is not None and (self._clock() - cached.cached_at) < self._ttl_s:
                return cached.grant

        # Miss (never cached or TTL-expired) -- refetch from the
        # wrapped resolver. Deliberately outside the lock: that call
        # may do real network I/O (DynamoDB GetItem) and shouldn't
        # block other principals' cache hits while it's in flight.
        # Raises straight through on AuthzError -- never cached, see
        # module docstring.
        grant = self._wrapped.resolve(principal_arn)
        with self._lock:
            self._cache[principal_arn] = _CachedGrant(grant=grant, cached_at=self._clock())
        return grant

    def list_grants(self) -> Dict[str, IamPrincipalGrant]:
        # GET /v1/grants (admin visibility) is not the hot path
        # resolve() is -- no caching benefit worth trading staleness
        # for here. Always live.
        return self._wrapped.list_grants()
