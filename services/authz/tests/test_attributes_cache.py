import unittest

from ..attributes.cache import CachedIamTenantResolver
from ..attributes.resolver import AuthzError, IamPrincipalGrant


class _FakeResolver:
    def __init__(self, grants, *, fail_arns=()):
        self._grants = dict(grants)
        self._fail_arns = set(fail_arns)
        self.resolve_calls = 0
        self.list_grants_calls = 0

    def resolve(self, principal_arn):
        self.resolve_calls += 1
        if principal_arn in self._fail_arns:
            raise AuthzError(f"no tenant mapping for IAM principal '{principal_arn}'", code="UNKNOWN_IAM_PRINCIPAL")
        return self._grants[principal_arn]

    def list_grants(self):
        self.list_grants_calls += 1
        return dict(self._grants)


class _FakeClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


_GRANT = IamPrincipalGrant(tenant_id="search", application_id="search-dev", roles=["developer"])
_ARN = "arn:aws:iam::123:role/x"


class CachedIamTenantResolverTests(unittest.TestCase):
    def test_second_resolve_within_ttl_is_a_cache_hit(self):
        wrapped = _FakeResolver({_ARN: _GRANT})
        clock = _FakeClock()
        cache = CachedIamTenantResolver(wrapped, ttl_s=30.0, clock=clock)

        first = cache.resolve(_ARN)
        clock.advance(10.0)
        second = cache.resolve(_ARN)

        self.assertEqual(first, _GRANT)
        self.assertEqual(second, _GRANT)
        self.assertEqual(wrapped.resolve_calls, 1)

    def test_resolve_after_ttl_expiry_refetches(self):
        wrapped = _FakeResolver({_ARN: _GRANT})
        clock = _FakeClock()
        cache = CachedIamTenantResolver(wrapped, ttl_s=30.0, clock=clock)

        cache.resolve(_ARN)
        clock.advance(30.1)
        cache.resolve(_ARN)

        self.assertEqual(wrapped.resolve_calls, 2)

    def test_unknown_principal_is_never_cached(self):
        wrapped = _FakeResolver({}, fail_arns=[_ARN])
        cache = CachedIamTenantResolver(wrapped, ttl_s=30.0, clock=_FakeClock())

        with self.assertRaises(AuthzError):
            cache.resolve(_ARN)
        with self.assertRaises(AuthzError):
            cache.resolve(_ARN)

        self.assertEqual(wrapped.resolve_calls, 2)

    def test_newly_onboarded_principal_is_seen_on_first_resolve_after_failure(self):
        """A principal unmapped a moment ago, now onboarded -- since
        failures are never cached, the very next resolve() sees the
        fresh grant instead of a stale UNKNOWN_IAM_PRINCIPAL."""
        wrapped = _FakeResolver({}, fail_arns=[_ARN])
        cache = CachedIamTenantResolver(wrapped, ttl_s=30.0, clock=_FakeClock())

        with self.assertRaises(AuthzError):
            cache.resolve(_ARN)

        wrapped._fail_arns.discard(_ARN)
        wrapped._grants[_ARN] = _GRANT

        self.assertEqual(cache.resolve(_ARN), _GRANT)

    def test_list_grants_always_delegates_uncached(self):
        wrapped = _FakeResolver({_ARN: _GRANT})
        cache = CachedIamTenantResolver(wrapped, ttl_s=30.0, clock=_FakeClock())

        cache.list_grants()
        cache.list_grants()

        self.assertEqual(wrapped.list_grants_calls, 2)

    def test_distinct_principals_cached_independently(self):
        other_arn = "arn:aws:iam::123:role/y"
        other_grant = IamPrincipalGrant(tenant_id="finance", application_id="finance-app", roles=["manager"])
        wrapped = _FakeResolver({_ARN: _GRANT, other_arn: other_grant})
        cache = CachedIamTenantResolver(wrapped, ttl_s=30.0, clock=_FakeClock())

        self.assertEqual(cache.resolve(_ARN), _GRANT)
        self.assertEqual(cache.resolve(other_arn), other_grant)
        self.assertEqual(cache.resolve(_ARN), _GRANT)
        self.assertEqual(cache.resolve(other_arn), other_grant)

        self.assertEqual(wrapped.resolve_calls, 2)


if __name__ == "__main__":
    unittest.main()
