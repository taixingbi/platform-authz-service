import unittest

from starlette.testclient import TestClient

from ..config import load_settings
from ..main import create_app
from ..resolver import IamPrincipalGrant


class FakeResolver:
    def __init__(self, grants):
        self._grants = grants

    def resolve(self, principal_arn):
        from ..resolver import AuthzError

        try:
            return self._grants[principal_arn]
        except KeyError:
            raise AuthzError(f"no tenant mapping for IAM principal '{principal_arn}'", code="UNKNOWN_IAM_PRINCIPAL") from None

    def list_grants(self):
        return dict(self._grants)


def _app(grants):
    app = create_app(settings=load_settings(), iam_tenant_resolver=FakeResolver(grants))
    return TestClient(app)


class AuthorizeTests(unittest.TestCase):
    def test_known_principal_is_allowed(self):
        client = _app(
            {
                "arn:aws:iam::123:role/x": IamPrincipalGrant(
                    tenant_id="search", application_id="search-dev", roles=["developer"]
                )
            }
        )

        resp = client.post(
            "/v1/authorize",
            json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}, "action": "llm.invoke"},
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["decision"], "ALLOW")
        self.assertEqual(body["tenant_id"], "search")
        self.assertEqual(body["application_id"], "search-dev")
        self.assertEqual(body["roles"], ["developer"])

    def test_unknown_principal_is_denied(self):
        client = _app({})

        resp = client.post(
            "/v1/authorize",
            json={"identity": {"subject": "arn:aws:iam::123:role/unknown", "auth_type": "aws_iam"}, "action": "llm.invoke"},
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["decision"], "DENY")
        self.assertIsNone(body["tenant_id"])

    def test_missing_action_is_rejected(self):
        client = _app({})

        resp = client.post(
            "/v1/authorize",
            json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}},
        )

        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["code"], "INVALID_REQUEST")

    def test_list_grants(self):
        client = _app(
            {"arn:aws:iam::123:role/x": IamPrincipalGrant(tenant_id="search", application_id="a", roles=["developer"])}
        )

        resp = client.get("/v1/grants")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("arn:aws:iam::123:role/x", resp.json()["grants"])

    def test_healthz(self):
        client = _app({})

        resp = client.get("/healthz")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})


class AuthorizeDecisionLoggingTests(unittest.TestCase):
    """Every /v1/authorize call logs one structured decision line --
    the audit trail a PDP needs (who, what tenant, ALLOW/DENY, which
    policy decided it), without ever logging the request's context dict
    (nothing sensitive is expected there, but it's not this service's
    business to echo it into logs)."""

    def test_allow_is_logged(self):
        client = _app(
            {
                "arn:aws:iam::123:role/x": IamPrincipalGrant(
                    tenant_id="search", application_id="search-dev", roles=["developer"]
                )
            }
        )

        with self.assertLogs("authz-service", level="INFO") as cm:
            client.post(
                "/v1/authorize",
                json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}, "action": "llm.invoke"},
            )

        record = cm.records[0]
        self.assertEqual(record.decision, "ALLOW")
        self.assertEqual(record.subject, "arn:aws:iam::123:role/x")
        self.assertEqual(record.tenant_id, "search")
        self.assertTrue(record.request_id)

    def test_deny_is_logged(self):
        client = _app({})

        with self.assertLogs("authz-service", level="INFO") as cm:
            client.post(
                "/v1/authorize",
                json={"identity": {"subject": "arn:aws:iam::123:role/unknown", "auth_type": "aws_iam"}, "action": "llm.invoke"},
            )

        record = cm.records[0]
        self.assertEqual(record.decision, "DENY")
        self.assertEqual(record.subject, "arn:aws:iam::123:role/unknown")


if __name__ == "__main__":
    unittest.main()
