import json
import unittest

from starlette.testclient import TestClient

from ..config import load_settings
from ..main import create_app
from ..policy_engine import PolicyRule
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


def _app(grants, authz_rules=None):
    app = create_app(
        settings=load_settings(), iam_tenant_resolver=FakeResolver(grants), authz_rules=authz_rules
    )
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

    def test_honors_incoming_request_id_header(self):
        """gateway-api's HttpIamTenantResolver forwards its own request_id
        as this header so a decision here correlates with the caller's
        gateway.chat/gateway.access log lines -- a fresh uuid4 would sever
        that link."""
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
                headers={"x-request-id": "req-abc-123"},
                json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}, "action": "llm.invoke"},
            )

        self.assertEqual(cm.records[0].request_id, "req-abc-123")

    def test_generates_request_id_when_header_absent(self):
        client = _app({})

        with self.assertLogs("authz-service", level="INFO") as cm:
            client.post(
                "/v1/authorize",
                json={"identity": {"subject": "arn:aws:iam::123:role/unknown", "auth_type": "aws_iam"}, "action": "llm.invoke"},
            )

        self.assertTrue(cm.records[0].request_id)


class AuthorizeTracingTests(unittest.TestCase):
    """gateway-api's HttpIamTenantResolver always injects a W3C
    traceparent header -- extracting it here (instead of ignoring it)
    is what makes this service's span a CHILD of the caller's, landing
    in the same trace instead of an unrelated one."""

    def test_extracts_incoming_traceparent(self):
        from unittest.mock import patch

        from .. import main as main_module

        client = _app(
            {
                "arn:aws:iam::123:role/x": IamPrincipalGrant(
                    tenant_id="search", application_id="search-dev", roles=["developer"]
                )
            }
        )
        traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

        with patch.object(main_module, "extract", wraps=main_module.extract) as mock_extract:
            client.post(
                "/v1/authorize",
                headers={"traceparent": traceparent},
                json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}, "action": "llm.invoke"},
            )

        mock_extract.assert_called_once()
        (carrier,), _ = mock_extract.call_args
        self.assertEqual(carrier.get("traceparent"), traceparent)


class AuthorizeSessionIdTests(unittest.TestCase):
    """session_id, when gateway-api's HttpIamTenantResolver forwards
    one, ends up on the decision log line (see telemetry/logging.py's
    session_id_ctx) -- never invented when absent, unlike request_id.

    session_id isn't an explicit log_event() field (see main.py) --
    JsonFormatter reads it from session_id_ctx at format() time, which
    only reflects the right value *during* the request (main.py resets
    it in a finally before client.post() returns), so these tests
    attach a real JsonFormatter-backed handler and capture its actual
    output live, the same pattern bedrock-gateway-app's
    PiiSafeLoggingTests uses -- asserting on the LogRecord after the
    fact (as assertLogs does) would see the contextvar already reset.
    """

    def _capture_formatted_output(self, post_fn):
        import io
        import logging

        from ..telemetry.logging import JsonFormatter

        captured = io.StringIO()
        handler = logging.StreamHandler(captured)
        handler.setFormatter(JsonFormatter())
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            post_fn()
        finally:
            root.removeHandler(handler)
        return captured.getvalue()

    def test_session_id_is_logged_when_present(self):
        client = _app(
            {
                "arn:aws:iam::123:role/x": IamPrincipalGrant(
                    tenant_id="search", application_id="search-dev", roles=["developer"]
                )
            }
        )

        output = self._capture_formatted_output(
            lambda: client.post(
                "/v1/authorize",
                headers={"x-session-id": "sess-abc-123"},
                json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}, "action": "llm.invoke"},
            )
        )

        lines = [json.loads(line) for line in output.splitlines() if line.strip()]
        decision_lines = [line for line in lines if line.get("message") == "authorize decision"]
        self.assertEqual(len(decision_lines), 1)
        self.assertEqual(decision_lines[0]["session_id"], "sess-abc-123")

    def test_session_id_absent_from_log_when_not_sent(self):
        client = _app({})

        output = self._capture_formatted_output(
            lambda: client.post(
                "/v1/authorize",
                json={"identity": {"subject": "arn:aws:iam::123:role/unknown", "auth_type": "aws_iam"}, "action": "llm.invoke"},
            )
        )

        lines = [json.loads(line) for line in output.splitlines() if line.strip()]
        decision_lines = [line for line in lines if line.get("message") == "authorize decision"]
        self.assertEqual(len(decision_lines), 1)
        self.assertNotIn("session_id", decision_lines[0])


class PolicyEngineWiringTests(unittest.TestCase):
    """Plan section 35.4: confirms policy_engine.evaluate() is actually
    wired into POST /v1/authorize, not just unit-tested in isolation
    (test_policy_engine.py owns the engine's own logic)."""

    def test_known_principal_with_no_rules_gets_default_policy_id(self):
        client = _app(
            {"arn:aws:iam::123:role/x": IamPrincipalGrant(tenant_id="search", application_id="a", roles=["developer"])},
            authz_rules=[],
        )

        resp = client.post(
            "/v1/authorize",
            json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}, "action": "llm.invoke"},
        )

        body = resp.json()
        self.assertEqual(body["decision"], "ALLOW")
        self.assertEqual(body["policy_id"], "default-allow-known-principal-v1")
        self.assertEqual(body["policy_version"], 1)

    def test_rule_deny_by_resource_id_is_enforced(self):
        client = _app(
            {"arn:aws:iam::123:role/x": IamPrincipalGrant(tenant_id="search", application_id="a", roles=["developer"])},
            authz_rules=[
                PolicyRule(
                    rule_id="deny-bad-model", version=3, effect="DENY", action="llm.invoke",
                    denied_resource_ids=["bad-model"],
                )
            ],
        )

        resp = client.post(
            "/v1/authorize",
            json={
                "identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"},
                "action": "llm.invoke",
                "resource": {"type": "model", "id": "bad-model"},
            },
        )

        body = resp.json()
        self.assertEqual(body["decision"], "DENY")
        self.assertEqual(body["policy_id"], "deny-bad-model")
        self.assertEqual(body["policy_version"], 3)

    def test_rule_allows_a_different_resource_id(self):
        client = _app(
            {"arn:aws:iam::123:role/x": IamPrincipalGrant(tenant_id="search", application_id="a", roles=["developer"])},
            authz_rules=[
                PolicyRule(
                    rule_id="deny-bad-model", version=1, effect="DENY", action="llm.invoke",
                    denied_resource_ids=["bad-model"],
                )
            ],
        )

        resp = client.post(
            "/v1/authorize",
            json={
                "identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"},
                "action": "llm.invoke",
                "resource": {"type": "model", "id": "good-model"},
            },
        )

        self.assertEqual(resp.json()["decision"], "ALLOW")

    def test_rule_deny_by_data_classification_is_enforced(self):
        client = _app(
            {"arn:aws:iam::123:role/x": IamPrincipalGrant(tenant_id="search", application_id="a", roles=["developer"])},
            authz_rules=[
                PolicyRule(
                    rule_id="deny-phi", version=1, effect="DENY", action="llm.invoke",
                    max_data_classification="internal",
                )
            ],
        )

        resp = client.post(
            "/v1/authorize",
            json={
                "identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"},
                "action": "llm.invoke",
                "context": {"data_classification": "phi"},
            },
        )

        body = resp.json()
        self.assertEqual(body["decision"], "DENY")
        self.assertEqual(body["policy_id"], "deny-phi")

    def test_role_scoped_rule_is_enforced(self):
        client = _app(
            {"arn:aws:iam::123:role/x": IamPrincipalGrant(tenant_id="search", application_id="a", roles=["developer"])},
            authz_rules=[
                PolicyRule(rule_id="deny-developer-invoke", version=1, effect="DENY", roles_any_of=["developer"])
            ],
        )

        resp = client.post(
            "/v1/authorize",
            json={"identity": {"subject": "arn:aws:iam::123:role/x", "auth_type": "aws_iam"}, "action": "llm.invoke"},
        )

        self.assertEqual(resp.json()["decision"], "DENY")

    def test_unknown_principal_still_denied_before_any_rule_evaluation(self):
        client = _app(
            {},
            authz_rules=[PolicyRule(rule_id="allow-everything", version=1, effect="ALLOW", action="*")],
        )

        resp = client.post(
            "/v1/authorize",
            json={"identity": {"subject": "arn:aws:iam::123:role/unknown", "auth_type": "aws_iam"}, "action": "llm.invoke"},
        )

        body = resp.json()
        self.assertEqual(body["decision"], "DENY")
        self.assertEqual(body["policy_id"], "iam-principal-mapping-v1")


if __name__ == "__main__":
    unittest.main()
