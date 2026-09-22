"""Plan section 35.4: real PDP rule evaluation. Engine unit tests here
(load/match/evaluate in isolation); /v1/authorize wiring in
test_authorize.py's PolicyEngineWiringTests.
"""
import tempfile
import unittest
from pathlib import Path

from ..policy.engine import (
    DEFAULT_DENY_POLICY_ID,
    DEFAULT_POLICY_ID,
    DEFAULT_POLICY_VERSION,
    PolicyRule,
    classification_rank,
    evaluate,
    load_rules_from_yaml,
)


class ClassificationRankTests(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(classification_rank("public"), classification_rank("internal"))
        self.assertLess(classification_rank("internal"), classification_rank("confidential"))
        self.assertLess(classification_rank("confidential"), classification_rank("phi"))

    def test_pii_and_phi_equal_rank(self):
        self.assertEqual(classification_rank("pii"), classification_rank("phi"))

    def test_case_insensitive(self):
        self.assertEqual(classification_rank("PHI"), classification_rank("phi"))

    def test_unknown_is_none(self):
        self.assertIsNone(classification_rank("not-a-real-value"))

    def test_none_is_none(self):
        self.assertIsNone(classification_rank(None))


class EvaluateNoRulesTests(unittest.TestCase):
    def test_no_rules_falls_through_to_default_allow(self):
        decision = evaluate([], tenant_id="acme", roles=["developer"], action="llm.invoke")

        self.assertEqual(decision.decision, "ALLOW")
        self.assertEqual(decision.policy_id, DEFAULT_POLICY_ID)
        self.assertEqual(decision.policy_version, DEFAULT_POLICY_VERSION)

    def test_default_allow_true_is_the_implicit_default(self):
        """No default_allow kwarg at all -- same as explicitly True,
        confirming this is opt-in-to-deny, not a breaking default
        change for every existing caller."""
        decision = evaluate([], tenant_id="acme", roles=["developer"], action="llm.invoke")
        self.assertEqual(decision.decision, "ALLOW")


class EvaluateDefaultDenyTests(unittest.TestCase):
    """Plan section 35.17: default_allow=False, a regulated
    production environment's Settings.default_allow_unmatched."""

    def test_no_matching_rule_denies_when_default_allow_is_false(self):
        decision = evaluate(
            [], tenant_id="acme", roles=["developer"], action="llm.invoke", default_allow=False,
        )

        self.assertEqual(decision.decision, "DENY")
        self.assertEqual(decision.policy_id, DEFAULT_DENY_POLICY_ID)
        self.assertEqual(decision.policy_version, DEFAULT_POLICY_VERSION)

    def test_an_explicit_allow_rule_still_wins_over_default_deny(self):
        """default_allow only controls the NO-MATCH fallback -- an
        explicit rule, of either effect, always takes precedence."""
        rule = PolicyRule(rule_id="allow-developer", version=1, effect="ALLOW", roles_any_of=["developer"])

        decision = evaluate(
            [rule], tenant_id="acme", roles=["developer"], action="llm.invoke", default_allow=False,
        )

        self.assertEqual(decision.decision, "ALLOW")
        self.assertEqual(decision.policy_id, "allow-developer")

    def test_an_explicit_deny_rule_still_wins_over_default_allow(self):
        rule = PolicyRule(rule_id="deny-contractor", version=1, effect="DENY", roles_any_of=["contractor"])

        decision = evaluate(
            [rule], tenant_id="acme", roles=["contractor"], action="llm.invoke", default_allow=True,
        )

        self.assertEqual(decision.decision, "DENY")
        self.assertEqual(decision.policy_id, "deny-contractor")

    def test_non_matching_rule_still_falls_through_to_default_deny(self):
        rule = PolicyRule(rule_id="allow-manager", version=1, effect="ALLOW", roles_any_of=["manager"])

        decision = evaluate(
            [rule], tenant_id="acme", roles=["developer"], action="llm.invoke", default_allow=False,
        )

        self.assertEqual(decision.decision, "DENY")
        self.assertEqual(decision.policy_id, DEFAULT_DENY_POLICY_ID)


class EvaluateActionMatchTests(unittest.TestCase):
    def test_action_mismatch_does_not_match(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", action="other.action")]

        decision = evaluate(rules, tenant_id="acme", roles=["developer"], action="llm.invoke")

        self.assertEqual(decision.decision, "ALLOW")  # falls through, r1 didn't match

    def test_wildcard_action_matches_anything(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", action="*")]

        decision = evaluate(rules, tenant_id="acme", roles=["developer"], action="llm.invoke")

        self.assertEqual(decision.decision, "DENY")
        self.assertEqual(decision.policy_id, "r1")


class EvaluateTenantMatchTests(unittest.TestCase):
    def test_tenant_scoped_rule_only_matches_that_tenant(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", tenant_id="claims")]

        acme_decision = evaluate(rules, tenant_id="acme", roles=[], action="llm.invoke")
        claims_decision = evaluate(rules, tenant_id="claims", roles=[], action="llm.invoke")

        self.assertEqual(acme_decision.decision, "ALLOW")
        self.assertEqual(claims_decision.decision, "DENY")

    def test_wildcard_tenant_matches_every_tenant(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", tenant_id="*")]

        decision = evaluate(rules, tenant_id="anything", roles=[], action="llm.invoke")

        self.assertEqual(decision.decision, "DENY")


class EvaluateRoleMatchTests(unittest.TestCase):
    def test_roles_any_of_requires_at_least_one_match(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", roles_any_of=["manager", "platform_admin"])]

        dev_decision = evaluate(rules, tenant_id="acme", roles=["developer"], action="llm.invoke")
        mgr_decision = evaluate(rules, tenant_id="acme", roles=["manager"], action="llm.invoke")

        self.assertEqual(dev_decision.decision, "ALLOW")
        self.assertEqual(mgr_decision.decision, "DENY")

    def test_empty_roles_any_of_is_no_condition(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY")]

        decision = evaluate(rules, tenant_id="acme", roles=[], action="llm.invoke")

        self.assertEqual(decision.decision, "DENY")


class EvaluateResourceConditionTests(unittest.TestCase):
    """A rule WITH a resource/classification condition only matches
    when that condition is actually triggered -- distinct from a
    plain identity-only rule, which matches on identity alone."""

    def test_denied_resource_id_matches(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", denied_resource_ids=["bad-model"])]

        blocked = evaluate(rules, tenant_id="acme", roles=[], action="llm.invoke", resource_id="bad-model")
        allowed = evaluate(rules, tenant_id="acme", roles=[], action="llm.invoke", resource_id="good-model")
        no_resource = evaluate(rules, tenant_id="acme", roles=[], action="llm.invoke")

        self.assertEqual(blocked.decision, "DENY")
        self.assertEqual(allowed.decision, "ALLOW")
        self.assertEqual(no_resource.decision, "ALLOW")

    def test_classification_exceeds_ceiling_matches(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", max_data_classification="internal")]

        phi_request = evaluate(
            rules, tenant_id="acme", roles=[], action="llm.invoke",
            context={"data_classification": "phi"},
        )
        internal_request = evaluate(
            rules, tenant_id="acme", roles=[], action="llm.invoke",
            context={"data_classification": "internal"},
        )
        no_context = evaluate(rules, tenant_id="acme", roles=[], action="llm.invoke")

        self.assertEqual(phi_request.decision, "DENY")
        self.assertEqual(internal_request.decision, "ALLOW")  # at the ceiling, not over it
        self.assertEqual(no_context.decision, "ALLOW")

    def test_unresolvable_classification_does_not_match(self):
        rules = [PolicyRule(rule_id="r1", version=1, effect="DENY", max_data_classification="internal")]

        decision = evaluate(
            rules, tenant_id="acme", roles=[], action="llm.invoke",
            context={"data_classification": "not-a-real-value"},
        )

        self.assertEqual(decision.decision, "ALLOW")


class EvaluatePriorityTests(unittest.TestCase):
    def test_higher_priority_rule_wins(self):
        rules = [
            PolicyRule(rule_id="low-priority-allow", version=1, effect="ALLOW", priority=1),
            PolicyRule(rule_id="high-priority-deny", version=1, effect="DENY", priority=100),
        ]
        # load_rules_from_yaml sorts by priority; evaluate() takes the
        # list as given, so build it pre-sorted the way the loader would.
        sorted_rules = sorted(rules, key=lambda r: -r.priority)

        decision = evaluate(sorted_rules, tenant_id="acme", roles=[], action="llm.invoke")

        self.assertEqual(decision.policy_id, "high-priority-deny")
        self.assertEqual(decision.decision, "DENY")


class LoadRulesFromYamlTests(unittest.TestCase):
    def test_missing_file_is_empty_list(self):
        self.assertEqual(load_rules_from_yaml("/no/such/file.yaml"), [])

    def test_empty_path_is_empty_list(self):
        self.assertEqual(load_rules_from_yaml(""), [])

    def test_loads_and_sorts_by_priority_descending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authz_rules.yaml"
            path.write_text(
                """
authz_rules:
  low:
    version: 1
    effect: ALLOW
    priority: 1
  high:
    version: 2
    effect: DENY
    action: "llm.invoke"
    tenant_id: claims
    roles_any_of: [manager]
    denied_resource_ids: [bad-model]
    max_data_classification: internal
    priority: 100
"""
            )
            rules = load_rules_from_yaml(str(path))

            self.assertEqual([r.rule_id for r in rules], ["high", "low"])
            high = rules[0]
            self.assertEqual(high.version, 2)
            self.assertEqual(high.effect, "DENY")
            self.assertEqual(high.tenant_id, "claims")
            self.assertEqual(high.roles_any_of, ["manager"])
            self.assertEqual(high.denied_resource_ids, ["bad-model"])
            self.assertEqual(high.max_data_classification, "internal")

    def test_loads_the_real_platform_rules_file_without_error(self):
        """policies/authz_rules.yaml is what the running service
        actually loads by default -- confirms it parses and produces
        the two rules documented there."""
        rules = load_rules_from_yaml("policies/authz_rules.yaml")

        rule_ids = {r.rule_id for r in rules}
        self.assertIn("deny-deprecated-model-deepseek-r1", rule_ids)
        self.assertIn("require-manager-for-phi-in-prod", rule_ids)


if __name__ == "__main__":
    unittest.main()
