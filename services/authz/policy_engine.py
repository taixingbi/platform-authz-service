"""Real PDP rule evaluation (plan section 35.4, P0 production
hardening).

Before this: `main.py`'s own comment was accurate and honest -- "the
one real rule this MVP enforces is: is the principal known at all,"
with `action`/`resource`/`context` already on the wire contract
(`models.py`'s `AuthorizeRequest`) but unused. This module is what
makes them matter: an ordered list of versioned `PolicyRule`s, each
with match conditions (action, tenant, roles, resource, data
classification) and an effect (ALLOW/DENY) -- first match wins, no
match falls through to a default-allow-known-principal decision
(same behavior this service already had, now the explicit fallback
rather than the only rule).

Honest scope note, not hidden: `bedrock-runtime-gateway-app`'s own
`HttpIamTenantResolver.resolve()` call happens during Stage 1
(authentication), before the requested model is even resolved
(Stage 4c) -- so today's real traffic sends `action="llm.invoke"`
with no `resource`/`context` at all. Rules with no resource/
classification condition (role- or tenant-scoped rules) evaluate
correctly against real traffic today; rules that key on `resource`/
`context` only fire for a caller that actually sends them (this
service's own tests, or a future gateway-app change that moves/adds
an authorization call after model resolution). Not silently implied
as fully wired end-to-end where it isn't yet.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Same table bedrock-runtime-gateway-app's routing/model_registry.py and
# policy/validation.py use -- kept as an independent literal here
# (this service has no dependency on that repo), same "hand-kept in
# sync, documented as a real limitation" tradeoff those already accept.
_CLASSIFICATION_RANK = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "phi": 3,
    "pii": 3,
}


def classification_rank(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    return _CLASSIFICATION_RANK.get(str(value).strip().lower())


DEFAULT_POLICY_ID = "default-allow-known-principal-v1"
DEFAULT_POLICY_VERSION = 1

# Plan section 35.17 (P0 production hardening): the fail-closed
# counterpart to DEFAULT_POLICY_ID above -- what a known principal
# gets instead, in an environment where Settings.default_allow_unmatched
# is False. See evaluate()'s own docstring.
DEFAULT_DENY_POLICY_ID = "default-deny-no-matching-rule-v1"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    version: int
    effect: str  # "ALLOW" | "DENY"
    action: str = "*"  # exact match, or "*" for any action
    tenant_id: Optional[str] = None  # None/"*" applies to every tenant
    roles_any_of: List[str] = field(default_factory=list)  # empty = no role condition
    # Resource/classification conditions -- a rule with NEITHER set
    # matches on identity/action/tenant/role alone (a plain access
    # rule). A rule with either set only matches when that specific
    # condition is triggered (see _matches_resource_condition).
    denied_resource_ids: List[str] = field(default_factory=list)
    max_data_classification: Optional[str] = None
    priority: int = 0  # higher evaluated first among rules with equal specificity


@dataclass(frozen=True)
class PolicyDecision:
    decision: str  # "ALLOW" | "DENY"
    policy_id: str
    policy_version: int
    reason: str


def load_rules_from_yaml(path: str) -> List[PolicyRule]:
    """Tolerant of a missing/empty path -- same convention every other
    file-backed store in this platform uses; returns no rules (every
    decision falls through to the default-allow-known-principal
    behavior this service already had)."""
    import yaml

    if not path or not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    rules: List[PolicyRule] = []
    for rule_id, cfg in (raw.get("authz_rules") or {}).items():
        cfg = cfg or {}
        rules.append(
            PolicyRule(
                rule_id=rule_id,
                version=int(cfg.get("version", 1)),
                effect=cfg["effect"],
                action=cfg.get("action", "*"),
                tenant_id=cfg.get("tenant_id"),
                roles_any_of=list(cfg.get("roles_any_of", [])),
                denied_resource_ids=list(cfg.get("denied_resource_ids", [])),
                max_data_classification=cfg.get("max_data_classification"),
                priority=int(cfg.get("priority", 0)),
            )
        )
    # Highest priority first; stable sort keeps YAML order as the
    # tiebreak, so two same-priority rules evaluate in the order a
    # human reading the file would expect.
    return sorted(rules, key=lambda r: -r.priority)


def _has_resource_condition(rule: PolicyRule) -> bool:
    return bool(rule.denied_resource_ids) or rule.max_data_classification is not None


def _matches_resource_condition(rule: PolicyRule, *, resource_id: Optional[str], context: Dict[str, Any]) -> bool:
    if resource_id is not None and resource_id in rule.denied_resource_ids:
        return True
    if rule.max_data_classification is not None:
        rule_rank = classification_rank(rule.max_data_classification)
        ctx_rank = classification_rank(context.get("data_classification"))
        if rule_rank is not None and ctx_rank is not None and ctx_rank > rule_rank:
            return True
    return False


def _rule_matches(
    rule: PolicyRule, *, tenant_id: str, roles: List[str], action: str,
    resource_id: Optional[str], context: Dict[str, Any],
) -> bool:
    if rule.action != "*" and rule.action != action:
        return False
    if rule.tenant_id not in (None, "*", tenant_id):
        return False
    if rule.roles_any_of and not any(r in roles for r in rule.roles_any_of):
        return False
    if not _has_resource_condition(rule):
        return True
    return _matches_resource_condition(rule, resource_id=resource_id, context=context)


def evaluate(
    rules: List[PolicyRule],
    *,
    tenant_id: str,
    roles: List[str],
    action: str,
    resource_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    default_allow: bool = True,
) -> PolicyDecision:
    """First matching rule (by descending priority) wins, regardless of
    `default_allow` -- an explicit rule always controls; this only
    changes what happens when NO rule matches at all.

    `default_allow=True` (default): default-allow-known-principal, the
    fallback this service already had before this module existed -- a
    caller that never sends resource/context, or whose identity
    matches no configured rule, sees identical behavior to before.
    Migration-friendly: introducing authz_rules.yaml shouldn't
    retroactively deny every tenant/action nobody has written a rule
    for yet.

    `default_allow=False` (plan section 35.17, a regulated production
    environment's Settings.default_allow_unmatched): an unmatched
    request is DENIED, not allowed through a default nobody explicitly
    wrote. "Known identity" (the principal resolved to a real tenant)
    is not the same thing as "authorized identity" (a rule actually
    grants this action) -- conflating them is exactly the gap this
    parameter closes.
    """
    context = context or {}
    for rule in rules:
        if _rule_matches(rule, tenant_id=tenant_id, roles=roles, action=action, resource_id=resource_id, context=context):
            return PolicyDecision(
                decision=rule.effect,
                policy_id=rule.rule_id,
                policy_version=rule.version,
                reason=f"matched rule '{rule.rule_id}' (priority {rule.priority})",
            )
    if default_allow:
        return PolicyDecision(
            decision="ALLOW",
            policy_id=DEFAULT_POLICY_ID,
            policy_version=DEFAULT_POLICY_VERSION,
            reason="no matching rule -- default allow for a known principal",
        )
    return PolicyDecision(
        decision="DENY",
        policy_id=DEFAULT_DENY_POLICY_ID,
        policy_version=DEFAULT_POLICY_VERSION,
        reason="no matching rule -- default deny (regulated production, plan section 35.17)",
    )
