#!/usr/bin/env python3
"""
Verify acm-vm-extended migration rules match kubevirt/kubevirt-migration-operator.

Upstream source of truth:
  https://github.com/kubevirt/kubevirt-migration-operator/blob/main/pkg/resources/cluster/rbac.go
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ADDON_TEMPLATE = REPO_ROOT / "charts/fine-grained-rbac/templates/acm-roles-addontemplate.yaml"
RBAC_GO_URL = (
    "https://raw.githubusercontent.com/kubevirt/kubevirt-migration-operator/"
    "main/pkg/resources/cluster/rbac.go"
)
RBAC_GO_REF = "kubevirt/kubevirt-migration-operator@main:pkg/resources/cluster/rbac.go"
KNOWN_MIGRATION_VERBS = frozenset(
    {
        "get",
        "list",
        "watch",
        "create",
        "update",
        "patch",
        "delete",
        "deletecollection",
    }
)


def fetch_rbac_go(url: str = RBAC_GO_URL) -> str:
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        print(f"ERROR: failed to fetch upstream {RBAC_GO_REF}: {exc}", file=sys.stderr)
        sys.exit(2)


def _go_function_body(go_source: str, func_name: str) -> str:
    marker = f"func {func_name}()"
    start = go_source.find(marker)
    if start < 0:
        raise ValueError(f"function {func_name} not found in upstream rbac.go")
    next_func = go_source.find("\nfunc ", start + len(marker))
    if next_func < 0:
        return go_source[start:]
    return go_source[start:next_func]


def parse_go_policy_rules(go_source: str, func_name: str) -> list[dict]:
    body = _go_function_body(go_source, func_name)
    rules: list[dict] = []
    for api_groups, resources, verbs in re.findall(
        r"APIGroups:\s*\[]string\{(.*?)\}.*?Resources:\s*\[]string\{(.*?)\}.*?Verbs:\s*\[]string\{(.*?)\}",
        body,
        re.DOTALL,
    ):
        groups = _go_string_list(api_groups)
        if not groups:
            continue
        rules.append(
            {
                "apiGroups": groups,
                "resources": _go_string_list(resources),
                "verbs": _go_string_list(verbs),
            }
        )
    return rules


def _go_string_list(raw: str) -> list[str]:
    return sorted(re.findall(r'"([^"]+)"', raw))


def merge_policy_rules(rule_sets: list[list[dict]]) -> list[dict]:
    merged: dict[tuple[str, ...], set[str]] = {}
    for rules in rule_sets:
        for rule in rules:
            for group in rule["apiGroups"]:
                for resource in rule["resources"]:
                    key = (group, resource)
                    merged.setdefault(key, set()).update(rule["verbs"])
    by_group: dict[str, dict[str, set[str]]] = {}
    for (group, resource), verbs in merged.items():
        by_group.setdefault(group, {})[resource] = verbs
    out: list[dict] = []
    for group in sorted(by_group):
        resources = sorted(by_group[group])
        verbs = sorted({v for r in resources for v in by_group[group][r]})
        if all(by_group[group][r] == set(verbs) for r in resources):
            out.append(
                {
                    "apiGroups": [group],
                    "resources": resources,
                    "verbs": verbs,
                }
            )
        else:
            for resource in resources:
                out.append(
                    {
                        "apiGroups": [group],
                        "resources": [resource],
                        "verbs": sorted(by_group[group][resource]),
                    }
                )
    return out


def _yaml_list_items(block: str) -> list[str]:
    return [line.strip() for line in re.findall(r"^\s+- (.+)$", block, re.MULTILINE)]


def _validate_migration_verbs(verbs: list[str], role_name: str) -> list[str]:
    normalized: list[str] = []
    bad: list[str] = []
    for verb in verbs:
        cleaned = verb.strip().strip("'\"")
        if cleaned == "*" or cleaned not in KNOWN_MIGRATION_VERBS:
            bad.append(verb)
        else:
            normalized.append(cleaned)
    if bad:
        raise ValueError(
            f"ClusterRole {role_name}: unsupported migrations.kubevirt.io verbs {bad}; "
            f"expected only {sorted(KNOWN_MIGRATION_VERBS)}"
        )
    return sorted(normalized)


def extract_role_migration_rules(yaml_text: str, role_name: str) -> list[dict]:
    marker = f"name: {role_name}"
    start = yaml_text.find(marker)
    if start < 0:
        raise ValueError(f"ClusterRole {role_name} not found in add-on template")

    next_role = yaml_text.find("\n        - apiVersion:", start + 1)
    if next_role < 0:
        block = yaml_text[start:]
    else:
        block = yaml_text[start:next_role]

    rules: list[dict] = []
    migration_rule = re.compile(
        r"- apiGroups:\s*\n"
        r"\s+- migrations\.kubevirt\.io\s*\n"
        r"\s+resources:\s*\n"
        r"((?:\s+- .+\n)+?)"
        r"\s+verbs:\s*\n"
        r"((?:\s+- .+\n)+?)"
        r"(?=\s+- apiGroups:|\Z)",
    )
    for rule_block in migration_rule.finditer(block):
        resources = _yaml_list_items(rule_block.group(1))
        verbs = _validate_migration_verbs(_yaml_list_items(rule_block.group(2)), role_name)
        rules.append(
            {
                "apiGroups": ["migrations.kubevirt.io"],
                "resources": sorted(resources),
                "verbs": verbs,
            }
        )
    return rules


def normalize_rules(rules: list[dict]) -> list[dict]:
    flat: dict[tuple[str, str], set[str]] = {}
    for rule in rules:
        for group in rule["apiGroups"]:
            for resource in rule["resources"]:
                flat.setdefault((group, resource), set()).update(rule["verbs"])
    by_group: dict[str, dict[str, set[str]]] = {}
    for (group, resource), verbs in flat.items():
        by_group.setdefault(group, {})[resource] = verbs
    normalized: list[dict] = []
    for group in sorted(by_group):
        resources = sorted(by_group[group])
        verb_sets = [by_group[group][r] for r in resources]
        if all(v == verb_sets[0] for v in verb_sets):
            normalized.append(
                {
                    "apiGroups": [group],
                    "resources": resources,
                    "verbs": sorted(verb_sets[0]),
                }
            )
        else:
            for resource in resources:
                normalized.append(
                    {
                        "apiGroups": [group],
                        "resources": [resource],
                        "verbs": sorted(by_group[group][resource]),
                    }
                )
    return normalized


def rules_equal(expected: list[dict], actual: list[dict]) -> bool:
    return normalize_rules(expected) == normalize_rules(actual)


def main() -> int:
    go_source = fetch_rbac_go()
    expected_view = parse_go_policy_rules(go_source, "getViewPolicyRules")
    expected_admin = merge_policy_rules(
        [
            parse_go_policy_rules(go_source, "getStorageMigratePolicyRules"),
            parse_go_policy_rules(go_source, "getStorageMigrateMultinsPolicyRules"),
        ]
    )

    template = ADDON_TEMPLATE.read_text(encoding="utf-8")
    try:
        actual_view = extract_role_migration_rules(template, "acm-vm-extended:view")
        actual_admin = extract_role_migration_rules(template, "acm-vm-extended:admin")
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    ok = True
    if not rules_equal(expected_view, actual_view):
        ok = False
        print("MISMATCH acm-vm-extended:view vs migrations.kubevirt.io:view")
        print(f"  expected (from {RBAC_GO_REF} getViewPolicyRules):")
        for rule in normalize_rules(expected_view):
            print(f"    {rule}")
        print("  actual (add-on template):")
        for rule in normalize_rules(actual_view):
            print(f"    {rule}")

    if not rules_equal(expected_admin, actual_admin):
        ok = False
        print("MISMATCH acm-vm-extended:admin vs storagemigrate + storagemigrate-multins")
        print(f"  expected (from {RBAC_GO_REF} getStorageMigrate*PolicyRules):")
        for rule in normalize_rules(expected_admin):
            print(f"    {rule}")
        print("  actual (add-on template):")
        for rule in normalize_rules(actual_admin):
            print(f"    {rule}")

    if ok:
        print(f"OK: acm-vm-extended migration rules match {RBAC_GO_REF}")
        return 0
    print(
        "\nUpdate charts/fine-grained-rbac/templates/acm-roles-addontemplate.yaml "
        "or investigate upstream kubevirt-migration-operator changes.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
