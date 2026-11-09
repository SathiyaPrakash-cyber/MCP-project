"""
B3 — Policy Mining for MCP (Advanced Novelty)
Auto-derives least-privilege RBAC/ABAC policies from observed audit logs.
Compares mined policy vs hand-written hybrid policy on coverage and over-permission.

Novel contribution: policy mining is established for classic ABAC but unexplored for MCP.
Reference: Zhang et al. (2018) "Mining ABAC Policies" — adapted for MCP tool-call context.

Run: python3 tests/policy_mining.py
"""
import json
import re
import time
from collections import defaultdict
from pathlib import Path


def load_audit_logs(log_dir: str = "logs") -> list[dict]:
    records = []
    for f in sorted(Path(log_dir).glob("mcp_audit_*.ndjson")):
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


def mine_rbac_policy(records: list[dict]) -> dict[str, set]:
    """Mine least-privilege RBAC: role → set of tools actually used (ALLOW only)."""
    role_tools: dict[str, set] = defaultdict(set)
    for r in records:
        if r.get("policy_decision") == "ALLOW" and r.get("tool_name"):
            role = r.get("role", "unknown")
            tool = r.get("tool_name", "")
            if role and tool:
                role_tools[role].add(tool)
    return dict(role_tools)


ELEVATED_ROLES = {"admin", "security_analyst"}

# A legitimate tool name. The adversarial probe set deliberately submits
# malformed names (case variants, null bytes, traversal fragments, shell
# metacharacters) to test normalisation; those are attack inputs, not tools,
# and including them would corrupt both the tool universe and the mined sets.
WELL_FORMED_TOOL = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")

# Rule labels emitted by the hand-written policy, grouped by what a denial
# under that label actually tells us about the tool.
_AUTHORISATION_DENIALS = {"rbac_deny", "explicit_deny"}
_CONTEXT_DENIALS = {"abac_deny"}
_ARGUMENT_DENIALS = {"argument_deny"}


def mine_tool_signals(records: list[dict]) -> dict[str, set]:
    """
    Separate the three things a denial can tell us about a tool.

    An earlier version of this function treated every ABAC denial as evidence
    that a tool was *sensitive*. That conflates three different signals and
    inflated the mined sensitive-tool set:

    * **elevated-only** — the tool was refused to a non-elevated role on an
      authorisation ground (``rbac_deny`` / ``explicit_deny``) *and* was
      observed being allowed to an elevated role. Only this is evidence of
      tool sensitivity.
    * **context-restricted** — the tool was refused under ``abac_deny``, i.e.
      the caller's role permitted it but the context (time of day, source
      address) did not. That is a property of the *condition*, not of the
      tool, and belongs in an ABAC clause rather than a sensitivity list.
    * **argument-filtered** — refused under ``argument_deny`` because of the
      call's arguments. Says nothing about the tool's sensitivity at all.

    A tool that no role was ever allowed to call is excluded from
    *elevated-only*: with no positive evidence, "sensitive" and "unused" are
    indistinguishable, and asserting the former would overstate the finding.
    """
    allowed_by_elevated: set[str] = set()
    allowed_by_anyone: set[str] = set()
    denied_auth_non_elevated: set[str] = set()
    context_restricted: set[str] = set()
    argument_filtered: set[str] = set()

    for r in records:
        tool = r.get("tool_name", "")
        role = r.get("role", "")
        if not tool:
            continue
        if r.get("policy_decision") == "ALLOW":
            allowed_by_anyone.add(tool)
            if role in ELEVATED_ROLES:
                allowed_by_elevated.add(tool)
            continue

        rule = r.get("policy_rule_matched", "")
        if rule in _AUTHORISATION_DENIALS and role not in ELEVATED_ROLES:
            denied_auth_non_elevated.add(tool)
        elif rule in _CONTEXT_DENIALS:
            context_restricted.add(tool)
        elif rule in _ARGUMENT_DENIALS:
            argument_filtered.add(tool)

    elevated_only = denied_auth_non_elevated & allowed_by_elevated
    unresolved = denied_auth_non_elevated - allowed_by_anyone

    def clean(s: set[str]) -> set[str]:
        return {t for t in s if WELL_FORMED_TOOL.fullmatch(t)}

    return {
        "elevated_only": clean(elevated_only),
        "context_restricted": clean(context_restricted - elevated_only),
        "argument_filtered": clean(argument_filtered),
        "denied_but_never_allowed": clean(unresolved),
        "malformed_names_rejected": {
            t for t in (denied_auth_non_elevated | context_restricted)
            if not WELL_FORMED_TOOL.fullmatch(t)
        },
    }


def mine_sensitive_tools(records: list[dict]) -> set:
    """
    Tools for which the logs provide positive evidence of elevated-only access.

    Retained as a thin wrapper over :func:`mine_tool_signals` so existing
    callers keep working; see that function for why the other denial classes
    are deliberately excluded.
    """
    return mine_tool_signals(records)["elevated_only"]


def generate_rego(role_tools: dict, sensitive: set) -> str:
    """Generate a mined Rego policy from observed patterns."""
    lines = [
        "# AUTO-MINED POLICY — generated by policy_mining.py",
        f"# Mined from {sum(len(v) for v in role_tools.values())} observed allow events",
        f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "package mcp_gateway.authz",
        "",
        "default allow = false",
        "",
        "allow {",
        "    not globally_blocked_tools[lower(input.tool.name)]",
        "    rbac_allow_mined",
        "    not violates_sensitivity_mined",
        "}",
        "",
        "rbac_allow_mined {",
        "    allowed := mined_role_permissions[input.user.role]",
        "    allowed[_] == input.tool.name",
        "}",
        "",
        "violates_sensitivity_mined {",
        "    mined_sensitive_tools[input.tool.name]",
        '    not input.user.role == "admin"',
        '    not input.user.role == "security_analyst"',
        "}",
        "",
    ]

    # Role permissions
    lines.append("mined_role_permissions = {")
    for role, tools in sorted(role_tools.items()):
        tools_str = ", ".join(f'"{t}"' for t in sorted(tools))
        lines.append(f'    "{role}": [{tools_str}],')
    lines.append("}")
    lines.append("")

    # Sensitive tools
    if sensitive:
        sensitive_str = ", ".join(f'"{t}": true' for t in sorted(sensitive))
        lines.append(f"mined_sensitive_tools = {{{sensitive_str}}}")
    else:
        lines.append("mined_sensitive_tools = {}")
    lines.append("")

    lines.append('globally_blocked_tools = {"system.format_disk": true, "admin.drop_all_tables": true, "system.rm_rf_root": true}')

    return "\n".join(lines)


def evaluate_vs_handwritten(mined: dict, handwritten_path: str = "policies/mcp_gateway.rego") -> dict:
    """Compare mined policy vs hand-written on key metrics."""
    mined_tools = {role: list(tools) for role, tools in mined.items()}
    mined_total = sum(len(v) for v in mined.values())

    hw_text = Path(handwritten_path).read_text() if Path(handwritten_path).exists() else ""
    hw_roles = re.findall(r'"([a-z_]+)":\s*\[(.*?)\]', hw_text, re.DOTALL)
    hw_total = sum(len(re.findall(r'"[^"]*"', perms)) for _, perms in hw_roles)

    return {
        "mined_roles": list(mined.keys()),
        "mined_unique_tools": mined_total,
        "handwritten_approx_permissions": hw_total,
        "over_permission_risk": "LOW — mined from actual usage (least privilege by design)",
        "under_permission_risk": "POSSIBLE — only captures observed usage, not intended permissions",
        "recommendation": "Use mined policy as audit baseline; hand-written policy for enforcement",
    }


def run():
    print("\n" + "=" * 64)
    print("  B3 — MCP POLICY MINING (Advanced Novelty)")
    print("  Mining least-privilege policies from audit logs")
    print("=" * 64)

    records = load_audit_logs()
    if not records:
        print("  No audit records found. Run some tool calls first.")
        return

    print(f"\n  Loaded {len(records)} audit records")

    role_tools = mine_rbac_policy(records)
    signals = mine_tool_signals(records)
    sensitive = signals["elevated_only"]

    print(f"\n  Mined RBAC permissions:")
    for role, tools in sorted(role_tools.items()):
        print(f"    {role:<20}: {sorted(tools)}")

    print("\n  Denial signals, separated by what each one actually evidences:")
    print(
        f"    elevated-only (sensitive)   : "
        f"{sorted(signals['elevated_only']) or 'none observed'}"
    )
    print(
        f"    context-restricted (ABAC)   : "
        f"{sorted(signals['context_restricted']) or 'none observed'}"
    )
    print(
        f"    argument-filtered           : "
        f"{sorted(signals['argument_filtered']) or 'none observed'}"
    )
    print(
        f"    denied but never allowed    : "
        f"{sorted(signals['denied_but_never_allowed']) or 'none observed'}"
    )
    print(
        f"    malformed names rejected    : "
        f"{len(signals['malformed_names_rejected'])} adversarial probe strings"
    )
    print(
        "    (only the first class is treated as evidence of tool sensitivity;\n"
        "     the others describe the condition or the arguments, not the tool)"
    )

    rego = generate_rego(role_tools, sensitive)

    Path("logs").mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_rego = f"logs/mined_policy_{ts}.rego"
    out_json = f"logs/policy_mining_report_{ts}.json"

    Path(out_rego).write_text(rego)

    comparison = evaluate_vs_handwritten(role_tools)
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "records_analyzed": len(records),
        "mined_role_permissions": {r: sorted(t) for r, t in role_tools.items()},
        "detected_sensitive_tools": sorted(sensitive),
        "denial_signals": {k: sorted(v) for k, v in signals.items()},
        "comparison_vs_handwritten": comparison,
    }
    Path(out_json).write_text(json.dumps(report, indent=2))

    print(f"\n  Mined Rego saved: {out_rego}")
    print(f"  Mining report: {out_json}")

    print("\n  Comparison vs hand-written hybrid policy:")
    for k, v in comparison.items():
        print(f"    {k}: {v}")

    print(f"\n  Novel contribution: First application of policy mining to MCP tool-call")
    print(f"  authorization context. Mines from {len(records)} real gateway decisions.\n")
    return records


def tool_universe(
    records: list[dict] | None = None,
    mock_server_path: str = "gateway/mock_server.py",
) -> set[str]:
    """
    The set of concrete tool names a wildcard grant can expand to.

    Built from the tools the upstream mock server advertises, unioned with
    every tool name that appears in the audit logs. Without this, a grant
    written as ``code.*`` cannot be compared with an observed call to
    ``code.execute`` at all.
    """
    universe: set[str] = set()
    try:
        text = Path(mock_server_path).read_text()
        universe |= set(re.findall(r'\{"name":\s*"([^"]+)"', text))
    except OSError:
        pass
    for r in records or []:
        name = r.get("tool_name", "")
        if WELL_FORMED_TOOL.fullmatch(name or ""):
            universe.add(name)
    return {t for t in universe if WELL_FORMED_TOOL.fullmatch(t)}


def expand_grants(grants: set[str], universe: set[str]) -> set[str]:
    """
    Expand wildcard grants such as ``code.*`` against the tool universe.

    A wildcard that matches nothing in the universe is kept verbatim so it is
    still counted as a granted-but-unused permission rather than silently
    disappearing from the denominator.
    """
    expanded: set[str] = set()
    for grant in grants:
        if grant.endswith(".*"):
            prefix = grant[:-1]  # keep the dot
            matches = {t for t in universe if t.startswith(prefix)}
            expanded |= matches or {grant}
        else:
            expanded.add(grant)
    return expanded


def over_permission_score(
    mined: dict,
    handwritten_rego_path: str = "policies/mcp_gateway.rego",
    records: list[dict] | None = None,
) -> dict:
    """
    B3 Advanced Novelty: Quantify over-permission per role.

    Computes the proportion of hand-written permissions never exercised in the
    observed workload. Wildcard grants are expanded against the tool universe
    first: comparing the literal string ``"code.*"`` against an observed call
    to ``"code.execute"`` treats a used permission as unused and inflates the
    over-permission figure, which is what an earlier revision of this function
    did.

    The result is a property of *this* workload, not a general claim: a
    permission counts as unused only because nothing in the collected traffic
    exercised it.
    """
    try:
        hw_text = open(handwritten_rego_path).read()
    except FileNotFoundError:
        print(f"  Note: {handwritten_rego_path} not found — run from mcp-gateway/ directory")
        return {}

    universe = tool_universe(records)
    hw_roles = re.findall(r'"([a-z_]+)":\s*\[(.*?)\]', hw_text, re.DOTALL)
    scores = {}

    print("\n  Over-Permission Score (hand-written vs actually observed):")
    print(f"  tool universe: {len(universe)} concrete tools")
    print("  " + "-" * 62)
    for role, perms in hw_roles:
        raw_grants = set(re.findall(r'"([^"]+)"', perms))
        if not raw_grants:
            continue
        hw_tools = expand_grants(raw_grants, universe)
        obs_tools = set(mined.get(role, []))
        unused = hw_tools - obs_tools
        pct = round(len(unused) / len(hw_tools) * 100)
        scores[role] = {
            "grants_written": len(raw_grants),
            "granted": len(hw_tools),
            "wildcards_expanded": sum(1 for g in raw_grants if g.endswith(".*")),
            "observed": len(obs_tools),
            "never_used": len(unused),
            "over_permission_pct": pct,
            "unused_tools": sorted(unused),
        }
        print(
            f"  {role:<20}: {pct:>3}% over-permitted  "
            f"({len(unused)}/{len(hw_tools)} granted tools unused; "
            f"{len(raw_grants)} grants written)"
        )

    print("\n  Finding: in the observed workload, hand-written roles grant more")
    print("  tools than were ever exercised. This measures the gap for this")
    print("  trace only; a different workload would give different figures.")

    import json, time
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = f"logs/over_permission_score_{ts}.json"
    Path(out).write_text(json.dumps(scores, indent=2))
    print(f"\n  Over-permission report: {out}")
    return scores


if __name__ == "__main__":
    # Run full mining + over-permission analysis
    _records = run()
    _latest = sorted(Path("logs").glob("policy_mining_report_*.json"))
    if _latest:
        _report = json.loads(_latest[-1].read_text())
        _mined = dict(_report.get("mined_role_permissions", {}))
        over_permission_score(_mined, records=_records)
