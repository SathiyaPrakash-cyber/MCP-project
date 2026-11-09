package mcp_gateway.authz

import future.keywords.in

default allow = false

# Canonicalisation (B1): normalise tool name before ANY check
norm_tool := lower(trim_space(input.tool.name))

allow {
    not explicitly_denied
    rbac_allow
    abac_allow
    not violates_argument_policy
}

# Single decision object (A4)
decision := {
    "allow": allow,
    "reason": reason,
    "rule_matched": rule_matched,
}

default reason = "deny: no matching rule"
reason = "explicit_deny: missing user identity" { not input.user.id }
reason = "explicit_deny: invalid role" { input.user.id; not valid_roles[input.user.role] }
reason = "explicit_deny: tool is globally blocked" { valid_roles[input.user.role]; globally_blocked_tools[norm_tool] }
reason = "explicit_deny: privileged tool requires admin" { valid_roles[input.user.role]; not globally_blocked_tools[norm_tool]; privileged_tools[norm_tool]; input.user.role != "admin" }
reason = "explicit_deny: destructive tool blocked for agent off-hours" { input.user.role == "agent"; destructive_tools[norm_tool]; is_off_hours }
reason = "argument_deny: injection or path traversal in args" { not explicitly_denied; rbac_allow; abac_allow; violates_argument_policy }
reason = "rbac_deny: role does not permit this tool" { not explicitly_denied; not rbac_allow }
reason = "abac_deny: context constraints not satisfied" { not explicitly_denied; rbac_allow; not abac_allow }
reason = "allow: rbac and abac checks passed" { allow }

default rule_matched = "default_deny"
rule_matched = "explicit_deny"    { explicitly_denied }
rule_matched = "argument_deny"    { not explicitly_denied; rbac_allow; abac_allow; violates_argument_policy }
rule_matched = "rbac_deny"        { not explicitly_denied; not rbac_allow }
rule_matched = "abac_deny"        { not explicitly_denied; rbac_allow; not abac_allow }
rule_matched = "rbac_abac_allow"  { allow }

explicitly_denied { not input.user.id }
explicitly_denied { not valid_roles[input.user.role] }
explicitly_denied { globally_blocked_tools[norm_tool] }
explicitly_denied { not globally_blocked_tools[norm_tool]; privileged_tools[norm_tool]; input.user.role != "admin" }
explicitly_denied { input.user.role == "agent"; destructive_tools[norm_tool]; is_off_hours }

rbac_allow {
    allowed := role_permissions[input.user.role]
    tool_permitted(norm_tool, allowed)
}

tool_permitted(tool, allowed) { allowed[_] == tool }
tool_permitted(tool, allowed) {
    prefix := allowed[_]
    endswith(prefix, "*")
    base := trim_suffix(prefix, "*")
    startswith(tool, base)
}

abac_allow {
    not violates_time_restriction
    not violates_sensitivity_restriction
    not violates_ip_restriction
}

violates_time_restriction { input.user.role == "read_only"; is_off_hours }
violates_sensitivity_restriction { sensitive_tools[norm_tool]; not elevated_roles[input.user.role] }
violates_ip_restriction { blocked_ips[input.context.source_ip] }

# Argument inspection (B2)
violates_argument_policy { sql_injection_in_args }
violates_argument_policy { path_traversal_in_args }

sql_injection_in_args {
    some k
    v := input.tool.args[k]
    is_string(v)
    contains(lower(v), "' or ")
}
sql_injection_in_args {
    some k
    v := input.tool.args[k]
    is_string(v)
    contains(lower(v), "drop table")
}
sql_injection_in_args {
    some k
    v := input.tool.args[k]
    is_string(v)
    contains(lower(v), "union select")
}
sql_injection_in_args {
    some k
    v := input.tool.args[k]
    is_string(v)
    contains(lower(v), "; delete from")
}
path_traversal_in_args {
    some k
    v := input.tool.args[k]
    is_string(v)
    contains(v, "../")
}

role_permissions = {
    "admin":            ["filesystem.*", "database.*", "code.*", "saas.*", "system.*", "admin.*"],
    "security_analyst": ["filesystem.read", "filesystem.list", "database.read", "database.query", "saas.read", "audit.*", "logs.*"],
    "developer":        ["filesystem.read", "filesystem.write", "filesystem.list", "code.*", "database.read", "database.query", "saas.read", "saas.webhook"],
    "read_only":        ["filesystem.read", "filesystem.list", "database.read", "saas.read"],
    "agent":            ["filesystem.read", "filesystem.list", "database.read", "database.query", "code.execute", "saas.read"]
}

valid_roles      = {"admin": true, "security_analyst": true, "developer": true, "read_only": true, "agent": true}
elevated_roles   = {"admin": true, "security_analyst": true}
sensitive_tools  = {"database.drop": true, "database.delete_all": true, "filesystem.delete_recursive": true, "system.shutdown": true, "admin.create_user": true, "admin.delete_user": true, "admin.modify_policy": true, "code.deploy_production": true}
destructive_tools = {"database.delete": true, "database.drop": true, "filesystem.delete": true, "filesystem.delete_recursive": true}
privileged_tools = {"code.execute_privileged": true, "system.exec": true, "system.sudo": true}
globally_blocked_tools = {"system.format_disk": true, "admin.drop_all_tables": true, "system.rm_rf_root": true}
blocked_ips = {}

is_off_hours { input.context.hour < 6 }
is_off_hours { input.context.hour >= 22 }
