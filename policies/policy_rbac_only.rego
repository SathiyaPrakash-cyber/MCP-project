package mcp_gateway.authz
default allow = false

allow {
    not globally_blocked_tools[input.tool.name]
    rbac_allow
}

rbac_allow {
    allowed := role_permissions[input.user.role]
    tool_permitted(input.tool.name, allowed)
}

tool_permitted(tool, allowed) { allowed[_] == tool }
tool_permitted(tool, allowed) {
    prefix := allowed[_]
    endswith(prefix, "*")
    base := trim_suffix(prefix, "*")
    startswith(tool, base)
}

role_permissions = {
    "admin":            ["filesystem.*","database.*","code.*","saas.*","system.*","admin.*"],
    "security_analyst": ["filesystem.read","filesystem.list","database.read","database.query","saas.read","audit.*"],
    "developer":        ["filesystem.read","filesystem.write","filesystem.list","code.*","database.read","database.query","saas.read"],
    "read_only":        ["filesystem.read","filesystem.list","database.read","saas.read"],
    "agent":            ["filesystem.read","filesystem.list","database.read","database.query","code.execute","saas.read"]
}

globally_blocked_tools = {"system.format_disk":true,"admin.drop_all_tables":true,"system.rm_rf_root":true}
