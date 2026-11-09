package mcp_gateway.authz
default allow = false

allow {
    not globally_blocked_tools[input.tool.name]
    not sensitive_tools[input.tool.name]
    not is_destructive_off_hours
}

allow {
    not globally_blocked_tools[input.tool.name]
    sensitive_tools[input.tool.name]
    elevated_roles[input.user.role]
}

is_destructive_off_hours {
    destructive_tools[input.tool.name]
    input.context.hour < 6
}
is_destructive_off_hours {
    destructive_tools[input.tool.name]
    input.context.hour >= 22
}

sensitive_tools   = {"database.drop":true,"database.delete_all":true,"filesystem.delete_recursive":true,"system.shutdown":true,"admin.create_user":true,"admin.modify_policy":true,"code.deploy_production":true}
destructive_tools = {"database.delete":true,"database.drop":true,"filesystem.delete":true}
globally_blocked_tools = {"system.format_disk":true,"admin.drop_all_tables":true,"system.rm_rf_root":true}
elevated_roles    = {"admin":true,"security_analyst":true}
