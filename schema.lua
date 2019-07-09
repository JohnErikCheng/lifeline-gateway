---
--- 插件配置
--- User: zqzhou
--- Date: 2019/6/18
---
local typedefs = require "kong.db.schema.typedefs"

return {
    name = "keycloak-auth",
    --    no_consumer = true,
    fields = {
        { consumer = typedefs.no_consumer },
        { run_on = typedefs.run_on_first },
        { protocols = typedefs.protocols_http },
        {
            config = {
                type = "record",
                fields = {
                    { kong_host = { type = "string" }, },
                    { kong_redirect_path = { type = "string" }, },
                    { kong_token_path = { type = "string" }, },
                    { kong_refresh_path = { type = "string" }, },
                    { kong_logout_path = { type = "string" }, },

                    { keycloak_host = { type = "string" }, },

                    { kong_client_id = { type = "string" }, },
                    { kong_client_secret = { type = "string" }, },
                    { keycloak_admin_uname = { type = "string" }, },
                    { keycloak_admin_pwd = { type = "string" }, },

                    { whitelist = { type = "array", elements = { type = "string" }, }, },
                    { blacklist = { type = "array", elements = { type = "string" }, }, },
                },
            },
        },
    },
    --entity_checks = {
    --    { only_one_of = { "config.whitelist", "config.blacklist" }, },
    --    { at_least_one_of = { "config.whitelist", "config.blacklist" }, },
    --},
    --    self_check = function(schema, plugin_t, dao, is_update)
    --        -- TODO: add check
    --        return true
    --    end
}