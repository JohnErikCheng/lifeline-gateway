---
--- 插件功能实现
--- User: zqzhou
--- Date: 2019/6/18
---
local acl = require "kong.plugins.keycloak-auth.auth.acl"
local authn = require "kong.plugins.keycloak-auth.auth.authn"
local authz = require "kong.plugins.keycloak-auth.auth.authz"

local kong = kong

local KeycloakAuthHandler = {}

KeycloakAuthHandler.PRIORITY = 1998
KeycloakAuthHandler.VERSION = "1.0.0"

--local function test()
--    kong.log.notice("1231231231231")
--end

function KeycloakAuthHandler:access(conf)

    --local dao = kong.db["keycloak_auth_clients"]
    --
    --local cache_key = dao:cache_key("123")
    --
    --local ok, err = kong.cache:safe_set(cache_key, "123-123", true)
    --
    --if err then
    --    kong.log.err(err)
    --end
    --
    --kong.log.notice(kong.cache:get(cache_key, nil, test))

    local request_path = kong.request.get_path()

    if not acl.access(conf, request_path) then
        authn.access(conf, request_path)
        authz.access(conf, request_path)
    end
end

return KeycloakAuthHandler
