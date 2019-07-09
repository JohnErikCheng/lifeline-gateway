---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by zqzhou.
--- DateTime: 2019/6/25 下午5:55
---
local url = require "socket.url"
local typedefs = require "kong.db.schema.typedefs"

-- 令牌id数据
local keycloak_auth_tids = {
    name = "keycloak_auth_tids",
    primary_key = { "id" },
    cache_key = { "tid" },
    endpoint_key = "tid",
    ttl = true,
    fields = {
        { id = typedefs.uuid },
        { tid = { type = "string", required = true, unique = true }, }
    },
}

-- 令牌数据
local keycloak_auth_tokens = {
    name = "keycloak_auth_tokens",
    primary_key = { "id" },
    cache_key = { "tid" },
    endpoint_key = "tid",
    ttl = true,
    fields = {
        { id = typedefs.uuid },
        { tid = { type = "string", required = true, unique = true }, },
        { access_token = { type = "string", required = true, unique = true }, },
        { expires_in = { type = "integer", required = true }, },
        { refresh_token = { type = "string", required = true }, },
    },
}

-- 客户端数据
local keycloak_auth_clients = {
    name = "keycloak_auth_clients",
    primary_key = { "id" },
    endpoint_key = "client_id",
    cache_key = { "client_id" },
    ttl = true,
    fields = {
        { id = typedefs.uuid },
        { client_uid = { type = "string", required = true, unique = true }, },
        { client_id = { type = "string", required = true, unique = true }, },
        { client_secret = { type = "string", required = true }, },
        { enabled = { type = "boolean", default = true }, },
        { auth_enabled = { type = "boolean", default = true }, },
        { client_resources = { type = "string", required = true }, },
    },
}

-- 用户权限数据
local keycloak_auth_user_permissions = {
    name = "keycloak_auth_user_permissions",
    primary_key = { "id" },
    endpoint_key = "user_client_id",
    cache_key = { "user_client_id" },
    ttl = true,
    fields = {
        { id = typedefs.uuid },
        { user_client_id = { type = "string", required = true, unique = true }, },
        { user_id = { type = "string", required = true }, },
        { client_id = { type = "string", required = true }, },
        { permissions = { type = "string", required = true }, },
    },
}

return {
    keycloak_auth_tids,
    keycloak_auth_tokens,
    keycloak_auth_clients,
    keycloak_auth_user_permissions,
}
