---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by zqzhou.
--- DateTime: 2019/6/25 下午5:55
--local endpoints = require "kong.api.endpoints"
--local kong = kong
--
--local clients_schema = kong.db.keycloak_auth_clients.schema
--local user_permissions_schema = kong.db.keycloak_auth_user_permissions.schema
--local tokens_schema = kong.db.keycloak_auth_tokens.schema
--
--return {
--    [""] = {
--        schema = clients_schema,
--        methods = {
--            GET = endpoints.get_entity_endpoint(clients_schema),
--            PUT = endpoints.put_entity_endpoint(clients_schema),
--            PATCH = endpoints.patch_entity_endpoint(clients_schema),
--            DELETE = endpoints.delete_entity_endpoint(clients_schema)
--        }
--    },
--    [""] = {
--        schema = user_permissions_schema,
--        methods = {
--            GET = endpoints.get_entity_endpoint(user_permissions_schema),
--            PUT = endpoints.put_entity_endpoint(user_permissions_schema),
--            PATCH = endpoints.patch_entity_endpoint(user_permissions_schema),
--            DELETE = endpoints.delete_entity_endpoint(user_permissions_schema)
--        }
--    },
--    [""] = {
--        schema = tokens_schema,
--        methods = {
--            GET = endpoints.get_entity_endpoint(tokens_schema),
--            PUT = endpoints.put_entity_endpoint(tokens_schema),
--            PATCH = endpoints.patch_entity_endpoint(tokens_schema),
--            DELETE = endpoints.delete_entity_endpoint(tokens_schema)
--        }
--    },
--}