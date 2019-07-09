local kong = kong
local exit = require "kong.plugins.keycloak-auth.utils.exit"
local cjson = require "cjson"
local _M = {}

--查询数据库
local function load_credential_by_client_id(client_id)
    local credential, err = kong.db.keycloak_auth_clients:select_by_client_id(client_id)
    if err then
        return nil, err
    end
    return credential
end

--从缓存获取client_id下的所有资源
function _M:load_client_source_by_client_id(client_id)
    local client_source, err
    if client_id then
        local credential_cache_key = kong.db.keycloak_auth_clients:cache_key(client_id)

        client_source, err = kong.cache:get(credential_cache_key, nil,
            load_credential_by_client_id,
            client_id)

        if err then
            return exit:internal_server_error(err)
        end
    end
    if client_source ~= nil then
    end
    return client_source
end

--查询数据库
local function load_by_client_user_id(client_id)
    local credential, err = kong.db.keycloak_auth_user_permissions:select_by_client_id(client_id)

    if err then
        return nil, err
    end
    return credential
end

--从缓存获取用户的权限数据 user_resources
function _M:load_user_resources(client_id)
    local user_resources, err

    if client_id then
        local credential_cache_key = kong.db.keycloak_auth_user_permissions:cache_key(client_id)
        user_resources, err = kong.cache:get(credential_cache_key, nil,
            load_by_client_user_id,
            client_id)

        if err then
            return exit:internal_server_error(err)
        end
    end
    return user_resources
end

--插入数据库
function _M:insert_db(client_source)
    local insert, err = kong.db.keycloak_auth_clients:insert({
        id = "5acafb6d-ca18-450d-92d7-48390acf4f61",
        client_id = "admin-cli",
        client_secret = "92bd6a34-989c-4143-863c-1cf44997b64d",
        client_resources = client_source,
    }, { ttl = 300 })

    if err then
        kong.log.err(err)
        return kong.response.exit(500, "An unexpected error occurred")
    end

    if insert then
        kong.log.notice("Insert database keycloak_auth_clients success!")
    end
end

return _M
