---
--- 客户端数据访问
--- Created by zqzhou.
--- DateTime: 2019/7/5 下午4:04
---
local kservice = require "kong.plugins.keycloak-auth.service.keycloak"
local cjson = require "cjson"

local kong = kong
local ipairs = ipairs
local setmetatable = setmetatable

--- 从数据库中获取客户端数据
--
-- @param 客户端id
-- @return 客户端数据table、错误提示
local function load_db_by_client_id(client_id)
    local client, err = kong.db.keycloak_auth_clients:select_by_client_id(client_id)

    if err then
        return nil, err
    end

    kong.log.notice("数据库取客户端" .. client_id .. cjson.encode(client))
    return client, nil
end

--- 插入单个客户端数据
--
-- @param 客户端数据table
-- @return true or false、错误提示
local function insert_client(client)
    kong.log.notice("插入数据.." .. cjson.encode(client))
    return kong.db.keycloak_auth_clients:insert(client, { ttl = 1800 })
end

--- 批量插入客户端数据
--
-- @param 客户端数据set
-- @return true or false、错误提示
local function bulk_insert_client(clients)
    local insert, err
    for i, v in ipairs(clients) do
        insert, err = insert_client(v)
    end
end

--- 从keycloak中获取客户端数据
--
-- @param 配置
-- @param 客户端id
-- @return 客户端数据table、错误提示
local function load_client_from_keycloak(configuration, client_id)
    local result, status, clients, insert, err

    local service_client = kservice:instance(configuration)

    status, clients, err = service_client:obtain_clients()

    if err then
        return nil, err
    end

    if not clients or #clients == 0 then
        return nil, nil
    end

    --insert, err = bulk_insert_client(clients)

    kong.log.notice("http获取" .. client_id .. cjson.encode(clients))

    for i, v in ipairs(clients) do
        -- 将获取的客户端数据insert到数据库
        insert, err = insert_client(v)

        if err then
            return nil, err
        end

        if v.clientId == client_id then
            result = v
        end
    end

    return result, nil
end

--[[

  clients public interface

]]--

local _M = {}

_M.__index = _M

--- 实例化
--
-- @param 配置
function _M:instance(configuration)
    local configuration = {
        configuration = configuration
    }
    return setmetatable(configuration, _M)
end

--- 从缓存中获取客户端数据
--
-- @param 客户端id
-- @return 客户端数据table、错误提示
function _M:load_client_by_client_id(client_id)
    local client, err

    if client_id then
        local cache_key = kong.db.keycloak_auth_clients:cache_key(client_id)

        client, err = kong.cache:get(cache_key, nil, load_db_by_client_id, client_id)

        if err then
            kong.log.err(err)
            return nil, err
        end

        kong.log.notice(cache_key .. " 获取到数据 " .. cjson.encode(client))
    end

    if not client then
        client, err = load_client_from_keycloak(self.configuration, client_id)

        if err then
            kong.log.err(err)
            return nil, err
        end
    end

    return client, nil
end

return _M