---
--- 用户权限数据访问
--- Created by zqzhou.
--- DateTime: 2019/7/5 下午4:05
---
local kservice = require "kong.plugins.keycloak-auth.service.keycloak"

local kong = kong
local setmetatable = setmetatable

--- 从数据库中获取用户权限数据
--
-- @param 用户和客户端id
-- @return 权限数据table、错误提示
local function load_db_by_user_client_id(user_client_id)
    local permission, err = kong.db.keycloak_auth_user_permissions:select_by_user_client_id(user_client_id)

    if err then
        return nil, err
    end

    return permission, nil
end

--- 插入单个用户权限数据
--
-- @param 权限数据table
-- @return true or false、错误提示
local function insert_user_permission(permission)
    return kong.db.keycloak_auth_user_permissions:insert(permission, { ttl = 1800 })
end

--- 从keycloak中获取用户权限数据
--
-- @param 配置
-- @param 用户令牌
-- @param 客户端id
-- @return 权限数据table、错误提示
local function load_user_permission_from_keycloak(configuration, access_token, client_id)
    local status, permission, insert, err

    local service_client = kservice:instance(configuration)

    status, permission, err = service_client:obtain_user_permissions(access_token, client_id)

    if err then
        return nil, err
    end

    if not permission then
        return nil, nil
    end

    -- 将获取的权限数据insert到数据库
    insert, err = insert_user_permission(permission)

    if err then
        return nil, err
    end

    return permission, nil
end

--[[

  user_permissions public interface

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

--- 从缓存中获取用户权限数据
--
-- @param 用户令牌，用来换取RPT
-- @param 用户id
-- @param 客户端id
-- @return 客户端数据table、错误提示
function _M:load_permissions_by_user_client_id(access_token, user_id, client_id)
    local permissions, err

    local user_client_id = user_id .. ":" .. client_id

    if client_id then
        local cache_key = kong.db.keycloak_auth_user_permissions:cache_key(user_client_id)

        permissions, err = kong.cache:get(cache_key, nil, load_db_by_user_client_id, user_client_id)

        if err then
            kong.log.err(err)
            return nil, err
        end
    end

    if not permissions then
        permissions, err = load_user_permission_from_keycloak(self.configuration, access_token, client_id)

        if err then
            kong.log.err(err)
            return nil, err
        end
    end

    return permissions, nil
end

return _M