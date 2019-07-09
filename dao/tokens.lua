---
--- 令牌数据访问
--- Created by zqzhou.
--- DateTime: 2019/7/5 下午4:02
---
local kservice = require "kong.plugins.keycloak-auth.service.keycloak"
local cjson = require "cjson"

local kong = kong
local ipairs = ipairs
local setmetatable = setmetatable


--- 从数据库中获取令牌数据
--
-- @param 令牌id
-- @return 令牌数据table、错误提示
local function load_db_by_token_id(tid)
    local token, err = kong.db.keycloak_auth_tokens:select_by_tid(tid)

    if err then
        return nil, err
    end

    kong.log.notice("数据库取令牌" .. tid .. cjson.encode(token))
    return token, nil
end

--- 从数据库中获取令牌id数据
--
local function load_db_by_tid_id(id)
    local tid, err = kong.db.keycloak_auth_tids:select_by_tid(id)

    if err then
        return nil, err
    end

    return tid, nil
end

--[[

  tokens public interface

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

--- 保存令牌数据
--
-- @param 令牌数据table
-- @return 保存结果
function _M:insert(token)
    return kong.db.keycloak_auth_tokens:insert(token, {
        ttl = token.expires_in
    })
end

--- 保存令牌id数据
--
-- @param 令牌id
-- @return 保存结果
function _M:insert_tid(tid)
    return kong.db.keycloak_auth_tids:insert({
        id = tid,
        tid = tid
    }, {
        ttl = 10
    })
end

--- 删除令牌id数据
--
-- @param 令牌id
-- @return 删除结果
function _M:delete_tid(tid)
    return kong.db.keycloak_auth_tids:delete({ id = tid })
end

--- 删除令牌数据
--
-- @param 令牌id
-- @return 保存结果
function _M:delete(tid)
    return kong.db.keycloak_auth_tokens:delete({ id = tid })
end

--- 从缓存中获取令牌id数据
--
-- @param 令牌id
-- @return 令牌id数据、错误提示
function _M:load_tid_by_tid_id(id)
    local tid, err

    if id then
        local cache_key = kong.db.keycloak_auth_tids:cache_key(id)

        tid, err = kong.cache:get(cache_key, nil, load_db_by_tid_id, id)

        if err then
            kong.log.err(err)
            return nil, err
        end
    end

    if not tid then
        return nil, nil
    end

    return tid.tid, nil
end

--- 从缓存中获取令牌数据
--
-- @param 令牌id
-- @return 令牌数据table、错误提示
function _M:load_token_by_token_id(tid)
    local token, err

    if tid then
        local cache_key = kong.db.keycloak_auth_tokens:cache_key(tid)

        token, err = kong.cache:get(cache_key, nil, load_db_by_token_id, tid)

        if err then
            kong.log.err(err)
            return nil, err
        end

    end

    return token, nil
end

return _M