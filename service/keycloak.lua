---
--- 管理员权限客户端工具
--- Created by zqzhou.
--- DateTime: 2019/7/4 上午10:47
---
local cjson = require "cjson"
local utils = require "kong.tools.utils"
local zhttp = require "kong.plugins.keycloak-auth.utils.http"
local client = require "kong.plugins.keycloak-auth.model.client"
local jwt_decoder = require "kong.plugins.keycloak-auth.utils.jwt"
local constants = require "kong.plugins.keycloak-auth.common.constants"
local user_permission = require "kong.plugins.keycloak-auth.model.user_permission"

local type = type
local ipairs = ipairs
local setmetatable = setmetatable
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local encode_args = utils.encode_args


-- keycloak领域内默认的几个客户端ID
local keycloak_realms_default_clients = {
    "account",
    "admin-cli",
    "broker",
    "realm-management",
    "security-admin-console",
    "master-realm",
    "test-realm"
}

--- table中是否包含
--
-- @param 待匹配项
-- @return true or false
local function in_table(value)
    for k, v in ipairs(keycloak_realms_default_clients) do
        if v == value then
            return true
        end
    end
    return false
end

--- 获取客户端的秘钥
--
-- @param 客户端秘钥获取地址
-- @param 管理员令牌
-- @return 状态码、秘钥、错误提示
local function obtain_client_secret(client_secret_url, admin_token)
    local post_body, post_headers = {}, { [constants.HEADERS.AUTHZ] = constants.HEADERS.BEARER .. " " .. admin_token }

    local status, res, err = zhttp:http_get_client(client_secret_url,
            post_headers, encode_args(post_body, true, false), 6000)

    if err or status == 500 then
        return status, nil, err
    end

    local decode_res = cjson_decode(res)
    if status ~= 200 then
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    return 200, decode_res.value, nil
end

--- 获取客户端的资源
--
-- @param 客户端资源获取地址
-- @param 管理员令牌
-- @return 状态码、资源集合、错误提示
local function obtain_client_resources(client_resources_url, admin_token)
    local post_body, post_headers = {}, { [constants.HEADERS.AUTHZ] = constants.HEADERS.BEARER .. " " .. admin_token }

    local status, res, err = zhttp:http_get_client(client_resources_url,
            post_headers, encode_args(post_body, true, false), 6000)

    if err or status == 500 then
        return status, nil, err
    end

    local decode_res = cjson_decode(res)
    if status ~= 200 then
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    local set = {}
    local index = 1

    for k, v in ipairs(decode_res) do
        if type(v) == "table" then
            set[index] = client:resource(v)
            index = index + 1
        end
    end

    return 200, set, nil
end

--[[

  keycloak public interface

]]--

local _M = {}

_M.__index = _M

--- 实例化客户端
--
-- Keycloak的Admin API需要有权限的账户方可访问，比如获取客户端数据、请求注销会话等接口
-- 用途：code换取令牌、刷新令牌、获取客户端数据、获取用户权限数据、获取管理员令牌
-- @param configuration
function _M:instance(configuration)
    local configs = {
        configuration = configuration,
        configurations = configuration:configurations()
    }
    return setmetatable(configs, _M)
end

--- 获取管理员访问令牌
--
-- @return 状态码、令牌数据、错误提示
function _M:obtain_admin_token()

    -- 先从当前缓存中获取，如果没有或者已过期则重新请求认证中心签发

    local post_body = {
        username = self.configurations.keycloak_admin_uname,
        password = self.configurations.keycloak_admin_pwd,
        grant_type = constants.OAUTH.GRANT_PASSWORD
    }

    local post_headers = { [constants.HEADERS.AUTHZ] = constants.HEADERS.BASIC .. " " .. self.configurations.kong_client_credentials }

    local status, res, err = zhttp:http_post_client(self.configurations.keycloak_token_url,
            post_headers, encode_args(post_body, true, false), 6000)

    if err then
        return 500, nil, err
    end

    local decode_res = cjson_decode(res)
    if status ~= 200 then
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    return 200, decode_res.access_token, nil
end

--- 注销会话
--
-- @param session_id
-- @return 状态码、请求结果、错误提示
function _M:logout_session(session_id)

    local status, admin_token, err = self:obtain_admin_token()
    if err then
        return status, nil, err
    end

    local post_headers = { [constants.HEADERS.AUTHZ] = constants.HEADERS.BEARER .. " " .. admin_token }

    local realms = self.configurations.realms
    local logout_url = self.configuration:get_keycloak_session_url(realms, session_id)

    local status, res, err = zhttp:http_delete_client(logout_url, post_headers, 6000)

    if err or status == 500 then
        return status, nil, err
    end

    -- 404表示当前session已注销过，直接返回成功即可
    if status == 404 then
        return 200, constants.RESULT.SUCCESS, nil
    end

    -- 注销后返回状态204
    if status ~= 204 then
        local decode_res = cjson_decode(res)
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    return 200, constants.RESULT.SUCCESS, nil

end

--- 获取用户权限数据，RPT
--
-- 暂时：资源的name集合即可，后期扩展再考虑其他的
-- @param 用户id
-- @param 客户端id
-- @return 状态码、用户权限table、错误提示
function _M:obtain_user_permissions(user_access_token, client_id)
    local post_headers = { [constants.HEADERS.AUTHZ] = constants.HEADERS.BEARER .. " " .. user_access_token }

    local post_body = {
        [constants.OAUTH.AUDIENCE] = client_id,
        [constants.OAUTH.GRANT_TYPE] = constants.OAUTH.GRANT_RPT
    }

    local status, res, err = zhttp:http_post_client(self.configurations.keycloak_token_url,
            post_headers, encode_args(post_body, true, false), 6000)

    if err or status == 500 then
        return status, nil, err
    end

    local decode_res = cjson_decode(res)

    if status ~= 200 then
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    local jwt, err = jwt_decoder:new(decode_res.access_token)
    if err then
        return 500, nil, err
    end

    return 200, user_permission:new(jwt.claims.sub, client_id, jwt.claims.authorization.permissions), nil

end

--- 获取客户端数据
--
-- @return 状态码、客户端数据table、错误提示
function _M:obtain_client(client_id)

end

--- 获取所有客户端数据
--
-- @return 状态码、客户端数据table、错误提示
function _M:obtain_clients()

    local status, admin_token, err = self:obtain_admin_token()
    if err then
        return status, nil, err
    end

    local post_body, post_headers = {}, { [constants.HEADERS.AUTHZ] = constants.HEADERS.BEARER .. " " .. admin_token }

    local status, res, err = zhttp:http_get_client(self.configurations.keycloak_clients_url,
            post_headers, encode_args(post_body, true, false), 6000)

    if err or status == 500 then
        return status, nil, err
    end

    if status ~= 200 then
        local decode_res = cjson_decode(res)
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    local set = {}
    local index = 1
    for k, v in ipairs(cjson_decode(res)) do
        if type(v) == "table" and not in_table(v.clientId) then

            local client_uid, client_secret, client_resources = v.id, nil, {}
            local realms = self.configurations.realms

            -- 客户端认证类型是秘钥方式
            if v.clientAuthenticatorType == constants.OAUTH.CLIENT_AUTH_TYPE then
                local client_secret_url = self.configuration:get_keycloak_client_secret_url(realms, client_uid)
                status, client_secret, err = obtain_client_secret(client_secret_url, admin_token)
                if err then
                    return status, nil, err
                end
            end

            -- 客户端开启服务授权
            if v.authorizationServicesEnabled == true then
                local client_resources_url = self.configuration:get_keycloak_resources_url(realms, client_uid)
                status, client_resources, err = obtain_client_resources(client_resources_url, admin_token)
                if err then
                    return status, nil, err
                end
            end

            set[index] = client:new(v, client_secret, cjson_encode(client_resources))
            index = index + 1

        end
    end

    return 200, set, nil
end

--- 换取令牌
--
-- @param 授权码
-- @return 状态码、令牌数据table、错误提示
function _M:exchange_token(code)

    local post_headers = { [constants.HEADERS.AUTHZ] = constants.HEADERS.BASIC .. " " .. self.configurations.kong_client_credentials }

    local post_body = {
        [constants.OAUTH.GRANT_TYPE] = constants.OAUTH.GRANT_AUTHORIZATION_CODE,
        [constants.OAUTH.CODE] = code,
        [constants.OAUTH.REDIRECT_URI] = self.configurations.kong_redirect_url
    }

    local status, res, err = zhttp:http_post_client(self.configurations.keycloak_token_url,
            post_headers, encode_args(post_body, false, false), 6000)

    if err then
        return 500, nil, err
    end

    local decode_res = cjson_decode(res)

    if status ~= 200 then
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    return 200, decode_res, nil
end

--- 刷新令牌
--
-- @param 刷新令牌
-- @return 状态码、令牌数据table、错误提示
function _M:refresh_token(refresh_token)

    local post_headers = { [constants.HEADERS.AUTHZ] = constants.HEADERS.BASIC .. " " .. self.configurations.kong_client_credentials }

    local post_body = {
        [constants.OAUTH.GRANT_TYPE] = constants.OAUTH.GRANT_REFRESH_TOKEN,
        [constants.OAUTH.REFRESH_TOKEN] = refresh_token
    }

    local status, res, err = zhttp:http_post_client(self.configurations.keycloak_token_url,
            post_headers, encode_args(post_body, true, false), 6000)

    if err then
        return 500, nil, err
    end

    local decode_res = cjson_decode(res)

    if status ~= 200 then
        return status, nil, decode_res.error .. ": " .. decode_res.error_description
    end

    return 200, decode_res, nil
end

return _M