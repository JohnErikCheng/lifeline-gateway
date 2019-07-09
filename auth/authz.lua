---
--- 权限判断
--- Created by zqzhou.
--- DateTime: 2019/6/25 下午5:02
---
local cjson = require "cjson"
local zresult = require "kong.plugins.keycloak-auth.common.result"
local configs = require "kong.plugins.keycloak-auth.common.configs"
local clients_dao = require "kong.plugins.keycloak-auth.dao.clients"
local messages = require "kong.plugins.keycloak-auth.common.messages"
local constants = require "kong.plugins.keycloak-auth.common.constants"
local user_permissions_dao = require "kong.plugins.keycloak-auth.dao.user_permissions"

local kong = kong
local ipairs = ipairs
local string = string
local cjson_decode = cjson.decode
local cjson_encode = cjson.encode
local ngx_re_gmatch = ngx.re.gmatch

--- 服务内部错误 500
--
local function internal_server_error()
    local body = zresult:build_result(500, messages.INTERNAL_ERR, nil, nil)
    return kong.response.exit(500, body, constants.HEADERS.JSON_CONTANT_HEADER)
end

--- 无权限错误 403
--
local function forbidden_error_exit()
    local body = zresult:build_result(403, messages.FORBIDDEN_ACCESS, nil, nil)
    return kong.response.exit(403, body, constants.HEADERS.JSON_CONTANT_HEADER)
end

--- 获取Authorization头的Bearer数据
--
-- @return 令牌
local function retrieve_token()
    local token = nil
    local authorization_header = kong.request.get_header(constants.HEADERS.AUTHZ)
    if authorization_header then
        local iterator = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if iterator then
            local m, err = iterator()
            if err then
                kong.log.err("获取Authorization头数据时出错: ", err)
                return internal_server_error()
            end

            if m and #m > 0 then
                token = m[1]
            end
        end
    end

    return token
end

--- 匹配资源
--
-- @param 待匹配路径
-- @param 资源集合
-- @return 匹配到的资源名称
local function matching_resources(path, resources)
    local shoot_resource

    if resources and #resources > 0 then
        for i, v in ipairs(resources) do

            local uris = v.uris
            if uris and #uris > 0 then
                for i = 1, #uris do
                    if string.find(path, uris[i]) then
                        shoot_resource = v.rsname
                        kong.log.notice("资源匹配【" .. path .. " with " .. uris[i] .. "】")
                        break
                    end
                end
            end

            if shoot_resource then
                break
            end
        end
    end

    return shoot_resource
end

--[[

  authz public interface

]]--

local _M = {}

function _M.access(conf, request_path)

    local client_id = kong.request.get_header(constants.HEADERS.XACD)

    local configuration = configs:new(conf)

    local k_client_dao = clients_dao:instance(configuration)

    -- 先获取客户端的数据
    local client, err = k_client_dao:load_client_by_client_id(client_id)

    if err then
        kong.log.err("获取客户端数据时出错: ", err)
        return internal_server_error()
    end

    kong.log.notice(cjson_encode(client))

    -- 开启授权的客户端才执行权限过滤
    if client and client.auth_enabled then
        local client_resources = client.client_resources
        local shoot_resource_name

        if client_resources then
            shoot_resource_name = matching_resources(request_path, cjson_decode(client_resources))
        end

        -- 匹配到资源，返回资源名称，继续匹配用户权限
        if shoot_resource_name then
            local token = retrieve_token()

            local user_id = kong.request.get_header(constants.HEADERS.XAUD)

            local k_user_permissions_dao = user_permissions_dao:instance(configuration)

            local user_permission, err = k_user_permissions_dao:load_permissions_by_user_client_id(token, user_id, client_id)

            if err then
                kong.log.err("获取用户权限数据时出错: ", err)
                return internal_server_error()
            end

            kong.log.notice(cjson_encode(user_permission))

            local has_permission = false

            local user_permissions = user_permission.permissions

            if user_permissions and #user_permissions > 0 then

                for i, v in ipairs(cjson_decode(user_permissions)) do
                    if string.find(shoot_resource_name, v.rsname) then
                        has_permission = true
                        break
                    end
                end

            end

            -- 无权限
            if not has_permission then
                return forbidden_error_exit()
            end

        end
    end

end

return _M