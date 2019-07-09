---
--- 认证处理
--- Created by zqzhou.
--- DateTime: 2019/6/25 上午10:27
---
local cjson = require "cjson"
local utils = require "kong.tools.utils"
local rsa_keys = require "kong.plugins.keycloak-auth.auth.keys"
local tokens_dao = require "kong.plugins.keycloak-auth.dao.tokens"
local zresult = require "kong.plugins.keycloak-auth.common.result"
local jwt_decoder = require "kong.plugins.keycloak-auth.utils.jwt"
local configs = require "kong.plugins.keycloak-auth.common.configs"
local messages = require "kong.plugins.keycloak-auth.common.messages"
local url_coder = require "kong.plugins.keycloak-auth.utils.url_coder"
local kservice = require "kong.plugins.keycloak-auth.service.keycloak"
local constants = require "kong.plugins.keycloak-auth.common.constants"

local kong = kong
local type = type
local table = table
local string = string
local unpack = unpack
local sub = string.sub
local find = string.find
local tostring = tostring
local split = utils.split
local strip = utils.strip
local concat = table.concat
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local ngx_re_gmatch = ngx.re.gmatch
local encode_args = utils.encode_args
local random_string = utils.random_string
local table_contains = utils.table_contains
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64

local rsa_public_key = rsa_keys.rsa_public_key
local rsa_private_key = rsa_keys.rsa_private_key

--- 服务内部错误 500
--
local function internal_server_error()
    local body = zresult:build_result(500, messages.INTERNAL_ERR, nil, nil)
    return kong.response.exit(500, body, constants.HEADERS.JSON_CONTANT_HEADER)
end

--- 错误响应
--
-- @param 状态码
-- @param 错误提示
-- @param 预留跳转地址
local function response_exit_error(status, err, location)
    local body = zresult:build_result(status, err, location, nil)
    return kong.response.exit(status, body, constants.HEADERS.JSON_CONTANT_HEADER)
end

--- 获取请求中的参数
--
-- 从GET、POST、PUT、PATCH类型的请求中获取参数的集合
-- @return 包含参数名和参数值的table
local function retrieve_parameters()
    local uri_args = kong.request.get_query()
    local method = kong.request.get_method()

    if method == "POST" or method == "PUT" or method == "PATCH" then
        local body_args = kong.request.get_body()

        return kong.table.merge(uri_args, body_args)
    end

    return uri_args
end

--- 获取重定向到认证中心的地址
--
-- 获取客户端的请求来源并拼装成请求认证客户端的URL地址
-- @param configurations
-- @return URL地址
local function retrieve_auth_url(configurations)
    -- 获取当前请求的来源
    -- 直接输入的地址请求，来源为空；页面点击的请求，来源为页面地址
    local client_uri = kong.request.get_header(constants.HEADERS.REFERER)
    if not client_uri then
        client_uri = "http://192.168.222.133:8000/api/resourcea"
    end

    -- 重定向地址，uri编码
    local redirect_uri = url_coder:encode_url(configurations.kong_redirect_url)

    -- 使用state参数传递客户端来源地址，base64url编码
    local state = jwt_decoder:base64_encode(client_uri)

    local segments = {
        configurations.keycloak_auth_url .. "?response_type=" .. constants.OAUTH.CODE,
        "client_id=" .. configurations.kong_client_id,
        "redirect_uri=" .. redirect_uri,
        "state=" .. state,
        "login=true",
        "scope=openid"
    }

    return concat(segments, "&")

end

--- 响应重定向到认证中心
--
-- 根据请求的类型响应不同的结果给客户端，包含重定向地址
-- @param configurations
-- @param 重定向到登录的原因，反馈给前端的消息
-- @return exit响应
local function redirect_to_auth(configurations, reason)
    local x_requested_with = kong.request.get_header(constants.HEADERS.AJAX)

    local status, body, headers = 302, {}, constants.HEADERS.JSON_CONTANT_HEADER

    if x_requested_with and x_requested_with == "XMLHttpRequest" then
        -- 如果是AJAX请求
        body = zresult:build_result(status, reason, retrieve_auth_url(configurations), nil)
    else
        -- 非AJAX请求
        headers = { [constants.HEADERS.LOCATION] = retrieve_auth_url(configurations) }
    end

    return kong.response.exit(status, body, headers)
end

--- 获取Authorization头数据
--
-- 根据传入的正则表达式获取Authorization头数据
-- @param 正则表达式
-- @return Authorization头数据
local function retrieve_auth_header(target)
    local token = nil
    local authorization_header = kong.request.get_header(constants.HEADERS.AUTHZ)
    if authorization_header then
        local iterator = ngx_re_gmatch(authorization_header, target)
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

--- 获取Authorization头的Bearer数据
--
-- @return Bearer令牌
local function retrieve_token()
    return retrieve_auth_header("\\s*[Bb]earer\\s+(.+)")
end

--- 获取Authorization头的Basic数据
--
-- @return Basic数据
local function retrieve_client_credentials()
    return retrieve_auth_header("\\s*[Bb]asic\\s+(.+)")
end

--- 重新签名
--
-- 使用RSA256私钥对令牌重新签名，并且返回新的令牌
-- @param 待重签名的令牌
-- @return 重签名后的令牌
local function re_signature(token)
    local result, pos, str, div, len = {}, 0, token, ".", 3

    local iter = function()
        return find(str, div, pos, true)
    end

    for st, sp in iter do
        result[#result + 1] = sub(str, pos, st - 1)
        pos = sp + 1
        len = len - 1
        if len <= 1 then
            break
        end
    end

    result[#result + 1] = sub(str, pos)

    local header_64, claims_64 = unpack(result)

    local re_sig_64, err = jwt_decoder:sign_signature_with(constants.ALGORITHM, header_64 .. "." .. claims_64, rsa_private_key)
    if err then
        kong.log.err("重新签名时出错: ", err)
        return internal_server_error()
    end

    local segments = { header_64, claims_64, re_sig_64 }

    return concat(segments, ".")

end

--- 校验令牌
--
-- 对重签名的令牌进行校验、验签等，并还原回原签名后返回
-- @param 重签名的令牌
-- @param configuration
-- @return jwt和重签名前的令牌
local function verify_token(token, configuration)

    -- 解码token
    local jwt, err = jwt_decoder:new(token)
    if err then
        return response_exit_error(401, messages.INVALID_TOKEN_PREFIX .. tostring(err), retrieve_auth_url(configuration:configurations()))
    end

    -- 公钥验签
    local verify, err = jwt:verify_signature(constants.ALGORITHM, rsa_public_key)
    if err or not verify then
        return response_exit_error(401, messages.INVALID_SIG, retrieve_auth_url(configuration:configurations()))
    end

    -- 转发之前，替换回Keycloak签发的令牌

    local k_token_dao = tokens_dao:instance(configuration)

    local token, err = k_token_dao:load_token_by_token_id(jwt.claims.jti)

    if err then
        kong.log.err("还原令牌时出错: ", err)
        return internal_server_error()
    end

    if not token then
        return response_exit_error(400, messages.INVALID_TOKEN, retrieve_auth_url(configuration:configurations()))
    end

    return jwt, token.access_token
end

--- 校验客户端凭证
--
-- 对请求携带的客户端凭证进行校验
-- @param 请求携带的客户端凭证原数据
-- @return 校验结果，true or false
local function verify_client(client_credentials)

    if not client_credentials or #client_credentials == 0 then
        return false
    end

    local base64_decode_client_credentials = ngx_decode_base64(client_credentials)

    local sep, fields = ":", {}
    local pattern = string.format("([^%s]+)", sep)
    base64_decode_client_credentials:gsub(pattern, function(c)
        fields[#fields + 1] = c
    end)

    if #fields ~= 2 then
        return false
    end

    local client_id, client_secret = unpack(fields)

    -- 从缓存中校验该客户端凭证

    return true
end

--- 处理来自认证中心重定向过来的请求
--
-- 所有客户端的登录均面向Kong客户端，用户登录后认证中心均会向/portal/auth/redirect地址跳转
-- 此方法用来处理该请求路由，使用code换取访问令牌后重定向到客户端
-- @param configuration
-- @return 携带令牌id响应重定向到客户端
local function hand_redirect_request(configuration)

    local parameters = retrieve_parameters()
    local code = parameters[constants.OAUTH.CODE]

    if nil == code or #code == 0 then
        return response_exit_error(401, messages.CODE_NOT_FOUND, retrieve_auth_url(configuration:configurations()))
    end

    -- 使用state代表客户端地址吧！
    local state = parameters[constants.OAUTH.STATE]
    if nil == state or #state == 0 then
        return response_exit_error(401, messages.STATE_NOT_FOUND, retrieve_auth_url(configuration:configurations()))
    end

    local service_client = kservice:instance(configuration)
    local status, result, err = service_client:exchange_token(code)

    if status == 500 then
        kong.log.err("换取令牌时出错: ", err)
    end

    if err then
        return response_exit_error(status, err, retrieve_auth_url(configuration:configurations()))
    end

    -- 从access_token中解析出tid
    local jwt, err = jwt_decoder:new(result.access_token)
    if err then
        kong.log.err("解码令牌时出错: ", err)
        return response_exit_error(500, messages.INTERNAL_ERR, retrieve_auth_url(configuration:configurations()))
    end

    local k_token_dao = tokens_dao:instance(configuration)

    local result, err = k_token_dao:insert({
        id = jwt.claims.jti,
        tid = jwt.claims.jti,
        access_token = result.access_token,
        refresh_token = result.refresh_token,
        expires_in = result.expires_in
    })

    if err then
        kong.log.err("保存令牌时出错: ", err)
    end

    result, err = k_token_dao:insert_tid(jwt.claims.jti)

    if err then
        kong.log.err("保存令牌时出错: ", err)
    end

    return kong.response.exit(302, {}, { [constants.HEADERS.LOCATION] = jwt_decoder:base64_decode(state) .. "?tid=" .. jwt.claims.jti })
end

--- 处理来自各客户端获取令牌的请求
--
-- 客户端接收到tid后，携带客户端凭证请求/portal/auth/token地址获取访问令牌
-- 此方法用来处理该请求路由，返回tid对应的访问令牌、刷新令牌和有效时长等数据
-- 这里也把用户的所有权限一并返回【提供给客户端动态展示菜单和页面按钮元素等】
-- @param configuration
-- @return 用户令牌、刷新令牌、有效期、用户权限集合等
local function hand_token_request(configuration)

    -- 客户端凭证
    local client_credentials = retrieve_client_credentials()

    if not verify_client(client_credentials) then
        return response_exit_error(401, messages.INVALID_CLIENT, retrieve_auth_url(configuration:configurations()))
    end

    local parameters = retrieve_parameters()
    local tid = parameters[constants.OAUTH.TID]

    if not tid or #tid == 0 then
        return response_exit_error(400, messages.MISSING_TID, retrieve_auth_url(configuration:configurations()))
    end

    local k_token_dao = tokens_dao:instance(configuration)

    tid = k_token_dao:load_tid_by_tid_id(tid)

    if not tid or #tid == 0 then
        return response_exit_error(400, messages.INVALID_TID, retrieve_auth_url(configuration:configurations()))
    end

    -- 以上校验完成客户端的请求参数 end

    -- 以下根据tid从缓存中获取访问令牌、刷新令牌、有效时长、用户权限数据 start

    local token, err = k_token_dao:load_token_by_token_id(tid)

    if err then
        kong.log.err("获取令牌时出错: ", err)
        return internal_server_error()
    end

    if not token then
        return response_exit_error(400, messages.INVALID_TID, retrieve_auth_url(configuration:configurations()))
    end

    local access_token = token.access_token

    local token = {
        access_token = re_signature(access_token),
        expires_in = token.expires_in,
        refresh_token = token.refresh_token
    }

    -- 删除tid数据，保证只能使用其换取一次
    local res, err = k_token_dao:delete_tid(tid)

    if err then
        kong.log.err("清除令牌ID时出错: ", err)
        return internal_server_error()
    end

    local body = zresult:build_result(200, constants.RESULT.SUCCESS, nil, token)
    return kong.response.exit(200, body, constants.HEADERS.JSON_CONTANT_HEADER)

end

--- 处理来自各客户端获取令牌的请求
--
-- 客户端携带客户端凭证和刷新令牌请求/portal/auth/refresh地址请求刷新访问令牌
-- 此方法用来处理该请求路由，返回刷新后的用户令牌、刷新令牌和有效时长等数据
-- 另外，这里也可以把用户的所有权限也一并返回【提供给客户端动态的刷新展示菜单和页面按钮元素等】
-- @param configuration
-- @return 用户令牌、刷新令牌、有效期、用户权限集合等
local function hand_refresh_request(configuration)

    -- 客户端凭证
    local client_credentials = retrieve_client_credentials()

    if not verify_client(client_credentials) then
        return response_exit_error(401, messages.INVALID_CLIENT, retrieve_auth_url(configuration:configurations()))
    end

    local parameters = retrieve_parameters()

    local grant_type_param = parameters[constants.OAUTH.GRANT_TYPE]
    if not grant_type_param or grant_type_param ~= constants.OAUTH.GRANT_REFRESH_TOKEN then
        return response_exit_error(400, messages.INVALID_GRANT_TYPE, retrieve_auth_url(configuration:configurations()))
    end

    local refresh_token_param = parameters[constants.OAUTH.REFRESH_TOKEN]

    if not refresh_token_param or #refresh_token_param == 0 then
        return response_exit_error(400, messages.MISSING_REFRESH_TOKEN, retrieve_auth_url(configuration:configurations()))
    end

    -- 以上校验完成客户端的请求参数 end

    -- 以下主动使用kong客户端凭证请求认证中心刷新令牌 start

    local service_client = kservice:instance(configuration)
    local status, result, err = service_client:refresh_token(refresh_token_param)

    if status == 500 then
        kong.log.err("刷新令牌时出错: ", err)
    end

    if err then
        return response_exit_error(status, err, retrieve_auth_url(configuration:configurations()))
    end

    local jwt, err = jwt_decoder:new(result.access_token)
    if err then
        kong.log.err("解码令牌时出错: ", err)
        return response_exit_error(500, messages.INTERNAL_ERR, retrieve_auth_url(configuration:configurations()))
    end

    local k_token_dao = tokens_dao:instance(configuration)

    local res, err = k_token_dao:insert({
        id = jwt.claims.jti,
        tid = jwt.claims.jti,
        access_token = result.access_token,
        refresh_token = result.refresh_token,
        expires_in = result.expires_in
    })

    if err then
        kong.log.err("保存令牌时出错: ", err)
    end

    local token = {
        access_token = re_signature(result.access_token),
        expires_in = result.expires_in,
        refresh_token = result.refresh_token
    }

    local body = zresult:build_result(200, constants.RESULT.SUCCESS, nil, token)
    return kong.response.exit(200, body, constants.HEADERS.JSON_CONTANT_HEADER)
end

--- 处理来自各客户端注销登录的请求
--
-- 客户端携带访问令牌请求/portal/auth/logout地址请求注销会话
-- 此方法用来处理该请求路由，删除令牌缓存并请求认证中心注销会话
-- @param configuration
-- @return 退出后响应重定向到认证中心
local function hand_logout_request(configuration)
    --local redirect_uri = kong.request.get_query_arg("redirect_uri")
    --
    --if nil == redirect_uri then
    --    return exit:unauthorized_error({ message = "No redirect_uri found", redirect_uri = "" })
    --end

    local token = retrieve_token()

    local token_type = type(token)
    if token_type ~= "string" or token_type == "nil" then
        return response_exit_error(401, messages.UNRECOGNIZED_TOKEN, retrieve_auth_url(configuration:configurations()))
    end

    local jwt = verify_token(token, configuration)

    -- 以上校验完成客户端的请求参数 end

    -- 以下请求认证中心注销会话、清空令牌缓存 start

    local service_client = kservice:instance(configuration)
    local status, result, err = service_client:logout_session(jwt.claims.session_state)

    if result ~= constants.RESULT.SUCCESS then
        kong.log.err("注销会话时出错: ", err)
        return response_exit_error(status, err, retrieve_auth_url(configuration:configurations()))
    end

    -- 清除令牌缓存
    local k_token_dao = tokens_dao:instance(configuration)

    local result, err = k_token_dao:delete(jwt.claims.jti)

    if err then
        kong.log.err("清除令牌时出错: ", err)
        return internal_server_error()
    end

    return redirect_to_auth(configuration:configurations(), constants.RESULT.LOGOUT)
end

--- 处理非网关认证类的业务服务的请求
--
-- 除几种网关认证类的路由请求外，所有请求要经过该方法的认证判断
-- 判断是否携带令牌、令牌的有效性校验，决定放过还是重定向至登录
-- @param configuration
-- @return 设置请求头
local function do_authentication(configuration)

    local client_id = kong.request.get_header(constants.HEADERS.XACD)

    if nil == client_id or #client_id == 0 then
        response_exit_error(401, messages.MISSING_CLIENT_ID, retrieve_auth_url(configuration:configurations()))
    end

    local token = retrieve_token()

    -- token未携带或校验失败，引导至登录
    local token_type = type(token)
    if token_type ~= "string" or token_type == "nil" then
        return redirect_to_auth(configuration:configurations(), messages.UNRECOGNIZED_TOKEN)
    end

    local jwt, kc_token = verify_token(token, configuration)

    -- 以上校验完成客户端的请求参数 end

    -- 以下设置一些请求头数据，包括用户id、用户名、有效令牌 start

    kong.service.request.set_header(constants.HEADERS.XAUD, jwt.claims.sub)
    kong.service.request.set_header(constants.HEADERS.XAUN, jwt.claims.preferred_username)
    kong.service.request.set_header(constants.HEADERS.AUTHZ, constants.HEADERS.BEARER .. " " .. kc_token)

end

--[[

  authn public interface

]]--

local _M = {}

--- 认证模块主方法入口
--
-- 处理所有认证类路由及服务请求的认证状态判断
-- @param 插件配置conf
-- @return
function _M.access(conf, request_path)

    -- 当前请求为认证重定向
    if nil ~= find(conf.kong_redirect_path, request_path) then
        return hand_redirect_request(configs:new(conf))
    end

    -- 当前请求为签发令牌
    if nil ~= find(conf.kong_token_path, request_path) then
        return hand_token_request(configs:new(conf))
    end

    -- 当前请求为刷新令牌，这里主动请求认证中心刷新后将令牌响应回客户端
    if nil ~= find(conf.kong_refresh_path, request_path) then
        return hand_refresh_request(configs:new(conf))
    end

    -- 当前请求为注销会话，需要请求keycloak注销session，并销毁缓存中的token
    if nil ~= find(conf.kong_logout_path, request_path) then
        return hand_logout_request(configs:new(conf))
    end

    -- 这里的请求需要校验携带的令牌，并判断放过请求还是跳转至登录
    return do_authentication(configs:new(conf))
end

return _M