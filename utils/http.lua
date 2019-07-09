---
--- HTTP请求工具类
--- Created by zqzhou.
--- DateTime: 2019/6/25 上午10:14
---
local zhttp = require "resty.http"

local _M = {}

--- 发送GET请求
--
-- @param url
-- @param headers
-- @param timeout
-- @return status, body, err_
function _M:http_get_client(url, headers, timeout)
    local httpc = zhttp.new()

    timeout = timeout or 30000
    httpc:set_timeout(timeout)

    headers = headers or {}
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    local res, err_ = httpc:request_uri(url, {
        method = "GET",
        headers = headers
    })
    httpc:set_keepalive(5000, 100)
    httpc:close()

    if not res then
        return res.status, nil, err_
    else
        return res.status, res.body, err_
    end
end

--- 发送POST请求
--
-- @param url
-- @param headers
-- @param timeout
-- @return status, body, err_
function _M:http_post_client(url, headers, body, timeout)
    local httpc = zhttp.new()

    timeout = timeout or 30000
    httpc:set_timeout(timeout)

    headers = headers or {}
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    local res, err_ = httpc:request_uri(url, {
        method = "POST",
        body = body,
        headers = headers
    })
    httpc:set_keepalive(5000, 100)
    httpc:close()

    if not res then
        return res.status, nil, err_
    else
        return res.status, res.body, err_
    end
end

--- 发送DELETE请求
--
-- @param url
-- @param headers
-- @param timeout
-- @return status, body, err_
function _M:http_delete_client(url, headers, timeout)
    local httpc = zhttp.new()

    timeout = timeout or 30000
    httpc:set_timeout(timeout)

    headers = headers or {}
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    local res, err_ = httpc:request_uri(url, {
        method = "DELETE",
        headers = headers
    })
    httpc:set_keepalive(5000, 100)
    httpc:close()

    if not res then
        return res.status, nil, err_
    else
        return res.status, res.body, err_
    end
end

return _M