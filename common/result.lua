---
--- 统一响应结果的封装
--- Created by zqzhou.
--- DateTime: 2019/7/2 下午5:21
---

local M = {}

local CODE = {
    ok = 200
}

--
-- 构建响应结果
--
-- 状态码：根据HTTP状态码自定义
-- 消息：提示或错误信息
-- 跳转地址：客户端可跳转至认证页面
-- 数据：根据不同请求响应数据
--
function M:build_result(code, message, location, data)
    local result = {
        code = code,
        message = message,
        location = location,
        data = data
    }
    return result
end

return M