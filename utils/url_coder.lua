---
--- URL编码解码
--- Created by zqzhou.
--- DateTime: 2019/7/5 下午2:28
---

local string = string
local tonumber = tonumber

local _M = {}

--- URL解码
--
-- 将URL编码的字符集改为原字符串
-- @param 待解码的字符串
-- @return 解码后的结果
function _M:decode_url(s)
    s = string.gsub(s, '%%(%x%x)', function(h)
        return string.char(tonumber(h, 16))
    end)
    return s
end

--- URL编码
--
-- 将字符串使用URL编码成ASCII字符集
-- @param 待编码的字符串
-- @return 编码后的结果
function _M:encode_url(s)
    s = string.gsub(s, "([^%w%.%- ])", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
    return string.gsub(s, " ", "+")
end

return _M