---
--- 黑白名单访问控制
--- Created by admin.
--- DateTime: 2019/7/2 9:26
---
local kong = kong
local string = string

local _M = {}

--- 黑白名单访问控制入口
--
-- 所有请求先经过该逻辑处理
-- @param 插件配置conf
-- @return true:直接放过
function _M.access(conf, request_path)

    local whitelist = conf.whitelist or {}

    if #whitelist == 0 then
        return false
    end

    for i = 1, #whitelist do
        if string.find(request_path, whitelist[i]) then
            kong.log.notice("白名单匹配【" .. request_path .. " with " .. whitelist[i] .. "】")
            return true
        end
    end

    return false
end

return _M