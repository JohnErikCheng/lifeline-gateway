---
--- 用户权限
--- Created by zqzhou.
--- DateTime: 2019/7/5 上午10:05
---
local cjson = require "cjson"

local type = type
local ipairs = ipairs
local cjson_encode = cjson.encode

local UserPermission = {}

UserPermission.__index = UserPermission

--- 对象实例化方法
--
-- @param 用户id
-- @param 客户端id
-- @param 用户权限数据table
function UserPermission:new(user_id, client_id, user_permission)

    local set = {}
    local index = 1

    for k, v in ipairs(user_permission) do
        if type(v) == "table" then
            local td = {
                rsname = v.rsname
            }
            set[index] = td
            index = index + 1
        end
    end

    return {
        user_client_id = user_id .. ":" .. client_id,
        user_id = user_id,
        client_id = client_id,
        permissions = cjson_encode(set)
    }
end

return UserPermission