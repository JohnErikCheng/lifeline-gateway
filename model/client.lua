---
--- 客户端
--- Created by zqzhou.
--- DateTime: 2019/7/4 下午5:17
---

local Client = {}

Client.__index = Client

--- 对象实例化方法
--
-- @param 包含客户端信息的table
-- @param 客户端秘钥
-- @param 客户端资源集合json
function Client:new(client, client_secret, client_resources_json)
    return {
        id = client.id,
        client_uid = client.id,
        client_id = client.clientId,
        client_secret = client_secret,
        enabled = client.enabled,
        auth_enabled = client.authorizationServicesEnabled,
        client_resources = client_resources_json
    }
end

--- 客户端资源数据
--
-- @param 包含客户端资源数据的table
function Client:resource(resource)
    return {
        rsname = resource.name,
        uris = resource.uris
    }
end

return Client