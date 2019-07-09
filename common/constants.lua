---
--- 插件的常量定义
--- Created by zqzhou.
--- DateTime: 2019/6/25 下午5:09
---

return {
    -- 空
    EMPTY = {},

    -- oauth类常量
    OAUTH = {
        RESPONSE_TYPE = "response_type",
        STATE = "state",
        CODE = "code",
        TID = "tid",
        TOKEN = "token",
        REFRESH_TOKEN = "refresh_token",
        SCOPE = "scope",
        CLIENT_ID = "client_id",
        CLIENT_SECRET = "client_secret",
        REDIRECT_URI = "redirect_uri",
        ACCESS_TOKEN = "access_token",
        GRANT_TYPE = "grant_type",
        GRANT_AUTHORIZATION_CODE = "authorization_code",
        GRANT_CLIENT_CREDENTIALS = "client_credentials",
        GRANT_REFRESH_TOKEN = "refresh_token",
        GRANT_PASSWORD = "password",
        GRANT_RPT = "urn:ietf:params:oauth:grant-type:uma-ticket",
        CLIENT_AUTH_TYPE = "client-secret",
        AUDIENCE = "audience"
    },

    -- 请求头类常量
    HEADERS = {
        JSON_CONTANT_HEADER = { ["Content-Type"] = "application/json; charset=utf-8" },
        AJAX = "X-Requested-With",
        AUTHZ = "Authorization",
        LOCATION = "Location",
        REFERER = "Referer",
        BASIC = "Basic",
        BEARER = "Bearer",
        XACD = "X-Authenticated-Client-ID",
        XAUD = "X-Authenticated-User-ID",
        XAUN = "X-Authenticated-User-Name"
    },

    -- 结果类常量
    RESULT = {
        ERROR = "error",
        SUCCESS = "success",
        LOGOUT = "logout"
    },

    ALGORITHM = "SHA256"
}