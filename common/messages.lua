---
--- 响应结果的消息定义
--- Created by zqzhou.
--- DateTime: 2019/7/3 下午5:39
---
return {
    INTERNAL_ERR = "internal_error: an unexpected error occurred",
    INVALID_TOKEN_PREFIX = "invalid_token: ",
    INVALID_SIG = "invalid_token: invalid signature",
    CODE_NOT_FOUND = "invalid_grant: code not found",
    STATE_NOT_FOUND = "invalid_grant: state not found",
    INVALID_CLIENT = "invalid_client: missing or invalid client authentication",
    MISSING_TID = "invalid_request: missing tid",
    INVALID_TID = "invalid_request: invalid tid",
    INVALID_TOKEN = "invalid_request: invalid token",
    INVALID_GRANT_TYPE = "invalid_request: missing or invalid grant type",
    MISSING_REFRESH_TOKEN = "invalid_request: missing or invalid refresh token",
    UNRECOGNIZED_TOKEN = "invalid_token: unrecognized token",
    MISSING_CLIENT_ID = "invalid_request: missing authenticated clientid",
    FORBIDDEN_ACCESS = "对不起，您没有权限访问当前地址！"
}