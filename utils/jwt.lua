---
--- JWT令牌校验工具类
--- Created by zqzhou.
--- DateTime: 2019/6/25 上午10:14
-- @see https://github.com/x25/luajwt
---
local json = require "cjson"
local rsa = require "kong.plugins.keycloak-auth.utils.rsa"

local rep = string.rep
local sub = string.sub
local find = string.find
local type = type
local time = ngx.time
local pairs = pairs
local error = error
local pcall = pcall
local concat = table.concat
local insert = table.insert
local unpack = unpack
local assert = assert
local tostring = tostring
local setmetatable = setmetatable
local getmetatable = getmetatable
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64

-- 签名方法
local alg_sign = {
    SHA256 = function(input, private_key)
        local priv, err = rsa:new({ private_key = private_key, algorithm = "SHA256" })
        if not priv then
            return nil, err
        end

        local sig, err = priv:sign(input)
        if not sig then
            return nil, err
        end

        return sig, nil
    end
}

-- 验签方法
local alg_verify = {
    RS256 = "",
    SHA256 = function(input, signature, public_key)
        local pub, err = rsa:new({ public_key = public_key, algorithm = "SHA256" })
        if not pub then
            return nil, err
        end
        local verify, err = pub:verify(input, signature)
        if not verify then
            return nil, err
        end
        return verify, nil
    end
}


--- base 64 encoding
-- @param input String to base64 encode
-- @return Base64 encoded string
local function base64_encode(input)
    local result = encode_base64(input, true)
    result = result:gsub("+", "-"):gsub("/", "_")
    return result
end


--- base 64 decode
-- @param input String to base64 decode
-- @return Base64 decoded string
local function base64_decode(input)
    local remainder = #input % 4

    if remainder > 0 then
        local padlen = 4 - remainder
        input = input .. rep("=", padlen)
    end

    input = input:gsub("-", "+"):gsub("_", "/")
    return decode_base64(input)
end


--- Tokenize a string by delimiter
-- Used to separate the header, claims and signature part of a JWT
-- @param str String to tokenize
-- @param div Delimiter
-- @param len Number of parts to retrieve
-- @return A table of strings
local function tokenize(str, div, len)
    local result, pos = {}, 0

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
    return result
end


--- Parse a JWT
-- Parse a JWT and validate header values.
-- @param token JWT to parse
-- @return A table containing base64 and decoded headers, claims and signature
local function decode_token(token)
    -- Get b64 parts
    local header_64, claims_64, signature_64 = unpack(tokenize(token, ".", 3))

    -- Decode JSON
    local ok, header, claims, signature = pcall(function()
        return json.decode(base64_decode(header_64)),
        json.decode(base64_decode(claims_64)),
        base64_decode(signature_64)
    end)
    if not ok then
        return nil, "invalid JSON"
    end

    if not header.alg or type(header.alg) ~= "string" or not alg_verify[header.alg] then
        return nil, "invalid alg".. header.alg
    end

    if not claims then
        return nil, "invalid claims"
    end

    -- 过期
    if ngx.time() > claims.exp then
        return nil, "expired token"
    end

    if not signature then
        return nil, "invalid signature"
    end

    return {
        token = token,
        header_64 = header_64,
        claims_64 = claims_64,
        signature_64 = signature_64,
        header = header,
        claims = claims,
        signature = signature
    }
end


-- For test purposes
local function encode_token(data, key, alg, header)
    if type(data) ~= "table" then
        error("Argument #1 must be table", 2)
    end

    if type(key) ~= "string" then
        error("Argument #2 must be string", 2)
    end

    if header and type(header) ~= "table" then
        error("Argument #4 must be a table", 2)
    end

    alg = alg or "SHA256"

    if not alg_sign[alg] then
        error("Algorithm not supported", 2)
    end

    local header = header or { typ = "JWT", alg = alg }
    local segments = {
        base64_encode(json.encode(header)),
        base64_encode(json.encode(data))
    }

    local signing_input = concat(segments, ".")
    local signature = alg_sign[alg](signing_input, key)

    segments[#segments + 1] = base64_encode(signature)

    return concat(segments, ".")
end

local err_list_mt = {}

local function add_error(errors, k, v)
    if not errors then
        errors = {}
    end

    if errors and errors[k] then
        if getmetatable(errors[k]) ~= err_list_mt then
            errors[k] = setmetatable({ errors[k] }, err_list_mt)
        end

        insert(errors[k], v)
    else
        errors[k] = v
    end

    return errors
end


--[[

  JWT public interface

]]--


local _M = {}

_M.__index = _M


--- Instantiate a JWT parser
-- Parse a JWT and instantiate a JWT parser for further operations
-- Return errors instead of an instance if any encountered
-- @param token JWT to parse
-- @return JWT parser
-- @return error if any
function _M:new(token)
    if type(token) ~= "string" then
        error("Token must be a string, got " .. tostring(token), 2)
    end

    local token, err = decode_token(token)
    if err then
        return nil, err
    end

    return setmetatable(token, _M)
end


--- Verify a JWT signature
-- Verify the current JWT signature against a given key
-- @param key Key against which to verify the signature
-- @return A boolean indicating if the signature if verified or not
function _M:verify_signature(alg, key)
    local flag, err = alg_verify[alg](self.header_64 .. "." .. self.claims_64, self.signature, key)
    if err then
        return nil, err
    end
    return flag
end

-- Sign a signature with A KEY
function _M:sign_signature(alg, key)
    local signature, err = alg_sign[alg](self.header_64 .. "." .. self.claims_64, key)
    if err then
        return nil, err
    end
    return base64_encode(signature), nil
end

function _M:sign_signature_with(alg, data, key)
    local signature, err = alg_sign[alg](data, key)
    if err then
        return nil, err
    end
    return base64_encode(signature), nil
end

function _M:base64_decode(input)
    return base64_decode(input)
end

function _M:base64_encode(input)
    return base64_encode(input)
end

--- Registered claims according to RFC 7519 Section 4.1
local registered_claims = {
    nbf = {
        type = "number",
        check = function(nbf)
            if nbf > time() then
                return "token not valid yet"
            end
        end
    },
    exp = {
        type = "number",
        check = function(exp)
            if exp <= time() then
                return "token expired"
            end
        end
    }
}


--- Verify registered claims (according to RFC 7519 Section 4.1)
-- Claims are verified by type and a check.
-- @param claims_to_verify A list of claims to verify.
-- @return A boolean indicating true if no errors zere found
-- @return A list of errors
function _M:verify_registered_claims(claims_to_verify)
    if not claims_to_verify then
        claims_to_verify = {}
    end

    local errors
    local claim
    local claim_rules

    for _, claim_name in pairs(claims_to_verify) do
        claim = self.claims[claim_name]
        claim_rules = registered_claims[claim_name]

        if type(claim) ~= claim_rules.type then
            errors = add_error(errors, claim_name, "must be a " .. claim_rules.type)

        else
            local check_err = claim_rules.check(claim)
            if check_err then
                errors = add_error(errors, claim_name, check_err)
            end
        end
    end

    return errors == nil, errors
end


--- Check that the maximum allowed expiration is not reached
-- @param maximum_expiration of the claim
-- @return A Boolean indicating true if the claim has reached the maximum
-- allowed expiration time
-- @return error if any
function _M:check_maximum_expiration(maximum_expiration)
    if maximum_expiration <= 0 then
        return true
    end

    local exp = self.claims.exp
    if exp == nil or exp - time() > maximum_expiration then
        return false, { exp = "exceeds maximum allowed expiration" }
    end

    return true
end

_M.encode = encode_token

return _M
