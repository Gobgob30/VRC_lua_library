local Authentication;
local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
-- encoding
function b64enc(data)
    return ((data:gsub('.', function(x)
        local r, b = '', x:byte()
        for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r;
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c = 0
        for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0) end
        return b:sub(c + 1, c + 1)
    end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

-- decoding
function b64dec(data)
    data = string.gsub(data, '[^' .. b .. '=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c = 0
        for i = 1, 8 do c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0) end
        return string.char(c)
    end))
end

local function encode_parm(tbl)
    -- todo: how would I get the argument name
    -- local args_table = {}
    local str = ""
    for k, v in pairs(tbl) do
        str = table.concat({ str, table.concat({ k, tostring(v) }, "=") }, "")
        if k ~= #tbl then
            str = table.concat({ str, "&" }, "")
        end
    end
    return str
end

local function encode_cookie(tbl)
    local str = ""
    for k, v in pairs(tbl) do
        str = table.concat({ str, table.concat({ k, tostring(v) }, "=") }, "")
        if k ~= #tbl then
            str = table.concat({ str, ";" }, "")
        end
    end
    return str
    -- local args_array = { ... }
    -- for i = 1, #args_array do
    --     str = table.concat({ str, debug.getlocal(2, i), "=", args_array[i] }, "")
    --     if i ~= #args_array then
    --         str = str .. ";"
    --     end
    -- end
    -- return str
end

local function decode_cookie(set_cookie)
    if not set_cookie then return {} end
    local cookie = {}
    for match in string.gmatch(set_cookie, "([^;]+)") do
        if match:find("=") then
            local key, value = match:match("([^=%s]+)=(.*)")
            cookie[key] = tonumber(value) and tonumber(value) or value
        else
            cookie[match:gsub("^[%s]+", "")] = true
        end
    end
    return cookie
end

Authentication = {
    check_user = function(email, displayName, userId, excludeUserId)
        if not userId or not email or not displayName then
            return false, "require either email, displayName, or userId"
        end
        local req, err = http.get(table.concat({ "https://api.vrchat.cloud/api/1/auth/exists?", encode_parm(email, displayName, userId, excludeUserId) }, ""))
        if not req then
            return nil, err
        end
        local data = textutils.unserializeJSON(req.readAll())
        req.close()
        if not data or data.userExists == nil then
            return nil, "failed to check user"
        end
        return data.userExists
    end,
    getCred = function()
        if settings.get("vrc_lib.save_cookie", true) then
            return settings.get("vrc_lib.cookie", {}).auth
        else
            return nil, "not saving"
        end
    end,
    getCred2fa = function()
        if settings.get("vrc_lib.save_cookie", true) then
            return settings.get("vrc_lib.2fa_cookie", {}).auth
        else
            return nil, "not saving"
        end
    end,
    is_logged_in = function(cookie, twoFactorAuth)
        cookie         = cookie or Authentication.getCred()
        twoFactorAuth  = twoFactorAuth or Authentication.getCred2fa()
        local req, err = http.get("https://api.vrchat.cloud/api/1/auth/user", {
            ["Cookie"] = encode_cookie {
                auth = cookie,
                twoFactorAuth = twoFactorAuth
            }
        })
        if not req then
            return nil, err
        end
        local data = textutils.unserializeJSON(req.readAll())
        req.close()
        if not data then
            return nil, "failed to check user"
        end
        if data.requiresTwoFactorAuth then
            return false, "requires 2FA"
        end
        return true
    end,
    login = function(email, password)
        if not email or not password then
            return nil, "require email and password"
        end
        local cookie = settings.get("vrc_lib.save_cookie", true) and settings.get("vrc_lib.cookie", {}).auth or nil
        local cookie2fa = settings.get("vrc_lib.2fa_cookie", true) and settings.get("vrc_lib.2fa_cookie", {}).auth or nil
        local req, err = http.get("https://api.vrchat.cloud/api/1/auth/user", {
            ["Authorization"] = table.concat({ "Basic", b64enc(table.concat({ textutils.urlEncode(email), textutils.urlEncode(password) }, ":")) }, " "),
            ["Cookie"] = encode_cookie {
                auth = cookie,
                twoFactorAuth = cookie2fa
            }
        })
        if not req then
            return nil, err
        end
        cookie = cookie and settings.get("vrc_lib.cookie", {}) or decode_cookie(req.getResponseHeaders()["Set-Cookie"])
        if settings.get("vrc_lib.save_cookie", true) and not cookie.expires then
            settings.set("vrc_lib.save_cookie", settings.get("vrc_lib.save_cookie", true))
            settings.set("vrc_lib.cookie", {
                auth = cookie.auth,
                expires = math.floor((os.epoch("utc") / 1000 + cookie["Max-Age"]) + .5)
            })
            settings.save()
        end
        local data = textutils.unserializeJSON(req.readAll())
        req.close()
        if not data then
            return nil, "failed to login"
        end
        if data.requiresTwoFactorAuth then
            return data.requiresTwoFactorAuth, cookie.auth
        end
        return true, cookie.auth
    end,
    Auth2fa = setmetatable({
        ["totp"] = true,
        ["otp"] = true,
        ["emailotp"] = true
    }, {
        __call = function(self, code, cookie, type)
            if not self[type] then
                return nil, "invalid type"
            end
            require("cc.pretty").pretty_print({
                ["Content-Type"] = "application/json",
                ["Cookie"] = encode_cookie {
                    auth = cookie
                }
            })
            local req, err, t = http.post(table.concat({ "https://api.vrchat.cloud/api/1/auth/twofactorauth/", type, "/verify" }, ""), textutils.serializeJSON({
                code = code
            }), {
                ["Content-Type"] = "application/json",
                ["Cookie"] = encode_cookie {
                    auth = cookie
                }
            })
            -- if t then
            --     -- require("cc.pretty").pretty_print(t.getResponseHeaders())
            --     print(t.readAll(), t.getResponseCode())
            -- end
            if not req then
                return nil, err
            end
            local cookies = decode_cookie(req.getResponseHeaders()["Set-Cookie"])
            if settings.get("vrc_lib.save_cookie", true) then
                settings.set("vrc_lib.2fa_cookie", {
                    auth = cookies.twoFactorAuth,
                    expires = math.floor((os.epoch("utc") / 1000 + cookies["Max-Age"]) + .5)
                })
            end
            local data = textutils.unserializeJSON(req.readAll())
            req.close()
            if not data then
                return nil, "failed to login"
            end
            return data.verified
        end
    }),
    logout = function(auth)
        local req, err = http.post {
            url = "https://api.vrchat.cloud/api/1/logout",
            headers = {
                ["Cookie"] = encode_cookie {
                    auth = auth
                },
            },
            method = "PUT"
        }
        if not req then
            return nil, err
        end
        local data = textutils.unserializeJSON(req.readAll())
        req.close()
        if not data then
            return nil, "failed to logout"
        end
        return data.success and true or false
    end,
    deleteUser = function(auth, user_id)
        local req, err = http.post {
            url = table.concat({ "https://api.vrchat.cloud/api/1/user/", user_id, "/delete" }, ""),
            headers = {
                ["Cookie"] = encode_cookie {
                    auth = auth
                },
            },
            method = "POST"
        }
        if not req then
            return nil, err
        end
        local data = textutils.unserializeJSON(req.readAll())
        req.close()
        if not data then
            return nil, "failed to delete user"
        end
        return {
            message = data.accountDeletionLog.message,
            time_of_deletion = data.accountDeletionLog.deletionScheduled,
            time_started = data.accountDeletionLog.dateTime
        }
    end
}

return {
    Authentication = Authentication
}
