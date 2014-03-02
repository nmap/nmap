local http = require "http"
local table = require "table"
local url = require "url"

---
-- http-default-accounts-fingerprints.lua
-- This file contains fingerprint data for http-default-accounts.nse
--
-- STRUCTURE:
-- * <code>name</code> - Descriptive name
-- * <code>category</code> - Category
-- * <code>login_combos</code>
---- * <code>username</code> - Default username
---- * <code>password</code> - Default password
-- * <code>paths</code> - Paths table containing the possible location of the target
-- * <code>target_check</code> - Validation function of the target (optional)
-- * <code>login_check</code> - Login function of the target
--
-- TODO: Update the functionality of <code>target_check</code> to differentiate
--       between valid HTTP/200 and a custom error page.
---

---
-- Requests given path using basic authentication.
-- @param host Host table
-- @param port Port table
-- @param path Path to request
-- @param user Username for Basic Auth
-- @param pass Password for Basic Auth
-- @param digest_auth Digest Authentication
-- @return True if login in was successful
---
local function try_http_basic_login(host, port, path, user, pass, digest_auth)
  local credentials = {username = user, password = pass, digest = digest_auth}
  local req = http.get(host, port, path, {no_cache=true, auth=credentials, redirect_ok = false})
  if req.status and req.status ~= 401 and req.status ~= 403 then
    return true
  end
  return false
end

---
-- Tries to login with a http post, if the FAIL string is not found
-- we assume login in was successful
-- @param host Host table
-- @param port Port table
-- @param target Target file
-- @param failstr String shown when login in fails
-- @param params Post parameters
-- @param follow_redirects True if you want redirects to be followed
-- @return True if login in was successful
---
local function try_http_post_login(host, port, path, target, failstr, params, follow_redirects)
  local req = http.post(host, port, url.absolute(path, target), {no_cache=true}, nil, params)

  if not req.status then return false end
  local status = tonumber(req.status) or 0
  if follow_redirects and ( status > 300 and status < 400 ) then
    req = http.get(host, port, url.absolute(path, req.header.location), { no_cache = true, redirect_ok = false })
  end
  if req.status and req.status ~= 404 and not(http.response_contains(req, failstr)) then
    return true
  end
  return false
end

---
-- Returns authentication realm advertised in an HTTP response
-- @param response HTTP response object, such as a result from http.get()
-- @return realm found in response header WWW-Authenticate
--               (or nil if not present)
---
local function http_auth_realm(response)
  local auth = response.header["www-authenticate"] or ""
  return auth:match('%srealm="([^"]*)')
end

fingerprints = {}

---
--WEB
---
table.insert(fingerprints, {
  name = "Cacti",
  category = "web",
  paths = {
    {path = "/cacti/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "index.php", "Invalid User Name/Password", {action="login", login_username=user, login_password=pass}, false)
  end
})

table.insert(fingerprints, {
  name = "Apache Tomcat",
  category = "web",
  paths = {
    {path = "/manager/html/"},
    {path = "/tomcat/manager/html/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Tomcat Manager Application"
  end,
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"},
    -- http://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4189
    {username = "ovwebusr", password = "OvW*busr1"},
    -- http://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4188
    {username = "j2deployer", password = "j2deployer"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Apache Axis2",
  category = "web",
  paths = {
    {path = "/axis2/axis2-admin/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
  end,
  login_combos = {
    {username = "admin", password = "axis2"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login", "Invalid auth credentials!", {submit="+Login+", userName=user, password=pass})
  end
})
---
--ROUTERS
---
table.insert(fingerprints, {
  name = "Arris 2307",
  category = "routers",
  paths = {
    {path = "/logo_t.gif"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login.cgi", "Login Error !!", {action="submit", page="", logout="", pws=pass})
  end
})

table.insert(fingerprints, {
  name = "Cisco IOS",
  category = "routers",
  paths = {
    {path = "/exec/show/log/CR"},
    {path = "/level/15/exec/-/configure/http"},
    {path = "/level/15/exec/-"},
    {path = "/level/15/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    -- Exact PCRE: "^level 15?( or view)? access$"
    return realm:gsub("_"," "):find("^level 15? .*access$")
  end,
  login_combos = {
    {username = "", password = ""},
    {username = "cisco", password = "cisco"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco WAP200",
  category = "routers",
  paths = {
    {path = "/StatusLan.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Linksys WAP200"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco WAP55AG",
  category = "routers",
  paths = {
    {path = "/WPA_Preshared.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Linksys WAP55AG"
  end,
  login_combos = {
    {username = "", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Nortel VPN Router",
  category = "routers",
  paths = {
    {path = "/manage/bdy_sys.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Management(1)"
  end,
  login_combos = {
    {username = "admin", password = "setup"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "F5 BIG-IP",
  category = "routers",
  paths = {
    {path = "/tmui/login.jsp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["f5-login-page"] == "true"
           and response.body
           and response.body:find("logmein.html",1,true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "logmein.html", "login%.jsp%?msgcode=1", {username=user, passwd=pass})
  end
})

---
--Digital recorders
---
table.insert(fingerprints, {
  name = "Digital Sprite 2",
  category = "security",
  paths = {
    {path = "/frmpages/index.html"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WebPage Configuration"
  end,
  login_combos = {
    {username = "dm", password = "web"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, true)
  end
})
