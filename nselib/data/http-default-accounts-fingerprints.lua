local base64 = require "base64"
local bin = require "bin"
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
  return auth:match('%srealm%s*=%s*"([^"]*)')
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
    -- true if the response is HTTP/200 and sets cookie "Cacti"
    if response.status == 200 then
      for _, ck in ipairs(response.cookies or {}) do
        if ck.name:lower() == "cacti" then return true end
      end
    end
    return false
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "index.php", "Invalid User Name/Password", {action="login", login_username=user, login_password=pass}, false)
  end
})

table.insert(fingerprints, {
  name = "Xplico",
  category = "web",
  paths = {
    {path = "/users/login"}
  },
  target_check = function (host, port, path, response)
    -- true if the response is HTTP/200 and sets cookie "Xplico"
    if response.status == 200 then
      for _, ck in ipairs(response.cookies or {}) do
        if ck.name:lower() == "xplico" then return true end
      end
    end
    return false
  end,
  login_combos = {
    {username = "admin", password = "xplico"},
    {username = "xplico", password = "xplico"}
  },
  login_check = function (host, port, path, user, pass)
    -- harvest all hidden fields from the login form
    local req1 = http.get(host, port, path, {no_cache=true, redirect_ok = false})
    if req1.status ~= 200 then return false end
    local html = req1.body and req1.body:match('<form%s+action%s*=%s*"[^"]*/users/login".->(.-)</form>')
    if not html then return false end
    local form = {}
    for n, v in html:gmatch('<input%s+type%s*=%s*"hidden"%s+name%s*=%s*"(.-)"%s+value%s*=%s*"(.-)"') do
      form[n] = v
    end
    -- add username and password to the form and submit it
    form["data[User][username]"] = user
    form["data[User][password]"] = pass
    local req2 = http.post(host, port, path, {no_cache=true, cookies=req1.cookies}, nil, form)
    if req2.status ~= 302 then return false end
    local loc = req2.header["location"]
    return loc and (loc:match("/admins$") or loc:match("/pols/index$"))
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
  name = "Adobe LiveCycle Management Console",
  category = "web",
  paths = {
    {path = "/lc/system/console"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "OSGi Management Console"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
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

table.insert(fingerprints, {
  name = "BeEF",
  category = "web",
  paths = {
    {path = "/ui/authentication/"}
  },
  target_check = function (host, port, path, response)
    return response.body
           and response.body:lower():find("<title>beef authentication</title>", 1, true)
  end,
  login_combos = {
    {username = "beef", password = "beef"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login",
                               "{%s*success%s*:%s*false%s*}",
                               {["username-cfrm"]=user, ["password-cfrm"]=pass})
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
  name = "ASUS RT-N10U",
  category = "routers",
  paths = {
    {path = "/as.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N10U"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Motorola RF Switch",
  category = "routers",
  paths = {
    {path = "/getfwversion.cgi"}
  },
  target_check = function (host, port, path, response)
    -- true if the response is HTTP/200 and returns a firmware version
    return response.status == 200
           and not response.header["server"]
           and response.header["content-type"] == "text/plain"
           and response.body
           and response.body:find("\n%d+%.%d+%.%d+%.%d+%-%w+\n")
  end,
  login_combos = {
    {username = "admin", password = "superuser"}
  },
  login_check = function (host, port, path, user, pass)
    local tohex = function (str)
                    local _, hex = bin.unpack("H" .. str:len(), str)
                    return hex:lower()
                  end
    local login = ("J20K34NMMT89XPIJ34S login %s %s"):format(tohex(user), tohex(pass))
    local lpath = url.absolute(path, "usmCgi.cgi/?" .. url.escape(login))
    local req = http.get(host, port, lpath, {no_cache=true, redirect_ok = false})
    return req
           and req.status == 200
           and req.body
           and req.body:match("^login 0 ")
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

---
--Printers
---
table.insert(fingerprints, {
  name = "Zebra Printer",
  category = "printer",
  paths = {
    {path = "/setgen"}
  },
  target_check = function (host, port, path, response)
    return response.body
           and response.body:lower():find("<h1>zebra technologies<br>", 1, true)
  end,
  login_combos = {
    {username = "", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {}
    form["0"] = pass
    return try_http_post_login(host, port, path, "authorize", "incorrect password", form)
  end
})

table.insert(fingerprints, {
  name = "Zebra Print Server",
  category = "printer",
  paths = {
    {path = "/server/TCPIPGEN.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Network Print Server"
           and response.header["server"]
           and response.header["server"] == "Micro-Web"
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "RICOH Web Image Monitor",
  category = "printer",
  paths = {
    {path = "/web/guest/en/websys/webArch/header.cgi"}
  },
  target_check = function (host, port, path, response)
    return response.header["server"]
           and response.header["server"]:find("^Web%-Server/%d+%.%d+$")
           and response.body
           and response.body:find("RICOH", 1, true)
  end,
  login_combos = {
    {username = "admin",      password = ""},
    {username = "supervisor", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    -- harvest the login form token
    local req1 = http.get(host, port, url.absolute(path, "authForm.cgi"), {no_cache=true, redirect_ok = false, cookies = "cookieOnOffChecker=on"})
    if req1.status ~= 200 then return false end
    local token = req1.body and req1.body:match('<input%s+type%s*=%s*"hidden"%s+name%s*=%s*"wimToken"%s+value%s*=%s*"(.-)"')
    if not token then return false end
    -- build the login form and submit it
    local form = {wimToken = token,
                  userid_work = "",
                  userid = base64.enc(user),
                  password_work = "",
                  password = base64.enc(pass),
                  open = ""}
    local req2 = http.post(host, port, url.absolute(path, "login.cgi"), {no_cache=true, cookies=req1.cookies}, nil, form)
    local loc = req2.header["location"] or ""
    -- successful login is a 302-redirect that sets a session cookie with numerical value
    if not (req2.status == 302 and loc:find("/mainFrame%.cgi$")) then return false end
    for _, ck in ipairs(req2.cookies or {}) do
      if ck.name:lower() == "wimsesid" then return ck.value:find("^%d+$") end
    end
    return false
  end
})

---
--Remote consoles
---
table.insert(fingerprints, {
  name = "Lantronix SLC",
  category = "console",
  paths = {
    {path = "/scsnetwork.htm"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"]
           and response.header["server"]:find("^mini_httpd")
           and response.body
           and response.body:find("<title>Lantronix SLC",1,true)
  end,
  login_combos = {
    {username = "sysadmin", password = "PASS"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "./", "%sname%s*=%s*(['\"]?)slcpassword%1[%s>]", {slclogin=user, slcpassword=pass})
  end
})
