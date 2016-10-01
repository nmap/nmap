local base64 = require "base64"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"
local have_openssl, openssl = pcall(require, 'openssl')

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
  return req.status
         and req.status ~= 401
         and req.status ~= 403
         and req.status ~= 404
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
    {path = "/"},
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
    return try_http_post_login(host, port, path, "index.php",
                              "%sname%s*=%s*(['\"]?)login_password%1[%s>]",
                              {action="login", login_username=user, login_password=pass})
  end
})

table.insert(fingerprints, {
  -- Version 2.0.6
  name = "Zabbix",
  category = "web",
  paths = {
    {path = "/zabbix/"}
  },
  target_check = function (host, port, path, response)
    -- true if the response is HTTP/200 and sets cookie "zbx_sessionid"
    if response.status == 200 then
      for _, ck in ipairs(response.cookies or {}) do
        if ck.name:lower() == "zbx_sessionid" then return true end
      end
    end
    return false
  end,
  login_combos = {
    {username = "admin", password = "zabbix"}
  },
  login_check = function (host, port, path, user, pass)
    local req = http.post(host, port, url.absolute(path, "index.php"),
                          {no_cache=true, redirect_ok=false},
                          nil,
                          {request="", name=user, password=pass, enter="Sign in"},
                          false)
    return req.status == 302 and req.header["location"] == "dashboard.php"
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
  -- Version 4.1.31, 6.0.24, 7.0.54
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
  name = "Apache Felix OSGi Management Console",
  category = "web",
  paths = {
    {path = "/system/console"},
    {path = "/lc/system/console"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "OSGi Management Console"
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "karaf", password = "karaf"},
    {username = "smx",   password = "smx"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 1.4.1, 1.5.2, 1.5.3, 1.6.0, 1.6.1
  name = "Apache Axis2",
  category = "web",
  paths = {
    {path = "/axis2/axis2-admin/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:lower():find("<title>login to axis2 :: administration page</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "axis2"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login",
                              "%sname%s*=%s*(['\"]?)password%1[%s>]",
                              {submit=" Login ", userName=user, password=pass})
  end
})

table.insert(fingerprints, {
   -- Version 0.4.4.6.1-alpha on SamuraiWTF 2.6
  name = "BeEF",
  category = "web",
  paths = {
    {path = "/ui/authentication/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("BeEF", 1, true)
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
  -- Version 12.2SE on Catalyst 3750, 3845, CBS3020, 12.3 on Aironet 1300
  name = "Cisco IOS",
  category = "routers",
  paths = {
    {path = "/"},
    -- TODO: Remove these paths completely unless a bug gets filed (9/1/2016)
    -- (The paths are likely redundant. "/" should be covering all the cases.)
    -- {path = "/exec/show/log/CR"},
    -- {path = "/level/15/exec/-/configure/http"},
    -- {path = "/level/15/exec/-"},
    -- {path = "/level/15/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    -- Exact PCRE: "^level 15?( or view)? access$"
    return realm:gsub("_"," "):find("^level 15? .*%f[^%s]access$")
  end,
  login_combos = {
    {username = "", password = ""},
    {username = "cisco", password = "cisco"},
    {username = "Cisco", password = "Cisco"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 1.0.22
  name = "Cisco WAP200",
  category = "routers",
  paths = {
    {path = "/"}
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
  -- Version 1.07.01
  name = "Cisco WAP55AG",
  category = "routers",
  paths = {
    {path = "/"}
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
  -- Version 1.0.1.3
  name = "ASUS RT-N10U",
  category = "routers",
  paths = {
    {path = "/"}
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
  name = "Motorola AP-7532",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"]
           and response.header["server"]:find("^lighttpd/%d+%.")
           and response.body
           and response.body:lower():find("<title>motorola solutions</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "motorola"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {_dc = stdnse.clock_ms(),
                  username = user,
                  password = pass}
    local lurl = url.absolute(path, "rest.fcgi/services/rest/login?" .. url.build_query(form))
    local req = http.get(host, port, lurl, {no_cache=true, redirect_ok=false})
    return req.status == 200
           and req.body
           and req.body:find('[{,]%s*"status"%s*:%s*true%s*[,}]')
  end
})

table.insert(fingerprints, {
  -- Version 3.3.2, 4.3.1, 4.4.0, 4.4.1 on RFS6000
  name = "Motorola RF Switch",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"]
           and response.header["server"]:find("^thttpd/%d+%.")
           and response.body
           and response.body:lower():find("<title>motorola wireless network management</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "superuser"}
  },
  login_check = function (host, port, path, user, pass)
    local login = ("J20K34NMMT89XPIJ34S login %s %s"):format(stdnse.tohex(user), stdnse.tohex(pass))
    local lurl = url.absolute(path, "usmCgi.cgi/?" .. url.escape(login))
    local req = http.get(host, port, lurl, {no_cache=true, redirect_ok=false})
    return req.status == 200
           and req.body
           and req.body:find("^login 0 ")
  end
})

table.insert(fingerprints, {
  -- Version 08.05.100 on NVR 1750D
  name = "Nortel VPN Router",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "HTTP Server"
           and response.body
           and response.body:lower():find("<title>nortel vpn router</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "setup"}
  },
  login_check = function (host, port, path, user, pass)
    -- realm="Management(8)"
    return try_http_basic_login(host, port,
                               url.absolute(path, "manage/bdy_sys.htm"),
                               user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 11.4.1, 11.5.3
  name = "F5 BIG-IP",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("F5 Networks", 1, true)
           and response.body:find("BIG-IP", 1, true)
           and response.body:find("/tmui/tmui/system/settings/redirect.jsp", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "tmui/logmein.html",
                              "login%.jsp%?msgcode=1",
                              {username=user, passwd=pass})
  end
})

table.insert(fingerprints, {
  -- Version 10.5 on MPX 8005
  name = "Citrix NetScaler",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("NetScaler", 1, true)
           and response.body:lower():find("<title>citrix login</title>", 1, true)
  end,
  login_combos = {
    {username = "nsroot", password = "nsroot"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login/do_login",
                              "Invalid username or password",
                              {username=user, password=pass, url="", timezone_offset="0"},
                              false)
  end
})

---
--Digital recorders
---
table.insert(fingerprints, {
  -- UI Version 03.2 (4.8), 03.2 (5.5)
  name = "Digital Sprite 2",
  category = "security",
  paths = {
    {path = "/frmpages/index.html"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WebPage Configuration"
           and response.header["server"] == "ADH-Web"
  end,
  login_combos = {
    {username = "dm", password = "web"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, true)
  end
})

---
--Industrial systems
---
table.insert(fingerprints, {
  -- Version 2.1.2, 2.2.0 on TSX ETY Port, 1.0.4, 2.2.0 on TSX ETY410
  name = "Schneider Modicon Web",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and response.header["server"]
           and response.header["server"]:find("^Schneider%-WEB/V%d+%.")
           and response.header["location"]
           and response.header["location"]:find("/index%.htm$")
  end,
  login_combos = {
    {username = "USER", password = "USER"}
  },
  login_check = function (host, port, path, user, pass)
    -- realm="Schneider Web"
    return try_http_basic_login(host, port,
                               url.absolute(path, "secure/system/globaldata.htm?Language=English"),
                               user, pass, false)
  end
})

---
--Printers
---
table.insert(fingerprints, {
  -- Version 61.17.5Z on ZTC GK420d
  name = "Zebra Printer",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Zebra Technologies", 1, true)
           and response.body:lower():find('<a href="config.html">view printer configuration</a>', 1, true)
  end,
  login_combos = {
    {username = "", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "authorize",
                              "incorrect password", {["0"]=pass})
  end
})

table.insert(fingerprints, {
  -- Version 61.17.5Z on ZTC GK420d, 1.01.4
  name = "Zebra Print Server",
  category = "printer",
  paths = {
    {path = "/server/TCPIPGEN.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Network Print Server"
  end,
  login_combos = {
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 1.04.9 on RICOH MP C4503, 1.05 on MP 5054, 1.12 on MP C5000
  name = "RICOH Web Image Monitor",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"]
           and response.header["server"]:find("^Web%-Server/%d+%.")
           and response.body
           and response.body:find("/websys/webArch/mainFrame.cgi", 1, true)
  end,
  login_combos = {
    {username = "admin",      password = ""},
    {username = "supervisor", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    -- determine proper login path by locale
    local req0 = http.get(host, port, path)
    if req0.status ~= 200 then return false end
    local lpath = req0.body and req0.body:match('location%.href="(/[^"]+/)mainFrame%.cgi"')
    if not lpath then return false end
    -- harvest the login form token
    local req1 = http.get(host, port, url.absolute(lpath, "authForm.cgi"),
                         {cookies="cookieOnOffChecker=on", no_cache=true, redirect_ok=false})
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
    local req2 = http.post(host, port, url.absolute(lpath, "login.cgi"),
                          {cookies=req1.cookies, no_cache=true, redirect_ok=false},
                          nil, form)
    local loc = req2.header["location"] or ""
    -- successful login is a 302-redirect that sets a session cookie with numerical value
    if not (req2.status == 302 and loc:find("/mainFrame%.cgi$")) then return false end
    for _, ck in ipairs(req2.cookies or {}) do
      if ck.name:lower() == "wimsesid" then return ck.value:find("^%d+$") end
    end
    return false
  end
})

table.insert(fingerprints, {
  -- Version 071.*, 072.* on WorkCentre 7835, 7845, ColorQube 8900X
  name = "Xerox WorkCentre/ColorQube",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find('SuppliesType != "InkStick"', 1, true)
           and response.body:find("XEROX WORKCENTRE", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "1111"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {_fun_function="HTTP_Authenticate_fn",
                  NextPage="/properties/authentication/luidLogin.php",
                  webUsername=user,
                  webPassword=pass,
                  frmaltDomain="default"}
    return try_http_post_login(host, port, path, "userpost/xerox.set",
                              "/login%.php%?invalid=t", form)
  end
})

table.insert(fingerprints, {
  -- Version 3.6/4
  name = "Lantronix ThinWeb Manager",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.header["server"]
           and response.header["server"]:find("^Gordian Embedded")
           and response.body
           and response.body:lower():find("<title>lantronix thinweb manager", 1, true)
  end,
  login_combos = {
    {username = "", password = "system"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "server_eps.html")
    -- obtain login nonce
    local req1 = http.get(host, port, lurl, {no_cache=true, redirect_ok=false})
    if req1.status ~= 403 then return false end
    local nonce = nil
    for _, ck in ipairs(req1.cookies or {}) do
      if ck.name == "SrvrNonce" then
        nonce = ck.value
        break
      end
    end
    if not nonce then return false end
    -- credential is the MD5 hash of the nonce and the password (in upper case)
    local creds = stdnse.tohex(openssl.md5(nonce .. ":" .. pass:upper()))
    local cookies = ("SrvrNonce=%s; SrvrCreds=%s"):format(nonce, creds)
    local req2 = http.get(host, port, lurl,
                         {cookies=cookies, no_cache=true, redirect_ok=false})
    return req2.status == 200
  end
})

---
--Storage
---
table.insert(fingerprints, {
  -- Version TS200R021 on MSA 2000 G3
  name = "HP Storage Management Utility",
  category = "storage",
  paths = {
    {path = "/api/id/"}
  },
  -- TODO: Change the probe path to "/" and use the following target_check
  -- once the http library adds support for gzip encoding. Don't forget
  -- to change url.absolute() argument from "../" to "api/" in login_check.
  --target_check = function (host, port, path, response)
  --  return have_openssl
  --         and response.status == 200
  --         and response.body
  --         and response.body:find("brandStrings", 1, true)
  --         and response.body:find("checkAuthentication", 1, true)
  --         and response.body:find("hp stuff init", 1, true)
  --end,
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.header["command-status"]
           and response.header["command-status"]:find("^0 %({.*systemName:.*,%s*controller:.*}%)")
  end,
  login_combos = {
    {username = "monitor", password = "!monitor"},
    {username = "manage",  password = "!manage"},
    {username = "admin",   password = "!admin"}
  },
  login_check = function (host, port, path, user, pass)
    local creds = stdnse.tohex(openssl.md5(user .. "_" .. pass))
    local content = "/api/login/" .. creds
    local header = {["Content-Type"] = "application/x-www-form-urlencoded",
                    ["datatype"] = "json"}
    local req = http.generic_request(host, port, "POST",
                                    url.absolute(path, "../"),
                                    {header=header, content=content,
                                    no_cache=true, redirect_ok=false})
    return req.status == 200
           and (req.header["command-status"] or ""):find("^1 ")
  end
})

---
--Virtualization systems
---
table.insert(fingerprints, {
  -- Version 5.0.0
  name = "VMware ESXi",
  category = "virtualization",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ID_EESX_Welcome", 1, true)
           and response.body:find("/folder?dcPath=ha-datacenter", 1, true)
  end,
  login_combos = {
    {username = "root", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    -- realm="VMware HTTP server"
    return try_http_basic_login(host, port,
                               url.absolute(path, "folder?dcPath=ha-datacenter"),
                               user, pass, false)
  end
})

---
--Remote consoles
---
table.insert(fingerprints, {
  -- Version 5.5, 6.1
  name = "Lantronix SLC",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"]
           and response.header["server"]:find("^mini_httpd")
           and response.body
           and response.body:find("lantronix", 1, true)
           and response.body:find("slcpassword", 1, true)
  end,
  login_combos = {
    {username = "sysadmin", password = "PASS"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "./",
                              "%sname%s*=%s*(['\"]?)slcpassword%1[%s>]",
                              {slclogin=user, slcpassword=pass})
  end
})

table.insert(fingerprints, {
  --Version 1.10.12
  name = "Dell iDRAC6",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 301
           and response.header["server"]
           and response.header["server"]:find("^Mbedthis%-Appweb/%d+%.")
           and response.header["location"]
           and response.header["location"]:find("/start%.html$")
  end,
  login_combos = {
    {username = "root", password = "calvin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "data/login",
                            "<authResult>1</authResult>",
                            {user=user, password=pass})
  end
})
