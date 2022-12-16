local base64 = require "base64"
local http = require "http"
local json = require "json"
local math = require "math"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local tableaux = require "tableaux"
local url = require "url"
local have_openssl, openssl = pcall(require, 'openssl')

---
-- http-default-accounts-fingerprints.lua
-- This file contains fingerprint data for http-default-accounts.nse
--
-- STRUCTURE:
-- * <code>name</code> - Descriptive name
-- * <code>cpe</code> - Official CPE Dictionary entry (optional)
-- * <code>category</code> - Category
-- * <code>login_combos</code> - Table of default credential pairs
---- * <code>username</code>
---- * <code>password</code>
-- * <code>paths</code> - Table of likely locations (paths) of the target
-- * <code>target_check</code> - Validation function of the target (optional)
-- * <code>login_check</code> - Login function of the target
---

---
-- Requests given path using http.get() but disabling cache and redirects.
-- @param host The host to connect to
-- @param port The port to connect to
-- @param path The path to retrieve
-- @param options [optional] A table of HTTP request options
-- @return A response table (see library http.lua for description)
---
local function http_get_simple (host, port, path, options)
  local opts = tableaux.tcopy(options or {})
  opts.bypass_cache = true
  opts.no_cache = true
  opts.redirect_ok = false
  return http.get(host, port, path, opts)
end

---
-- Requests given path using http.post() but disabling cache and redirects.
-- (The current implementation of http.post() does not use either; this is
-- a defensive wrapper to guard against future problems.)
-- @param host The host to connect to
-- @param port The port to connect to
-- @param path The path to retrieve
-- @param options [optional] A table of HTTP request options
-- @param postdata A string or a table of data to be posted
-- @return A response table (see library http.lua for description)
---
local function http_post_simple (host, port, path, options, postdata)
  local opts = tableaux.tcopy(options or {})
  opts.no_cache = true
  opts.redirect_ok = false
  return http.post(host, port, path, opts, nil, postdata)
end

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
  local resp = http_get_simple(host, port, path, {auth=credentials})
  return resp.status
         and resp.status ~= 400
         and resp.status ~= 401
         and resp.status ~= 403
         and resp.status ~= 404
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
  local resp = http_post_simple(host, port, url.absolute(path, target), nil, params)
  if not resp.status then return false end
  local status = tonumber(resp.status) or 0
  if follow_redirects and ( status > 300 and status < 400 ) then
    resp = http_get_simple(host, port, url.absolute(path, resp.header.location))
  end
  if resp.status and resp.status ~= 404 and not(http.response_contains(resp, failstr)) then
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

---
-- Tests whether an HTTP response sets a named cookie with a given value
-- @param response a standard HTTP response object
-- @param name a case-insensitive cookie name that must be set
-- @param pattern to validate the cookie value
-- @return cookie value if such a cookie is found
---
local function sets_cookie(response, name, pattern)
  name = name:lower()
  for _, ck in ipairs(response.cookies or {}) do
    if ck.name:lower() == name then
      return (not pattern or ck.value:find(pattern)) and ck.value
    end
  end
  return false
end

---
-- Generates default scheme, host, and port components for a parsed URL.
--
-- This filter function generates the scheme, host, and port components from
-- the standard <code>host</code> and <code>port</code> script objects. These
-- components can then be passed onto function <code>url.build</code>.
--
-- As an example, the following code generates a URL for path "/test/"
-- on the current host and port:
-- <code>
-- local testurl = url.build(url_build_defaults(host, port, {path = "/test/"}))
-- </code>
-- or, alternatively, when not used as a filter:
-- <code>
-- local parsed = url_build_defaults(host, port)
-- parsed.path = "/test/"
-- local testurl = url.build(parsed)
-- </code>
--
-- @param host The host the URL is intended for.
-- @param port The port the URL is intended for.
-- @param parsed Parsed URL, as typically returned by <code>url.parse</code>,
-- or nil. The table can be be missing the scheme, host, and port components.
-- @return A clone of the parsed URL, with any missing scheme, host, and port
-- components added.
-- @see url.parse
-- @see url.build
---
local function url_build_defaults (host, port, parsed)
  local parts = tableaux.tcopy(parsed or {})
  parts.host = parts.host or stdnse.get_hostname(host, port)
  parts.scheme = parts.scheme or shortport.ssl(host, port) and "https" or "http"
  if not parts.port and port.number ~= url.get_default_port(parts.scheme) then
    parts.port = port.number
  end
  return parts
end

---
-- Encodes a string to make it safe for embedding into XML/HTML.
--
-- @param s The string to be encoded.
-- @return A string with unsafe characters encoded
---
local function xmlencode (s)
  return s:gsub("%W", function (c) return ("&#x%x;"):format(c:byte()) end)
end

fingerprints = {}

---
--WEB
---
table.insert(fingerprints, {
  -- Version 0.8.8a
  name = "Cacti",
  cpe = "cpe:/a:cacti:cacti",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/cacti/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (sets_cookie(response, "Cacti") or sets_cookie(response, "CactiEZ"))
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
  cpe = "cpe:/a:zabbix:zabbix",
  category = "web",
  paths = {
    {path = "/zabbix/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200 and sets_cookie(response, "zbx_sessionid")
  end,
  login_combos = {
    {username = "admin", password = "zabbix"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "index.php"), nil,
                                 {request="", name=user, password=pass, enter="Sign in"})
    return resp.status == 302 and resp.header["location"] == "dashboard.php"
  end
})

table.insert(fingerprints, {
  -- Version 0.7, 1.0.1
  name = "Xplico",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302 and sets_cookie(response, "Xplico")
  end,
  login_combos = {
    {username = "admin", password = "xplico"},
    {username = "xplico", password = "xplico"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "users/login")
    -- harvest all hidden fields from the login form
    local resp1 = http_get_simple(host, port, lurl)
    if resp1.status ~= 200 then return false end
    local html = (resp1.body or ""):match('<form%s+action%s*=%s*"[^"]*/users/login".->(.-)</form>')
    if not html then return false end
    local form = {}
    for n, v in html:gmatch('<input%s+type%s*=%s*"hidden"%s+name%s*=%s*"(.-)"%s+value%s*=%s*"(.-)"') do
      form[n] = v
    end
    -- add username and password to the form and submit it
    form["data[User][username]"] = user
    form["data[User][password]"] = pass
    local resp2 = http_post_simple(host, port, lurl, {cookies=resp1.cookies}, form)
    local loc = resp2.header["location"] or ""
    return resp2.status == 302
           and (loc:find("/admins$") or loc:find("/pols/index$"))
  end
})

table.insert(fingerprints, {
  --Version 5.3.1.1944 on EH6000
  name = "ExtraHop Web UI",
  category = "web",
  paths = {
    {path = "/extrahop/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("csrfmiddlewaretoken", 1, true)
           and response.body:lower():find("<title>extrahop login", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    -- obtain cookies and a CSRF token
    local resp1 = http_get_simple(host, port, path)
    if not (resp1.status == 200 and resp1.body) then return false end
    local tname, tvalue = resp1.body:match("<input%s+type%s*=%s*'hidden'%s+name%s*=%s*'(csrfmiddlewaretoken)'%s+value%s*=%s*'(.-)'")
    if not tname then return false end
    local form = {[tname]=tvalue,
                  next=path,
                  username=user,
                  password=pass}
    -- Referer header is mandatory
    local header = {["Referer"]=url.build(url_build_defaults(host, port, {path=path}))}
    local resp2 = http_post_simple(host, port, path,
                                  {cookies=resp1.cookies, header=header}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/extrahop/$")
  end
})

table.insert(fingerprints, {
  -- Version 3.2.3, 3.4.4, 4.0.8
  name = "Nagios",
  cpe = "cpe:/a:nagios:nagios",
  category = "web",
  paths = {
    {path = "/"},
    {path = "/nagios/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Nagios Access"
  end,
  login_combos = {
    {username = "nagiosadmin", password = "nagios"},
    {username = "nagiosadmin", password = "nagiosadmin"},
    -- IBM PurePower Integrated Manager
    {username = "nagiosadmin", password = "PASSW0RD"},
    -- CactiEZ
    {username = "nagiosadmin", password = "CactiEZ"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 3.1.1, 4.0.2, 4.1.2
  name = "Grafana",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302 and sets_cookie(response, "grafana_sess")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local header = {["Accept"] = "application/json, text/plain, */*",
                    ["Content-Type"] = "application/json;charset=utf-8"}
    local jin = {user=user, email="", password=pass}
    json.make_object(jin)
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 {header=header}, json.generate(jin))
    return resp.status == 200 and sets_cookie(resp, "grafana_user") == user
  end
})

table.insert(fingerprints, {
  -- Version 8.1, 9.2, 10.3.4, 10.3.6, 12.1.2
  name = "WebLogic Server Console",
  cpe = "cpe:/a:bea:weblogic_server",
  category = "web",
  paths = {
    {path = "/console/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/console/login/LoginForm%.jsp%f[;\0]")
  end,
  login_combos = {
    -- WebLogic 9.x
    {username = "weblogic", password = "weblogic"},
    -- WebLogic 10.x, 12.x
    {username = "weblogic", password = "weblogic1"},
    {username = "weblogic", password = "welcome1"},
    -- Adobe LiveCycle ES
    {username = "weblogic", password = "password"},
    -- PeopleSoft
    {username = "system", password = "Passw0rd"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "j_security_check"), nil,
                                 {j_username=user,j_password=pass,j_character_encoding="UTF-8"})
    -- WebLogic 8.x, 9.x
    if resp.status == 403 then return false end
    -- WebLogic 10.x, 12.x
    if resp.status == 302
       and (resp.header["location"] or ""):find("/console/login/LoginForm%.jsp$") then
      return false
    end
    return true
  end
})

table.insert(fingerprints, {
  name = "Apache Tomcat",
  cpe = "cpe:/a:apache:tomcat",
  category = "web",
  paths = {
    {path = "/manager/html/"},
    {path = "/manager/status/"},
    {path = "/manager/text/"},
    {path = "/tomcat/manager/html/"},
    {path = "/tomcat/manager/status/"},
    {path = "/tomcat/manager/text/"},
    {path = "/cognos_express/manager/html/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Tomcat Manager Application"
  end,
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-3548
    {username = "admin", password = ""},
    -- https://github.com/seshendra/vagrant-ubuntu-tomcat7/
    {username = "admin", password = "tomcat"},
    -- https://github.com/apache/tomcat/blob/2b8f9665dbfb89c78878784cd9b63d2b976ba623/webapps/manager/WEB-INF/jsp/403.jsp#L66
    {username = "tomcat", password = "s3cret"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-4094
    {username = "ADMIN", password = "ADMIN"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4189
    {username = "ovwebusr", password = "OvW*busr1"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4188
    {username = "j2deployer", password = "j2deployer"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-0557
    {username = "cxsdk", password = "kdsxc"},
    -- XAMPP https://www.apachefriends.org/index.html
    {username = "xampp", password = "xampp"},
    -- QLogic QConvergeConsole http://www.qlogic.com/
    {username = "QCC", password = "QLogic66"},
    -- HAPI FHIR http://hapifhir.io/
    {username = "fhir", password = "FHIRDefaultPassword"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Apache Tomcat Host Manager",
  cpe = "cpe:/a:apache:tomcat",
  category = "web",
  paths = {
    {path = "/host-manager/html/"},
    {path = "/host-manager/text/"},
    {path = "/tomcat/host-manager/html/"},
    {path = "/tomcat/host-manager/text/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Tomcat Host Manager Application"
  end,
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-3548
    {username = "admin", password = ""},
    -- https://github.com/seshendra/vagrant-ubuntu-tomcat7/
    {username = "admin", password = "tomcat"},
    -- https://github.com/apache/tomcat/blob/2b8f9665dbfb89c78878784cd9b63d2b976ba623/webapps/manager/WEB-INF/jsp/403.jsp#L66
    {username = "tomcat", password = "s3cret"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-4094
    {username = "ADMIN", password = "ADMIN"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4189
    {username = "ovwebusr", password = "OvW*busr1"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4188
    {username = "j2deployer", password = "j2deployer"},
    -- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-0557
    {username = "cxsdk", password = "kdsxc"},
    -- XAMPP https://www.apachefriends.org/index.html
    {username = "xampp", password = "xampp"},
    -- QLogic QConvergeConsole http://www.qlogic.com/
    {username = "QCC", password = "QLogic66"},
    -- HAPI FHIR http://hapifhir.io/
    {username = "fhir", password = "FHIRDefaultPassword"}
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
  cpe = "cpe:/a:apache:axis2",
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
    local resp = http_post_simple(host, port, url.absolute(path, "login"), nil,
                                 {userName=user,password=pass,submit=" Login "})
    return resp.status == 200
           and (resp.body or ""):lower():find("<a%s+href%s*=%s*(['\"])axis2%-admin/logout%1")
  end
})

table.insert(fingerprints, {
  name = "Plumtree Portal",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 302
           and (response.header["location"] or ""):find("/portal/server%.pt$")
  end,
  login_combos = {
    {username = "Administrator", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {in_hi_space="Login",
                  in_hi_spaceID="0",
                  in_hi_control="Login",
                  in_hi_dologin="true",
                  in_tx_username=user,
                  in_pw_userpass=pass,
                  in_se_authsource=""}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "portal/server.pt"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/portal/server%.pt[;?]")
           and sets_cookie(resp, "plloginoccured") == "true"
  end
})

table.insert(fingerprints, {
  -- Version 0.4.4.6.1 on SamuraiWTF 2.6, 0.4.7.0 on Kali 2016.2
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
    local resp = http_post_simple(host, port, url.absolute(path, "login"), nil,
                                 {["username-cfrm"]=user, ["password-cfrm"]=pass})
    return resp.status == 200
           and (resp.body or ""):find("{%s*success%s*:%s*true%s*}")
  end
})

table.insert(fingerprints, {
  name = "Pure Storage",
  category = "web",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body:find("<title>Pure Storage Login</title>", 1, true)
  end,
  login_combos = {
    {username = "pureuser", password = "pureuser"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login",
                               "{%s*Welcome%s*:%s*Invalid%s*}",
                               {["username"]=user, ["password"]=pass})
  end
})

table.insert(fingerprints, {
  name = "Active MQ",
  category = "web",
  paths = {
    {path = "/admin"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "ActiveMQRealm"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
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
  cpe = "cpe:/o:cisco:ios",
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
    return realm:gsub("_"," "):find("^level 15?%f[ ].* access$")
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
  -- Version (see below)
  name = "Cisco Linksys",
  cpe = "cpe:/h:linksys:*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    -- realm="Linksys WAP200", "Linksys WAP55AG", "Linksys E2000"
    return (http_auth_realm(response) or ""):find("^Linksys %u[%u%d]+$")
  end,
  login_combos = {
    -- WAP55AG, version 1.07.01
    -- E2000, version 1.0.03 (any username is valid)
    {username = "", password = "admin"},
    -- WAP200, version 1.0.22
    {username = "admin", password = "admin"},
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version ESIP-12-v302r125573-131230c_upc on EPC3925
  --         ES-16-E138-c3220r55103-150810 on EPC3928AD
  name = "Cisco EPC39xx",
  cpe = "cpe:/h:cisco:epc39*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Docsis", 1, true)
           and response.body:find("window%.location%.href%s*=%s*(['\"])Docsis_system%.asp%1")
  end,
  login_combos = {
    {username = "",      password = ""},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {username_login=user,
                  password_login=pass,
                  LanguageSelect="en",
                  Language_Submit="0",
                  login="Log In"}
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "goform/Docsis_system"),
                                 nil, form)
    local loc = resp.header["location"] or ""
    return resp.status == 302
           and (loc:find("/Quick_setup%.asp$") or loc:find("/Administration%.asp$"))
  end
})

table.insert(fingerprints, {
  -- Version 1.0.1.3 on RT-N10U, RT-N66U
  name = "ASUS RT",
  cpe = "cpe:/h:asus:rt-*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    -- realm="RT-N10U", "RT-N66U"
    return (http_auth_realm(response) or ""):find("^RT%-%u[%u%d]+$")
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 5.00.12 on F5D7234-4
  name = "Belkin G Wireless Router",
  cpe = "cpe:/h:belkin:f5d7234-4",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("setup_top.htm", 1, true)
           and response.body:find("status.stm", 1, true)
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/login.exe"), nil,
                                 -- this should be local time, not UTC
                                 {totalMSec = stdnse.clock_ms()/1000,
                                 pws = stdnse.tohex(openssl.md5(pass))})
    return resp.status == 302
           and (resp.header["location"] or ""):find("/index%.htm$")
  end
})

table.insert(fingerprints, {
  -- Version 1.00.12 on F9K1001 v1
  name = "Belkin N150",
  cpe = "cpe:/h:belkin:n150_f9k1001",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return have_openssl
           and response.status == 200
           and response.body
           and response.body:find("Belkin", 1, true)
           and response.body:find("isAPmode", 1, true)
           and response.body:lower():find("showmenu.js", 1, true)
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local form = {page="",
                  logout="",
                  action="submit",
                  pws=base64.enc(pass),
                  itsbutton1="Submit",
                  h_language="en",
                  is_parent_window="1"}
    local resp = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                 nil, form)
    return resp.status == 200
           and resp.body
           and resp.body:find("index.html", 1, true)
  end
})

table.insert(fingerprints, {
  -- Version H131-310CTU-C07_R01_4.5.5.27
  name = "Comtrend NexusLink-5631",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DSL Router"
  end,
  login_combos = {
    {username = "apuser", password = "apuser"},
    {username = "root", password = "12345"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 1.0.1-00 on model 5554
  name = "Zoom ADSL X5",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 301
           and (response.header["server"] or ""):find("^Nucleus/%d+%.")
           and (response.header["location"] or ""):find("/hag/pages/home%.htm$")
  end,
  login_combos = {
    {username = "admin", password = "zoomadsl"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port,
                               url.absolute(path, "hag/pages/home.htm"),
                               user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 2.3, 2.4 on FVS318
  name = "Netgear ProSafe Firewall FVS318",
  cpe = "cpe:/h:netgear:fvs318",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"] == "Netgear"
           and response.body
           and response.body:lower():find("<frame%s+src%s*=%s*(['\"]?)top.html%1%s")
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, url.absolute(path, "top.html"),
                               user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 2.00.03, .05, .07, .08 on GS108Ev3, GS108PEv3
  name = "Netgear ProSafe Plus Switch",
  cpe = "cpe:/h:netgear:gs108*",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("loginTData", 1, true)
           and response.body:lower():find("<title>netgear ", 1, true)
  end,
  login_combos = {
    {username = "", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "login.cgi"),
                                 nil, {password=pass})
    return resp.status == 200 and sets_cookie(resp, "GS108SID", ".")
  end
})

table.insert(fingerprints, {
  -- AP6521, AP6522, AP7522, AP7532
  name = "Motorola AP",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^lighttpd/%d+%.")
           and response.body
           and response.body:lower():find("<title>motorola solutions</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "motorola"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {_dc = math.floor(stdnse.clock_ms()),
                  username = user,
                  password = pass}
    local lurl = url.absolute(path, "rest.fcgi/services/rest/login?" .. url.build_query(form))
    local resp = http_get_simple(host, port, lurl)
    if not (resp.status == 200 and resp.body) then return false end
    local jstatus, jout = json.parse(resp.body)
    return jstatus and jout.status
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
           and (response.header["server"] or ""):find("^thttpd/%d+%.")
           and response.body
           and response.body:lower():find("<title>motorola wireless network management</title>", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "superuser"}
  },
  login_check = function (host, port, path, user, pass)
    local login = ("J20K34NMMT89XPIJ34S login %s %s"):format(stdnse.tohex(user), stdnse.tohex(pass))
    local lurl = url.absolute(path, "usmCgi.cgi/?" .. url.escape(login))
    local resp = http_get_simple(host, port, lurl)
    return resp.status == 200
           and (resp.body or ""):find("^login 0 ")
  end
})

table.insert(fingerprints, {
  -- Version 3.4.5.1 on Aruba800
  name = "ArubaOS WebUI",
  cpe = "cpe:/o:arubanetworks:arubaos",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 401
           and response.body
           and response.body:find("/images/arubalogo.gif", 1, true)
           and response.body:find("/screens/wms/wms.login", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "screens/wms/wms.login"),
                                 nil,
                                 {opcode="login", url="/", needxml="0",
                                 uid=user, passwd=pass})
    return resp.status == 200
           and (resp.body or ""):find("/screens/wmsi/monitor.summary.html", 1, true)
  end
})

table.insert(fingerprints, {
  name = "Aruba AirWave",
  cpe = "cpe:/a:arubanetworks:airwave",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 401
           and response.body
           and response.body:find("/noauth/theme/airwave/favicon.ico", 1, true)
           and response.body:find("/api/user_prefs.json", 1, true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "LOGIN",
                              "403 Forbidden",
                              {credential_0=user, credential_1=pass,
                              destination=url.absolute(path, "index.html")})
  end
})

table.insert(fingerprints, {
  -- Version 08.05.100 on NVR 1750D
  name = "Nortel VPN Router",
  cpe = "cpe:/h:nortel:vpn_router_*",
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
    return try_http_basic_login(host, port,
                               url.absolute(path, "manage/bdy_sys.htm"),
                               user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 5.0.0r8 on NetScreen 5XT
  name = "ScreenOS",
  cpe = "cpe:/o:juniper:netscreen_screenos",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^Virata%-EmWeb/R%d+_")
           and response.body
           and response.body:lower():find("admin_pw", 1, true)
  end,
  login_combos = {
    {username = "netscreen", password = "netscreen"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {admin_id="",
                  admin_pw="",
                  time=tostring(math.floor(stdnse.clock_ms())):sub(5),
                  un=base64.enc(user),
                  pw=base64.enc(pass)}
    local resp = http_post_simple(host, port, url.absolute(path, "index.html"),
                                 nil, form)
    return resp.status == 303
           and (resp.header["location"] or ""):find("/nswebui.html?", 1, true)
  end
})

table.insert(fingerprints, {
  -- Version 11.4.1, 11.5.3
  name = "F5 TMOS",
  cpe = "cpe:/o:f5:tmos",
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
  cpe = "cpe:/a:citrix:netscaler",
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
  name = "DM Digital Sprite 2",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Dedicated Micros", 1, true)
           and response.body:find("webpages/index.shtml", 1, true)
           and response.body:lower():find('<meta%s+name%s*=%s*"author"%s+content%s*=%s*"dedicated micros ')
  end,
  login_combos = {
    {username = "dm", password = "web"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port,
                               url.absolute(path, "frmpages/index.html"),
                               user, pass, true)
  end
})

table.insert(fingerprints, {
  -- Version SD32L30, ECS116/A
  name = "DM NetVu",
  category = "security",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("Dedicated Micros", 1, true)
           and response.body:find("/gui/gui_outer_frame.shtml", 1, true)
           and response.body:lower():find('<meta%s+name%s*=%s*"author"%s+content%s*=%s*"dedicated micros ')
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "gui/frmpages/gui_system.shtml")
    -- Check if authentication is required at all
    local resp = http_get_simple(host, port, lurl)
    if resp.status == 200 then
      return (resp.body or ""):find('top.render_table("System Page"', 1, true)
    end
    return try_http_basic_login(host, port, lurl, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "AXIS Network Camera (M Series)",
  category = "security",
  paths = {
    {path = "/view/viewer_index.shtml"},
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    return realm:find("AXIS")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = ""},
    {username = "root", password = ""},
    {username = "root", password = "root"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Hikvision DS-XXX Network Camera",
  category = "security",
  paths = {
    {path = "/PSIA/Custom/SelfExt/userCheck"},
  },
  target_check = function (host, port, path, response)
    return response.header["server"] == "App-webs/"
 
  end,
  login_combos = {
    {username = "admin", password = "12345"},
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "NUOO DVR",
  category = "security",
  paths = {
    {path = "/"},
  },
  target_check = function (host, port, path, response)
    return response.header['server'] and response.header["server"]:find("lighttpd") 
      and response.body and response.body:lower():find("<title>network video recorder login</title>")
  end,
  login_combos = {
    {username = "admin", password = "admin"},
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "login.php"), nil,
                                 {language="en", user=user, pass=pass,submit="Login"})
    if resp.status == 302 and not(resp.body:find("loginfail")) then return true end
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
           and (response.header["server"] or ""):find("^Schneider%-WEB/V%d+%.")
           and (response.header["location"] or ""):find("/index%.htm$")
  end,
  login_combos = {
    {username = "USER", password = "USER"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port,
                               url.absolute(path, "secure/system/globaldata.htm?Language=English"),
                               user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 06.05.00/6.0.1 on QD2040 HW 675
  name = "TCS Basys Controls Communication Center",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Private"
           and (response.header["server"] or ""):find("^lighttpd/%d+%.")
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 01.01
  name = "Riello UPS NetMan 204",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^mini_httpd/%d+%.")
           and response.body
           and response.body:lower():find("<title>netman 204 login</title>", 1, true)
  end,
  login_combos = {
    {username = "admin",     password = "admin"},
    {username = "fwupgrade", password = "fwupgrade"},
    {username = "user",      password = "user"},
    {username = "eurek",     password = "eurek"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port,
                                 url.absolute(path, "cgi-bin/login.cgi"),
                                 nil, {username=user, password=pass})
    return resp.status == 200
           and resp.body
           and (resp.body:find(">window.location.replace(", 1, true)
             or resp.body:find("Another user is logged in", 1, true))
  end
})

table.insert(fingerprints, {
  -- Version 3.2.5 on AP9606, 2.5.0, 2.6.4 on AP9617, AP9619, 1.1.6 on AP7900
  name = "APC Management Card (basic auth)",
  category = "industrial",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "APC Management Card"
  end,
  login_combos = {
    {username = "apc", password = "apc"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
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
           and (response.header["server"] or ""):find("^Web%-Server/%d+%.")
           and response.body
           and response.body:find("/websys/webArch/mainFrame.cgi", 1, true)
  end,
  login_combos = {
    {username = "admin",      password = ""},
    {username = "supervisor", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    -- determine proper login path by locale
    local resp0 = http.get(host, port, path)
    if resp0.status ~= 200 then return false end
    local lurl = (resp0.body or ""):match('location%.href="(/[^"]+/)mainFrame%.cgi"')
    if not lurl then return false end
    -- harvest the login form token
    local resp1 = http_get_simple(host, port, url.absolute(lurl, "authForm.cgi"),
                                 {cookies="cookieOnOffChecker=on"})
    if resp1.status ~= 200 then return false end
    local token = (resp1.body or ""):match('<input%s+type%s*=%s*"hidden"%s+name%s*=%s*"wimToken"%s+value%s*=%s*"(.-)"')
    if not token then return false end
    -- build the login form and submit it
    local form = {wimToken = token,
                  userid_work = "",
                  userid = base64.enc(user),
                  password_work = "",
                  password = base64.enc(pass),
                  open = ""}
    local resp2 = http_post_simple(host, port, url.absolute(lurl, "login.cgi"),
                                  {cookies=resp1.cookies}, form)
    return resp2.status == 302
           and (resp2.header["location"] or ""):find("/mainFrame%.cgi$")
           and sets_cookie(resp2, "wimsesid", "^%d+$")
  end
})

table.insert(fingerprints, {
  -- Version 071.*, 072.* on WorkCentre 7835, 7845, ColorQube 8900X
  name = "Xerox WorkCentre/ColorQube",
  cpe = "cpe:/h:xerox:workcentre",
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
                  NextPage=url.absolute(path, "properties/authentication/luidLogin.php"),
                  webUsername=user,
                  webPassword=pass,
                  frmaltDomain="default"}
    return try_http_post_login(host, port, path, "userpost/xerox.set",
                              "/login%.php%?invalid=t", form)
  end
})

table.insert(fingerprints, {
  -- Version 1.1, 1.1 SP7
  name = "EFI Fiery Webtools",
  category = "printer",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["content-location"] or ""):find("^redirect%.html%.")
           and response.body
           and response.body:lower():find('content="0;url=wt2parser.cgi?home_', 1, true)
  end,
  login_combos = {
    {username = "Administrator", password = ""},
    {username = "Administrator", password = "Fiery.1"}
  },
  login_check = function (host, port, path, user, pass)
    -- sessionId normally includes the client IP, not the target,
    -- but this would be too revealing
    local sessionid = host.ip
                      .. "_"
                      .. math.floor(stdnse.clock_ms())
                      .. math.random(100000, 999999)
    local encpass = xmlencode(pass)
    local header = {["Content-Type"]="text/xml", ["SOAPAction"]='""'}
    local soapmsg = [[
      <?xml version='1.0' encoding='UTF-8'?>
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <SOAP-ENV:Body>
          <ns1:doLogin xmlns:ns1="urn:FierySoapService" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <sessionId xsi:type="xsd:string">__SESS__</sessionId>
            <in xsi:type="ns1:Login">
              <fieldsMask xsi:type="xsd:int">0</fieldsMask>
              <password xsi:type="xsd:string">__PASS__</password>
              <timeout xsi:type="xsd:int">30</timeout>
              <userName xsi:type="xsd:string" xsi:nil="true"/>
            </in>
          </ns1:doLogin>
        </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
      ]]
    -- strip off indentation
    soapmsg = soapmsg:gsub("%f[^\0\n]%s+", "")
    -- username is not injected into the payload because it is implied
    soapmsg = soapmsg:gsub("__%w+__", {__SESS__=sessionid, __PASS__=encpass})
    local resp = http_post_simple(host, port, url.absolute(path, "soap"),
                                 {header=header}, soapmsg)
    return resp.status == 200
           and (resp.body or ""):find('<result xsi:type="xsd:boolean">true</result>', 1, true)
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
           and (response.header["server"] or ""):find("^Gordian Embedded")
           and response.body
           and response.body:lower():find("<title>lantronix thinweb manager", 1, true)
  end,
  login_combos = {
    {username = "", password = "system"}
  },
  login_check = function (host, port, path, user, pass)
    local lurl = url.absolute(path, "server_eps.html")
    -- obtain login nonce
    local resp1 = http_get_simple(host, port, lurl)
    local nonce = resp1.status == 403 and sets_cookie(resp1, "SrvrNonce", ".")
    if not nonce then return false end
    -- credential is the MD5 hash of the nonce and the password (in upper case)
    local creds = stdnse.tohex(openssl.md5(nonce .. ":" .. pass:upper()))
    local cookies = ("SrvrNonce=%s; SrvrCreds=%s"):format(nonce, creds)
    local resp2 = http_get_simple(host, port, lurl, {cookies=cookies})
    return resp2.status == 200
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
           and response.header["command-status"]:find("^0 %({%s*systemName:.*,%s*controller:.*}%)")
  end,
  login_combos = {
    {username = "monitor", password = "!monitor"},
    {username = "manage",  password = "!manage"},
    {username = "admin",   password = "!admin"}
  },
  login_check = function (host, port, path, user, pass)
    local creds = stdnse.tohex(openssl.md5(user .. "_" .. pass))
    local header = {["Content-Type"] = "application/x-www-form-urlencoded",
                    ["datatype"] = "json"}
    local resp = http_post_simple(host, port, url.absolute(path, "../"),
                                 {header=header}, "/api/login/" .. creds)
    return resp.status == 200
           and (resp.header["command-status"] or ""):find("^1 ")
  end
})

table.insert(fingerprints, {
  -- Version 7.5.0.3 on 2072-24C
  name = "IBM Storwize V3700",
  cpe = "cpe:/a:ibm:storwize_v3700_software",
  category = "storage",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("V3700", 1, true)
           and response.body:lower():find("<title>[^<]-%sibm storwize v3700%s*</title>")
  end,
  login_combos = {
    {username = "superuser", password = "passw0rd"}
  },
  login_check = function (host, port, path, user, pass)
    local form = {login=user,
                 password=pass,
                 newPassword="",
                 confirmPassword="",
                 tzoffset="0", -- present twice in the original form
                 nextURL="",   -- present twice in the original form
                 licAccept=""}
    local resp = http_post_simple(host, port, url.absolute(path, "login"),
                                 nil, form)
    return resp.status == 302
           and (resp.header["location"] or ""):find("/gui$")
  end
})

---
--Virtualization systems
---
table.insert(fingerprints, {
  -- Version 5.0.0
  name = "VMware ESXi",
  cpe = "cpe:/o:vmware:esxi",
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
    return try_http_basic_login(host, port,
                               url.absolute(path, "folder?dcPath=ha-datacenter"),
                               user, pass, false)
  end
})

table.insert(fingerprints, {
  -- Version 4.0.0
  name = "PCoIP Zero Client",
  cpe = "cpe:/a:teradici:pcoip_host_software",
  category = "virtualization",
  paths = {
    {path = "/login.html"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("PCoIP&#174 Zero Client", 1, true)
           and response.body:find("password_value", 1, true)
  end,
  login_combos = {
    {username = "", password = "Administrator"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "cgi-bin/login"),
                                 nil, {password_value=pass, idle_timeout=60})
    -- successful login is a 302-redirect that sets a session cookie with hex
    -- value; failed login is the same but the cookie contains an error message
    return resp.status == 302 and sets_cookie(resp, "session_id", "^%x+$")
  end
})

---
--Remote consoles
---
table.insert(fingerprints, {
  -- Version 5.5, 6.1, 6.2, 7.2 on SLC16, SLC32, SLC48, SLC 8016
  name = "Lantronix SLC",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and (response.header["server"] or ""):find("^mini_httpd/%d+%.")
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
  --Version 1.10.12, 1.80
  name = "Dell iDRAC6",
  cpe = "cpe:/o:dell:idrac6_firmware",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 301
           and (response.header["server"] or ""):find("^Mbedthis%-Appweb/%d+%.")
           and (response.header["location"] or ""):find("/start%.html$")
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

table.insert(fingerprints, {
  name = "Dell iDRAC9",
  cpe = "cpe:/o:dell:idrac9_firmware",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    -- analyze response for 1st request to "/"
    if not (response.status == 302 and (response.header["location"] or ""):find("/restgui/start%.html$")) then return false end

    -- check with 2nd request to "/restgui/start.html" to be sure
    local resp = http_get_simple(host, port, url.absolute(path, "restgui/start.html"))  
    return resp.status == 200
           and resp.body
           and resp.body:find("idrac-start-screen", 1, true)
  end,
  login_combos = {
    {username = "root", password = "calvin"}
  },
  login_check = function (host, port, path, user, pass)
    local headers = {
                      ["user"]='"'..user..'"',
                      ["password"]='"'..pass..'"'
                    }
    local resp = http_post_simple(host, port, url.absolute(path, "sysmgmt/2015/bmc/session"),
                                 {header=headers})
    local body = resp.body or ""

    return (resp.status == 201 and (
                body:find('"authResult":0') -- standard login success
                or body:find('"authResult":7') -- login success with default credentials
                or body:find('"authResult":9') -- login success with password reset required
              )
            )
  end
})

table.insert(fingerprints, {
  --Version 1.1 on Supermicro X7SB3
  name = "Supermicro WPCM450",
  category = "console",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.body
           and response.body:find("ATEN International", 1, true)
           and response.body:find("/cgi/login.cgi", 1, true)
  end,
  login_combos = {
    {username = "ADMIN", password = "ADMIN"}
  },
  login_check = function (host, port, path, user, pass)
    local resp = http_post_simple(host, port, url.absolute(path, "cgi/login.cgi"),
                                 nil, {name=user, pwd=pass})
    return resp.status == 200
           and (resp.body or ""):find("../cgi/url_redirect.cgi?url_name=mainmenu", 1, true)
  end
})
