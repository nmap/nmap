local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Examines cookies set by HTTP services.  Reports any session cookies set
without the httponly flag.  Reports any session cookies set over SSL without
the secure flag.  If http-enum.nse is also run, any interesting paths found
by it will be checked in addition to the root.
]]

---
-- @usage
-- nmap -p 443 --script http-cookie-flags <target>
--
-- @output
-- 443/tcp open  https
-- | http-cookie-flags:
-- |   /:
-- |     PHPSESSID:
-- |       secure flag not set and HTTPS in use
-- |   /admin/:
-- |     session_id:
-- |       secure flag not set and HTTPS in use
-- |       httponly flag not set
-- |   /mail/:
-- |     ASPSESSIONIDASDF:
-- |       httponly flag not set
-- |     ASP.NET_SessionId:
-- |_      secure flag not set and HTTPS in use
--
-- @args path Specific URL path to check for session cookie flags. Default: / and those found by http-enum.
-- @args cookie Specific cookie name to check flags on. Default: A variety of commonly used session cookie names and patterns.
--
-- @xmloutput
-- <table key="/">
-- <table key="PHPSESSID">
-- <elem>secure flag not set and HTTPS in use</elem>
-- </table>
-- </table>
-- <table key="/admin/">
-- <table key="session_id">
-- <elem>secure flag not set and HTTPS in use</elem>
-- <elem>httponly flag not set</elem>
-- </table>
-- </table>
-- <table key="/mail/">
-- <table key="ASPSESSIONIDASDF">
-- <elem>httponly flag not set</elem>
-- </table>
-- <table key="ASP.NET_SessionId">
-- <elem>secure flag not set and HTTPS in use</elem>
-- </table>
-- </table>
--
-- @see http-enum.nse
-- @see http-security-headers.nse

categories = { "default", "safe", "vuln" }
author = "Steve Benson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
dependencies = {"http-enum"}

portrule = shortport.http

-- a list of patterns indicating cookies which are likely session cookies
local session_cookie_patterns = {
  '^PHPSESSID$',
  '^CFID$',
  '^CFTOKEN$',
  '^VOXSQSESS$',
  '^CAKEPHP$',
  '^FedAuth$',
  '^ASPXAUTH$',
  '^session$',
  '[Ss][Ee][Ss][Ss][Ii][Oo][Nn][^%a]*[Ii][Dd]'
}

-- check cookies set on a particular URL path. returns a table with problem
-- cookie names mapped to a table listing each problem found.
local check_path = function(is_session_cookie, host, port, path)
  stdnse.debug1("start check of %s", path)
  local path_issues = stdnse.output_table()
  local resp = http.get(host, port, path)
  if not resp.status then
    stdnse.debug1("Error retrieving %s: %s", path, resp["status-line"])
    return nil
  end

  if not resp.cookies then
    stdnse.debug2("No cookies on %s", path)
    return nil
  end

  for _,cookie in ipairs(resp.cookies) do
    stdnse.debug2('  cookie: %s', cookie.name)
    local issues = stdnse.output_table()
    if is_session_cookie(cookie.name) then
      stdnse.debug2('    IS a session cookie')
      if port.service=='https' and not cookie.secure then
        stdnse.debug2('    * no secure flag and https')
        issues[#issues+1] = 'secure flag not set and HTTPS in use'
      end
      if not cookie.httponly then
        stdnse.debug2('    * no httponly')
        issues[#issues+1] = 'httponly flag not set'
      end
    end

    if #issues>0 then
      path_issues[cookie.name] = issues
    end

  end

  stdnse.debug1("end check of %s : %d issues found", path, #path_issues)
  if #path_issues>0 then
    return path_issues
  else
    return nil
  end
end

action = function(host, port)
  local all_issues = stdnse.output_table()
  local specified_path = stdnse.get_script_args(SCRIPT_NAME..".path")
  local specified_cookie = stdnse.get_script_args(SCRIPT_NAME..".cookie")

  -- create a function, is_session_cookie, which accepts a cookie name and
  -- returns true if it is likely a session cookie, based on script-args
  local is_session_cookie
  if specified_cookie == nil then
    is_session_cookie = function(cookie_name)
      for _, pattern in ipairs(session_cookie_patterns) do
        if string.find(cookie_name, pattern) then
          return true
        end
      end
      return false
    end
  else
    is_session_cookie = function(cookie_name)
      return cookie_name==specified_cookie
    end
  end

  -- build a list of URL paths to check cookies for based on script-args and
  -- http-enum results.
  local paths_to_check = {}
  if specified_path == nil then
    stdnse.debug2('path script-arg is nil; checking / and anything from http-enum')
    paths_to_check[#paths_to_check+1] = '/'
    for _,path in ipairs( stdnse.registry_get({host.ip, 'www', port.number, 'all_pages'}) or {}) do
      paths_to_check[#paths_to_check+1] = path
    end
  else
    stdnse.verbose1('path script-arg is %s; checking only that path', specified_path)
    paths_to_check[#paths_to_check+1] = specified_path
  end

  -- check desired cookies on all desired paths
  for _,path in ipairs(paths_to_check) do
    all_issues[path] = check_path(is_session_cookie, host, port, path)
  end

  if #all_issues>0 then
    return all_issues
  else
    return nil
  end

end
