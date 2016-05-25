local proxy = require "proxy"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description=[[
Checks if an HTTP proxy is open.

The script attempts to connect to www.google.com through the proxy and
checks for a valid HTTP response code. Valid HTTP response codes are
200, 301, and 302. If the target is an open proxy, this script causes
the target to retrieve a web page from www.google.com.
]]

---
-- @args proxy.url Url that will be requested to the proxy
-- @args proxy.pattern Pattern that will be searched inside the request results
--
-- @usage
-- nmap --script http-open-proxy.nse \
--      --script-args proxy.url=<url>,proxy.pattern=<pattern>
-- @output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- |  proxy-open-http: Potentially OPEN proxy.
-- |_ Methods successfully tested: GET HEAD CONNECT

-- Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar> / www.buanzo.com.ar / linux-consulting.buanzo.com.ar
-- Changelog: Added explode() function. Header-only matching now works.
--   * Fixed set_timeout
--   * Fixed some \r\n's
-- 2008-10-02 Vlatko Kosturjak <kost@linux.hr>
--   * Match case-insensitively against "^Server: gws" rather than
--     case-sensitively against "^Server: GWS/".
-- 2009-05-14 Joao Correa <joao@livewire.com.br>
--   * Included tests for HEAD and CONNECT methods
--   * Included url and pattern arguments
--   * Script now checks for http response status code, when url is used
--   * If google is used, script checks for Server: gws

author = "Arturo 'Buanzo' Busleiman"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "safe"}

--- Performs the custom test, with user's arguments
-- @param host The host table
-- @param port The port table
-- @param test_url The url te send the request
-- @param pattern The pattern to check for valid result
-- @return status if any request succeeded
-- @return response String with supported methods
function custom_test(host, port, test_url, pattern)
  local lstatus = false
  local response = {}
  -- if pattern is not used, result for test is code check result.
  -- otherwise it is pattern check result.

  -- strip hostname
  if not string.match(test_url, "^http://.*") then
    test_url = "http://" .. test_url
    stdnse.debug1("URL missing scheme. URL concatenated to http://")
  end
  local url_table = url.parse(test_url)
  local hostname = url_table.host

  local get_status = proxy.test_get(host, port, "http", test_url, hostname, pattern)
  local head_status = proxy.test_head(host, port, "http", test_url, hostname, pattern)
  local conn_status = proxy.test_connect(host, port, "http", hostname)
  if get_status then
    lstatus = true
    response[#response+1] = "GET"
  end
  if head_status then
    lstatus = true
    response[#response+1] = "HEAD"
  end
  if conn_status then
    lstatus = true
    response[#response+1] = "CONNECTION"
  end
  if lstatus then response = "Methods supported: " .. table.concat(response, " ") end
  return lstatus, response
end

--- Performs the default test
-- First: Default google request and checks for Server: gws
-- Seconde: Request to wikipedia.org and checks for wikimedia pattern
-- Third: Request to computerhistory.org and checks for museum pattern
--
-- If any of the requests is successful, the proxy is considered open
-- If all get requests return the same result, the user is alerted that
-- the proxy might be redirecting his requests (very common on wi-fi
-- connections at airports, cafes, etc.)
--
-- @param host The host table
-- @param port The port table
-- @return status if any request succeeded
-- @return response String with supported methods
function default_test(host, port)
  local fstatus = false
  local cstatus = false
  local get_status, head_status, conn_status
  local get_r1, get_r2, get_r3
  local get_cstatus, head_cstatus

  -- Start test n1 -> google.com
  -- making requests
  local test_url = "http://www.google.com"
  local hostname = "www.google.com"
  local pattern  = "^server: gws"
  get_status, get_r1, get_cstatus = proxy.test_get(host, port, "http", test_url, hostname, pattern)
  local _
  head_status, _, head_cstatus = proxy.test_head(host, port, "http", test_url, hostname, pattern)
  conn_status = proxy.test_connect(host, port, "http", hostname)

  -- checking results
  -- conn_status use a different flag (cstatus)
  -- because test_connection does not use patterns, so it is unable to detect
  -- cases where you receive a valid code, but the response does not match the
  -- pattern.
  -- if it was using the same flag, program could return without testing GET/HEAD
  -- once more before returning
  local response = {}
  if get_status then fstatus = true; response[#response+1] = "GET" end
  if head_status then fstatus = true; response[#response+1] = "HEAD" end
  if conn_status then cstatus = true; response[#response+1] = "CONNECTION" end

  -- if proxy is open, return it!
  if fstatus then return fstatus, "Methods supported: " .. table.concat(response, " ") end

  -- if we receive a invalid response, but with a valid
  -- response code, we should make a next attempt.
  -- if we do not receive any valid status code,
  -- there is no reason to keep testing... the proxy is probably not open
  if not (get_cstatus or head_cstatus or conn_status) then return false, nil end
  stdnse.debug1("Test 1 - Google Web Server\nReceived valid status codes, but pattern does not match")

  test_url = "http://www.wikipedia.org"
  hostname = "www.wikipedia.org"
  pattern  = "wikimedia"
  get_status, get_r2, get_cstatus = proxy.test_get(host, port, "http", test_url, hostname, pattern)
  head_status, _, head_cstatus = proxy.test_head(host, port, "http", test_url, hostname, pattern)
  conn_status = proxy.test_connect(host, port, "http", hostname)

  if get_status then fstatus = true; response[#response+1] = "GET" end
  if head_status then fstatus = true; response[#response+1] = "HEAD" end
  if conn_status then
    if not cstatus then response[#response+1] = "CONNECTION" end
    cstatus = true
  end

  if fstatus then return fstatus, "Methods supported: "  .. table.concat(response, " ") end

  -- same valid code checking as above
  if not (get_cstatus or head_cstatus or conn_status) then return false, nil end
  stdnse.debug1("Test 2 - Wikipedia.org\nReceived valid status codes, but pattern does not match")

  test_url = "http://www.computerhistory.org"
  hostname = "www.computerhistory.org"
  pattern  = "museum"
  get_status, get_r3, get_cstatus = proxy.test_get(host, port, "http", test_url, hostname, pattern)
  conn_status = proxy.test_connect(host, port, "http", hostname)

  if get_status then fstatus = true; response[#response+1] = "GET" end
  if conn_status then
    if not cstatus then response[#response+1] = "CONNECTION" end
    cstatus = true
  end

  if fstatus then return fstatus, "Methods supported:" .. table.concat(response, " ") end
  if not get_cstatus then
    stdnse.debug1("Test 3 - Computer History\nReceived valid status codes, but pattern does not match")
  end

  -- Check if GET is being redirected
  if proxy.redirectCheck(get_r1, get_r2) and proxy.redirectCheck(get_r2, get_r3) then
    return false, "Proxy might be redirecting requests"
  end

  -- Check if at least CONNECTION worked
  if cstatus then return true, "Methods supported:" .. table.concat(response, " ") end

  -- Nothing works...
  return false, nil
end

portrule = shortport.port_or_service({8123,3128,8000,8080},{'polipo','squid-http','http-proxy'})

action = function(host, port)
  local supported_methods = "\nMethods successfully tested: "
  local fstatus = false
  local def_test = true
  local test_url, pattern

  test_url, pattern = proxy.return_args()

  if(test_url) then def_test = false end
  if(pattern) then pattern = ".*" .. pattern .. ".*" end

  if def_test
    then fstatus, supported_methods = default_test(host, port)
    else fstatus, supported_methods = custom_test(host, port, test_url, pattern);
  end

  -- If any of the tests were OK, then the proxy is potentially open
  if fstatus then
    return "Potentially OPEN proxy.\n" .. supported_methods
  elseif not fstatus and supported_methods then
    return supported_methods
  end
  return

end
