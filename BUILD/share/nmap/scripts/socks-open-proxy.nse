local proxy = require "proxy"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description=[[
Checks if an open socks proxy is running on the target.

The script attempts to connect to a proxy server and send socks4 and
socks5 payloads. It is considered an open proxy if the script receives
a Request Granted response from the target port.

The payloads try to open a connection to www.google.com port 80.  A
different test host can be passed as <code>proxy.url</code>
argument.
]]
---
--@args proxy.url URL that will be requested to the proxy.
--@args proxy.pattern Pattern that will be searched inside the request results.
--@output
-- PORT     STATE  SERVICE
-- 1080/tcp open   socks
-- |  socks-open-proxy:
-- |   status: open
-- |   versions:
-- |     socks4
-- |_    socks5
--
--@xmloutput
--<elem key="status">open</elem>
--<table key="versions">
--  <elem>socks4</elem>
--  <elem>socks5</elem>
--</table>
--@usage
-- nmap --script=socks-open-proxy \
--    --script-args proxy.url=<host>,proxy.pattern=<pattern>

author = "Joao Correa"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "safe"}


--- Performs the custom test, with user's arguments
-- @param host The host table
-- @param port The port table
-- @param test_url The url to request
-- @param pattern The pattern to check for valid result
-- @return status If any request succeeded
-- @return response Table with supported methods
local function custom_test(host, port, test_url, pattern)
  local status4, status5, fstatus, cstatus4, cstatus5
  local get_r4, get_r5
  local methods
  local response = {}

  -- strip hostname
  if not string.match(test_url, "^http://.*") then
    test_url = "http://" .. test_url
    stdnse.debug1("URL missing scheme. URL concatenated to http://")
  end
  local url_table = url.parse(test_url)
  local hostname = url_table.host
  test_url = url_table.path

  -- make requests
  status4, get_r4, cstatus4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5, cstatus5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  fstatus = status4 or status5
  if(cstatus4) then response[#response+1]="socks4" end
  if(cstatus5) then response[#response+1]="socks5" end
  if(fstatus) then return fstatus, response end

  -- Nothing works...
  if not (cstatus4 or cstatus5) then
    return false, nil
  else
    return "pattern not matched", response
  end
end

--- Performs the default test
-- First: Default google request and checks for Server: gws
-- Second: Request to wikipedia.org and checks for wikimedia pattern
-- Third: Request to computerhistory.org and checks for museum pattern
--
-- If any of the requests is successful, the proxy is considered open.
-- If all requests return the same result, the user is alerted that
-- the proxy might be redirecting his requests (very common on wi-fi
-- connections at airports, cafes, etc.)
--
-- @param host The host table
-- @param port The port table
-- @return status If any request succeeded
-- @return response Table with supported methods
local function default_test(host, port)
  local status4, status5, fstatus
  local cstatus4, cstatus5
  local get_r4, get_r5
  local methods
  local response = {}

  local test_url = "/"
  local hostname = "www.google.com"
  local pattern = "^server: gws"
  status4, get_r4, cstatus4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5, cstatus5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  fstatus = status4 or status5
  if(cstatus4) then response[#response+1]="socks4" end
  if(cstatus5) then response[#response+1]="socks5" end
  if(fstatus) then return fstatus, response end

  -- if we receive a invalid response, but with a valid
  -- response code, we should make a next attempt.
  -- if we do not receive any valid status code,
  -- there is no reason to keep testing... the proxy is probably not open
  if not (cstatus4 or cstatus5) then return false, nil end
  stdnse.debug1("Test 1 - Google Web Server: Received valid status codes, but pattern does not match")

  test_url = "/"
  hostname = "www.wikipedia.org"
  pattern  = "wikimedia"
  status4, get_r4, cstatus4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5, cstatus5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  if(status4) then fstatus = true; response[#response+1]="socks4" end
  if(status5) then fstatus = true; response[#response+1]="socks5" end
  if(fstatus) then return fstatus, response end

  if not (cstatus4 or cstatus5) then return false, nil end
  stdnse.debug1("Test 2 - Wikipedia.org: Received valid status codes, but pattern does not match")

  local redir_check_get = get_r4 or get_r5

  test_url = "/"
  hostname = "www.computerhistory.org"
  pattern  = "museum"
  status4, get_r4, cstatus4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5, cstatus5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  if(status4) then fstatus = true; response[#response+1]="socks4" end
  if(status5) then fstatus = true; response[#response+1]="socks5" end
  if(fstatus) then return fstatus, response end

  if not (cstatus4 or cstatus5) then return false, nil end
  stdnse.debug1("Test 3 - Computer History: Received valid status codes, but pattern does not match")

  -- Check if GET is being redirected
  if proxy.redirectCheck(get_r4 or get_r5, redir_check_get) then
    return "redirecting", response
  end

  -- Protocol works, but nothing matches
  return "pattern not matched", response

end

portrule = shortport.port_or_service({1080, 9050},
  {"socks", "socks4", "socks5", "tor-socks"})

action = function(host, port)
  local supported_versions
  local fstatus = false
  local pattern, test_url
  local def_test = true
  local hostname
  local retval = stdnse.output_table()

  test_url, pattern = proxy.return_args()

  if(test_url) then def_test = false end
  if(pattern) then pattern = ".*" .. pattern .. ".*" end

  if def_test
    then fstatus, supported_versions = default_test(host, port)
    else fstatus, supported_versions = custom_test(host, port, test_url, pattern)
  end

  -- If any of the tests were OK, then the proxy is potentially open
  if fstatus == true then
    retval["status"] = "open"
    retval["versions"] = supported_versions
    return retval
  elseif fstatus and supported_versions then
    retval["status"] = fstatus
    retval["versions"] = supported_versions
    return retval
  end

end
