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
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT     STATE  SERVICE
-- 1080/tcp open   socks
-- |  proxy-open-socks: Potentially OPEN proxy.
-- |_ Versions succesfully tested: Socks4 Socks5
--@usage
-- nmap --script=socks-open-proxy \
--		--script-args proxy.url=<host>,proxy.pattern=<pattern>

author = "Joao Correa"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "safe"}

require "shortport"
require "stdnse"
require "url"
require "proxy"

--- Performs the custom test, with user's arguments 
-- @param host The host table
-- @param port The port table
-- @param test_url The url te send the request
-- @param pattern The pattern to check for valid result
-- @return status (if any request was succeded
-- @return response String with supported methods
local function custom_test(host, port, test_url, pattern)
  local status4, status5, fstatus
  local get_r4, get_r5
  local methods
  local response = "Versions succesfully tested:"

  -- strip hostname
  if not string.match(test_url, "^http://.*") then 
    test_url = "http://" .. test_url
    stdnse.print_debug("URL missing scheme. URL concatenated to http://")
  end
  local url_table = url.parse(test_url)
  local hostname = url_table.host

  -- make requests
  status4, get_r4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  if(status4) then fstatus = true; response = response .. " Socks4" end
  if(status5) then fstatus = true; response = response .. " Socks5" end
  if(fstatus) then return fstatus, response end	
end

--- Performs the default test
-- First: Default google request and checks for Server: gws
-- Seconde: Request to wikipedia.org and checks for wikimedia pattern
-- Third: Request to computerhistory.org and checks for museum pattern
--
-- If any of the requests is succesful, the proxy is considered open
-- If all requests return the same result, the user is alerted that
-- the proxy might be redirecting his requests (very common on wi-fi
-- connections at airports, cafes, etc.)
--
-- @param host The host table
-- @param port The port table
-- @return status (if any request was succeded
-- @return response String with supported methods
local function default_test(host, port)
  local status4, status5, fstatus
  local cstatus4, cstatus5
  local get_r4, get_r5
  local methods
  local response = "Versions succesfully tested:"
	
  local test_url = "http://www.google.com"
  local hostname = "www.google.com"
  local pattern = "^server: gws"
  status4, get_r4, cstatus4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5, cstatus5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  if(status4) then fstatus = true; response = response .. " Socks4" end
  if(status5) then fstatus = true; response = response .. " Socks5" end
  if(fstatus) then return fstatus, response end

  -- if we receive a invalid response, but with a valid 
  -- response code, we should make a next attempt.
  -- if we do not receive any valid status code,
  -- there is no reason to keep testing... the proxy is probably not open
  if not (cstatus4 or cstatus5) then return false, nil end
  stdnse.print_debug("Test 1 - Google Web Server: Received valid status codes, but pattern does not match")
	
  test_url = "http://www.wikipedia.org"
  hostname = "www.wikipedia.org"
  pattern  = "wikimedia"
  status4, get_r4, cstatus4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5, cstatus5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  if(status4) then fstatus = true; response = response .. " Socks4" end
  if(status5) then fstatus = true; response = response .. " Socks5" end
  if(fstatus) then return fstatus, response end

  if not (cstatus4 or cstatus5) then return false, nil end
  stdnse.print_debug("Test 2 - Wikipedia.org: Received valid status codes, but pattern does not match")

  test_url = "http://www.computerhistory.org"
  hostname = "www.computerhistory.org"
  pattern  = "museum"
  status4, get_r4, cstatus4 = proxy.test_get(host, port, "socks4", test_url, hostname, pattern)
  status5, get_r5, cstatus5 = proxy.test_get(host, port, "socks5", test_url, hostname, pattern)

  if(status4) then fstatus = true; response = response .. " Socks4" end
  if(status5) then fstatus = true; response = response .. " Socks5" end
  if(fstatus) then return fstatus, response end

  if not (cstatus4 or cstatus5) then return false, nil end
  stdnse.print_debug("Test 3 - Computer History: Received valid status codes, but pattern does not match")

  -- Check if GET is being redirected
  if proxy.redirectCheck(get_r4, get_r5) then
    return false, "Proxy might be redirecting requests"
  end

  -- Nothing works...
  return false, nil

end

portrule = shortport.port_or_service({1080},{"socks","socks4","socks5"})

action = function(host, port)
  local supported_versions = "\nVersions succesfully tested: "
  local fstatus = false
  local pattern, test_url
  local def_test = true
  local hostname
  local retval

  test_url, pattern = proxy.return_args()

  if(test_url) then def_test = false end
  if(pattern) then pattern = ".*" .. pattern .. ".*" end

  if def_test
    then fstatus, supported_versions = default_test(host, port)
    else fstatus, supported_versions = custom_test(host, port, test_url, pattern)
  end

  -- If any of the tests were OK, then the proxy is potentially open
  if fstatus then
    retval = "Potentially OPEN proxy.\n" .. supported_versions
    return retval
  elseif not fstatus and supported_versions then
    return supported_versions
  end
  return

end
