local base64 = require "base64"
local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password guessing against HTTP proxy servers.
]]

---
-- @usage
-- nmap --script http-proxy-brute -p 8080 <host>
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-proxy-brute:
-- |   Accounts
-- |     patrik:12345 - Valid credentials
-- |   Statistics
-- |_    Performed 6 guesses in 2 seconds, average tps: 3
--
-- @args http-proxy-brute.url sets an alternative URL to use when brute forcing
--       (default: http://scanme.insecure.org)
-- @args http-proxy-brute.method changes the HTTP method to use when performing
--       brute force guessing (default: HEAD)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- maybe the script does not need to be in the external category
-- as most request should not "leave" the proxy.
categories = {"brute", "intrusive", "external"}


portrule = shortport.port_or_service({8123,3128,8000,8080},{'polipo','squid-http','http-proxy'})

local arg_url = stdnse.get_script_args(SCRIPT_NAME .. '.url') or 'http://scanme.nmap.org/'
local arg_method = stdnse.get_script_args(SCRIPT_NAME .. '.method') or "HEAD"

Driver = {

  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function( self )
    return true
  end,

  login = function( self, username, password )

    -- the http library does not yet support proxy authentication, so let's
    -- do what's necessary here.
    local header = { ["Proxy-Authorization"] = "Basic " .. base64.enc(username .. ":" .. password) }
    local response = http.generic_request(self.host, self.port, arg_method, arg_url, { header = header, bypass_cache = true } )

    -- if we didn't get a 407 error, assume the credentials
    -- were correct. we should probably do some more checks here
    if ( response.status ~= 407 ) then
      return true, creds.Account:new( username, password, creds.State.VALID)
    end

    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    return true
  end,
}

-- checks whether the proxy really needs authentication and that the
-- authentication mechanism can be handled by our script, currently only
-- BASIC authentication is supported.
local function checkProxy(host, port, url)
  local response = http.generic_request(host, port, arg_method, url, { bypass_cache = true })

  if ( response.status ~= 407 ) then
    return false, "Proxy server did not require authentication"
  end

  local proxy_auth = response.header["proxy-authenticate"]
  if ( not(proxy_auth) ) then
    return false, "No proxy authentication header was found"
  end

  local challenges = http.parse_www_authenticate(proxy_auth)

  for _, challenge in ipairs(challenges) do
    if ( "Basic" == challenge.scheme ) then
      return true
    end
  end
  return false, "The authentication scheme wasn't supported"
end

action = function(host, port)

  local status, err = checkProxy(host, port, arg_url)
  if ( not(status) ) then
    return stdnse.format_output(false, err)
  end

  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  local result
  status, result = engine:start()

  return result
end
