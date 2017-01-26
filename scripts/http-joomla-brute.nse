local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Performs brute force password auditing against Joomla web CMS installations.

This script initially reads the session cookie and parses the security token to perfom the brute force password auditing.
It uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are stored using the
credentials library.

Joomla's default uri and form names:
* Default uri:<code>/administrator/index.php</code>
* Default uservar: <code>username</code>
* Default passvar: <code>passwd</code>
]]

---
-- @usage
-- nmap -sV --script http-joomla-brute
--   --script-args 'userdb=users.txt,passdb=passwds.txt,http-joomla-brute.hostname=domain.com,
--                  http-joomla-brute.threads=3,brute.firstonly=true' <target>
-- nmap -sV --script http-joomla-brute <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-joomla-brute:
-- |   Accounts
-- |     xdeadbee:i79eWBj07g => Login correct
-- |   Statistics
-- |_    Perfomed 499 guesses in 301 seconds, average tps: 0
--
-- @args http-joomla-brute.uri Path to authentication script. Default: /administrator/index.php
-- @args http-joomla-brute.hostname Virtual Hostname Header
-- @args http-joomla-brute.uservar sets the http-variable name that holds the
--                                 username used to authenticate. Default: username
-- @args http-joomla-brute.passvar sets the http-variable name that holds the
--                                 password used to authenticate. Default: passwd
-- @args http-joomla-brute.threads sets the number of threads. Default: 3
--
-- Other useful arguments when using this script are:
-- * http.useragent = String - User Agent used in HTTP requests
-- * brute.firstonly = Boolean - Stop attack when the first credentials are found
-- * brute.mode = user/creds/pass - Username password iterator
-- * passdb = String - Path to password list
-- * userdb = String - Path to user list
--
--
-- @see http-form-brute.nse

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.http

local DEFAULT_JOOMLA_LOGIN_URI = "/administrator/index.php"
local DEFAULT_JOOMLA_USERVAR = "username"
local DEFAULT_JOOMLA_PASSVAR = "passwd"
local DEFAULT_THREAD_NUM = 3

local security_token
local session_cookie_str

---
--This class implements the Brute library (https://nmap.org/nsedoc/lib/brute.html)
---
Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = stdnse.get_script_args('http-joomla-brute.hostname') or host
    o.port = port
    o.uri = stdnse.get_script_args('http-joomla-brute.uri') or DEFAULT_JOOMLA_LOGIN_URI
    o.options = options
    return o
  end,

  connect = function( self )
    return true
  end,

  login = function( self, username, password )
    stdnse.debug2("HTTP POST %s%s with security token %s\n", self.host, self.uri, security_token)
    local response = http.post( self.host, self.port, self.uri, { cookies = session_cookie_str, no_cache = true, no_cache_body = true }, nil,
      { [self.options.uservar] = username, [self.options.passvar] = password,
      [security_token] = 1, lang = "", option = "com_login", task = "login" } )

    if response.body and not( response.body:match('name=[\'"]*'..self.options.passvar ) ) then
      stdnse.debug2("Response:\n%s", response.body)
      return true, creds.Account:new( username, password, creds.State.VALID)
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    return true
  end,

  check = function( self )
    local response = http.get( self.host, self.port, self.uri )
    stdnse.debug1("HTTP GET %s%s", stdnse.get_hostname(self.host),self.uri)
    -- Check if password field is there
    if ( response.status == 200 and response.body:match('type=[\'"]password[\'"]')) then
      stdnse.debug1("Initial check passed. Launching brute force attack")
      session_cookie_str = response.cookies[1]["name"].."="..response.cookies[1]["value"];
      if response.body then
        local _
        _, _, security_token = string.find(response.body, '<input type="hidden" name="(%w+)" value="1" />')
      end
      if security_token then
        stdnse.debug2("Security Token found:%s", security_token)
      else
        stdnse.debug2("The security token was not found.")
        return false
      end

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
  local status, result, engine
  local uservar = stdnse.get_script_args('http-joomla-brute.uservar') or DEFAULT_JOOMLA_USERVAR
  local passvar = stdnse.get_script_args('http-joomla-brute.passvar') or DEFAULT_JOOMLA_PASSVAR
  local thread_num = tonumber(stdnse.get_script_args("http-joomla-brute.threads")) or DEFAULT_THREAD_NUM

  engine = brute.Engine:new( Driver, host, port, { uservar = uservar, passvar = passvar } )
  engine:setMaxThreads(thread_num)
  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()

  return result
end
