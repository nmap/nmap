local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
performs brute force password auditing against Drupal CMS.
This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are
stored using the credentials library.
Drupal default uri and form names:
* Default uri: <code>user</code>
* Default uservar: <code>name</code>
* Default passvar: <code>pass</code>
]]

---
-- @usage
-- nmap -sV --script http-drupal-brute <target>
-- nmap -sV --script http-drupal-brute
--   --script-args 'userdb=users.txt,passdb=passwds.txt,http-drupal-brute.hostname=domain.com,
--                  http-drupal-brute.threads=3,brute.firstonly=true' <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-drupal-brute: 
-- |   Accounts: 
-- |     admin:demo123 - Valid credentials
-- |_  Statistics: Performed 3 guesses in 1 seconds, average tps: 3
--
-- @args http-drupal-brute.uri points to 'user'. default /user
-- @args http-drupal-brute.hostname sets the host header in case of virtual
--       hosting
-- @args http-drupal-brute.uservar sets the http-variable name that holds the
--                                    username used to authenticate. Default: log
-- @args http-drupal-brute.passvar sets the http-variable name that holds the
--                                    password used to authenticate. Default: pwd
-- @args http-drupal-brute.threads sets the number of threads. Default: 3
--
-- Other useful arguments when using this script are:
-- * http.useragent = String - User Agent used in HTTP requests
-- * brute.firstonly = Boolean - Stop attack when the first credentials are found
-- * brute.mode = user/creds/pass - Username password iterator
-- * passdb = String - Path to password list
-- * userdb = String - Path to user list
--
-- Based on Paulino Calderon's http-wordpress-brute
--

author = "Nima Ghotbi <ghotbi.nima@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.http

local DEFAULT_DRUP_URI = "/user"
local DEFAULT_DRUP_USERVAR = "name"
local DEFAULT_DRUP_PASSVAR = "pass"
local DEFAULT_THREAD_NUM = 3

---
--This class implements the Driver class from the Brute library
---
Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.hostname = stdnse.get_script_args('http-drupal-brute.hostname')
    o.http_options = {
      no_cache = true,
      header = {
        -- nil just means not set, so default http.lua behavior
        Host = stdnse.get_script_args('http-drupal-brute.hostname')
      }
    }
    o.host = host
    o.port = port
    o.uri = stdnse.get_script_args('http-drupal-brute.uri') or DEFAULT_DRUP_URI
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
    local response = http.post( self.host, self.port, self.uri, self.http_options,
      nil, { [self.options.uservar] = username, [self.options.passvar] = password, ['form_id'] = 'user_login' } )
    -- This redirect is taking us to /?q=user/[0-9]+
    if response.status == 302 then
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
    -- Check if password field is there
    if ( response.status == 200 and response.body:match('type=[\'"]password[\'"]')) then
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
  local status, result, engine
  local uservar = stdnse.get_script_args('http-drupal-brute.uservar') or DEFAULT_DRUP_USERVAR
  local passvar = stdnse.get_script_args('http-drupal-brute.passvar') or DEFAULT_DRUP_PASSVAR
  local thread_num = stdnse.get_script_args("http-drupal-brute.threads") or DEFAULT_THREAD_NUM

  engine = brute.Engine:new( Driver, host, port, { uservar = uservar, passvar = passvar } )
  engine:setMaxThreads(thread_num)
  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()

  return result
end
