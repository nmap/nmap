local nmap = require "nmap"
local http = require "http"
local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against Plone Web CMS installations.

This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are
stored using the credentials library.

Plone default uri and form names:
* Default uri:<code>/login_form</code>
* Default uservar: <code>__ac_name</code>
* Default passvar: <code>__ac_password</code>
]]

---
-- @usage
-- nmap -sV --script http-plone-brute
--   --script-args 'userdb=users.txt,passdb=passwds.txt,http-plone-brute.hostname=domain.com,
--                  http-plone-brute.threads=3,brute.firstonly=true' <target>
-- nmap -sV --script http-plone-brute <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-plone-brute:
-- |   Accounts
-- |     the0wl:WgHfTa35b => Login correct
-- |   Statistics
-- |_    Perfomed 259 guesses in 309 seconds, average tps: 0
--
-- @args http-plone-brute.uri Path to authentication script. Default: /login_form
-- @args http-plone-brute.hostname Virtual Hostname Header
-- @args http-plone-brute.uservar sets the http-variable name that holds the
--                                 username used to authenticate. Default: __ac_name
-- @args http-plone-brute.passvar sets the http-variable name that holds the
--                                 password used to authenticate. Default: __ac_password
-- @args http-plone-brute.threads sets the number of threads. Default: 3
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

author = "J. Igor Melo <jigordev@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({80, 443},{"http", "https"}, "tcp")

local DEFAULT_PLONE_URI = "/login_form"
local DEFAULT_PLONE_USERVAR = "__ac_name"
local DEFAULT_PLONE_PASSVAR = "__ac_password"
local DEFAULT_THREAD_NUM = 3

local security_token

---
--This class implements the Brute library (https://nmap.org/nsedoc/lib/brute.html)
---
Driver = {
	new = function(self, host, port, options)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		o.host = stdnse.get_script_args(SCRIPT_NAME .. ".hostname") or host
		o.port = port
		o.uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or DEFAULT_PLONE_URI
		o.http_options = {no_cache = true}
		o.options = options
		return o
	end,

	connect = function(self)
		return true
	end,

	login = function(self, username, password)
		stdnse.debug2("HTTP POST %s%s", self.host, self.uri)
		local response = http.post(self.host, self.port, self.uri, self.http_options,
			nil, {[self.options.uservar] = username, [self.options.passvar] = password, _authenticator = security_token, came_from = ""})

		if response.body and not response.body:match("name=['\"]"..self.options.passvar) then
			stdnse.debug2("Response:\n%s", response.body)
			return true, creds.Account:new(username, password, creds.State.VALID)
		end
		return false, brute.Error:new("Incorrect password")
	end,

	disconnect = function(self)
		return true
	end,

	check = function(self)
		local response = http.get(self.host, self.port, self.uri)
		stdnse.debug1("HTTP GET %s%s", stdnse.get_hostname(self.host), self.uri)
		-- Check if password field is there
		if response.status == 200 and response.body:match("type=['\"]password['\"]") then
			stdnse.debug1("Initial check passed. Lauching brute force attack")
			if response.body then
				local _
				_, _, security_token = response.body:find("<input type=\"hidden\" name=\"_authenticator\" value=\"(%w+)\" />")
			end

			if security_token then
				stdnse.debug2("Security Token found: %s", security_token)
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

action = function(host, port)
	local status, result, engine
	local uservar = stdnse.get_script_args(SCRIPT_NAME .. ".uservar") or DEFAULT_PLONE_USERVAR
	local passvar = stdnse.get_script_args(SCRIPT_NAME .. ".passvar") or DEFAULT_PLONE_PASSVAR
	local thread_num = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".threads")) or DEFAULT_THREAD_NUM

	engine = brute.Engine:new(Driver, host, port, {uservar = uservar, passvar = passvar})
	engine:setMaxThreads(thread_num)
	engine.options.script_name = SCRIPT_NAME
	status, result = engine:start()

	return result
end
