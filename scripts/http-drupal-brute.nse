local nmap = require "nmap"
local http = require "http"
local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against Drupal Web CMS installations.

This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are
stored using the credentials library.

Drupal default uri and form names:
* Default uri:<code>/user/login</code>
* Default uservar: <code>name</code>
* Default passvar: <code>pass</code>
]]

---
-- @usage
-- nmap -sV --script http-drupal-brute
--   --script-args 'userdb=users.txt,passdb=passwds.txt,http-drupal-brute.hostname=domain.com,
--                  http-drupal-brute.threads=3,brute.firstonly=true' <target>
-- nmap -sV --script http-drupal-brute <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-drupal-brute:
-- |   Accounts
-- |     the0wl:ftW3c0acD => Login correct
-- |   Statistics
-- |_    Perfomed 133 guesses in 241 seconds, average tps: 2
--
-- @args http-drupal-brute.uri Path to authentication script. Default: /user/login/
-- @args http-drupal-brute.hostname Virtual Hostname Header
-- @args http-drupal-brute.uservar sets the http-variable name that holds the
--                                 username used to authenticate. Default: name
-- @args http-drupal-brute.passvar sets the http-variable name that holds the
--                                 password used to authenticate. Default: pass
-- @args http-drupal-brute.threads sets the number of threads. Default: 3
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

local DEFAULT_DRUPAL_URI = "/user/login/"
local DEFAULT_DRUPAL_USERVAR = "name"
local DEFAULT_DRUPAL_PASSVAR = "pass"
local DEFAULT_THREAD_NUM = 3

local form_id

Driver = {
	new = function(self, host, port, options)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		o.host = stdnse.get_script_args(SCRIPT_NAME .. ".hostname") or host
		o.port = port
		o.uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or DEFAULT_DRUPAL_URI
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
			nil, {[self.options.uservar] = username, [self.options.passvar] = password, form_id = form_id, op = "Log in"})

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
		-- check if password field is there
		if response.status == 200 and response.body:match("type=['\"]password['\"]") then
			stdnse.debug1("Initial check passed. Lauching brute force attack")
			if response.body then
				local _
				_, _, form_id = response.body:find("name=\"form_id\" value=\"(%w+)\"")
			end

			if form_id then
				stdnse.debug2("Form ID value found: %s", form_id)
			else
				stdnse.debug2("Could not find form id")
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
	local uservar = stdnse.get_script_args(SCRIPT_NAME .. ".uservar") or DEFAULT_DRUPAL_USERVAR
	local passvar = stdnse.get_script_args(SCRIPT_NAME .. ".passvar") or DEFAULT_DRUPAL_PASSVAR
	local thread_num = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".threads")) or DEFAULT_THREAD_NUM

	engine = brute.Engine:new(Driver, host, port, {uservar = uservar, passvar = passvar})
	engine:setMaxThreads(thread_num)
	engine.options.script_name = SCRIPT_NAME
	status, result = engine:start()

	return result
end
