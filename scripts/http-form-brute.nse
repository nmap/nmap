local brute = require "brute"
local creds = require "creds"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Performs brute force password auditing against http form-based authentication.

This script uses the unpwdb and brute libraries to perform password
guessing. Any successful guesses are stored in the nmap registry, using
the creds library, for other scripts to use.

The script automatically attempts to discover the form method, action, and
field names to use in order to perform password guessing. (Use argument
path to specify the page where the form resides.) If it fails doing so
the form components can be supplied using arguments method, path, uservar,
and passvar. The same arguments can be used to selectively override
the detection outcome.

After attempting to authenticate using a HTTP GET or POST request the script
analyzes the response and attempts to determine whether authentication was
successful or not. The script analyzes this by checking the response using
the following rules:
   1. If the response was empty the authentication was successful.
   2. If the onsuccess argument was provided then the authentication either
      succeeded or failed depending on whether the response body contained
      the message/pattern passed in the onsuccess argument.
   3. If no onsuccess argument was passed, and if the onfailure argument
      was provided then the authentication either succeeded or failed
      depending on whether the response body does not contain
      the message/pattern passed in the onfailure argument.
   4. If neither the onsuccess nor onfailure argument was passed and the
      response contains a form field named the same as the submitted
      password parameter then the authentication failed.
   5. Authentication was successful.
]]

---
-- @usage
-- nmap --script http-form-brute -p 80 <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp   open  http    syn-ack
-- | http-brute:
-- |   Accounts
-- |     Patrik Karlsson:secret - Valid credentials
-- |   Statistics
-- |_    Perfomed 60023 guesses in 467 seconds, average tps: 138
--
-- @args http-form-brute.path identifies the page that contains the form
--       (default: "/"). The script analyses the content of this page to
--       determine the form destination, method, and fields. If argument
--       passvar is specified then the form detection is not performed and
--       the path argument is instead used as the form submission destination
--       (the form action). Use the other arguments to define the rest of
--       the form manually as necessary.
-- @args http-form-brute.method sets the HTTP method (default: "POST")
-- @args http-form-brute.hostname sets the host header in case of virtual
--       hosting
-- @args http-form-brute.uservar (optional) sets the form field name that
--       holds the username used to authenticate.
-- @args http-form-brute.passvar sets the http-variable name that holds the
--       password used to authenticate. If this argument is set then the form
--       detection is not performed. Use the other arguments to define
--       the form manually.
-- @args http-form-brute.onsuccess (optional) sets the message/pattern
--       to expect on successful authentication
-- @args http-form-brute.onfailure (optional) sets the message/pattern
--       to expect on unsuccessful authentication

--
-- Version 0.5
-- Created 07/30/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 05/23/2011 - v0.2 - changed so that uservar is optional
-- Revised 06/05/2011 - v0.3 - major re-write, added onsuccess, onfailure and
--                             support for redirects
-- Revised 08/12/2014 - v0.4 - added support for GET method
-- Revised 08/14/2014 - v0.5 - major revision
--                           - added support for submitting to a different URL
--                             than where the form resides
--                           - added detection of form action method
--                           - improved effectiveness of detection logic and
--                             patterns
--                           - added debug messages for inspection of detection
--                             results
--                           - added retry capability
--

author = "Patrik Karlsson, nnposter"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")


-- Miscellaneous script-wide constants
local max_rcount = 2    -- how many times a form submission can be redirected
local form_debug = 1    -- debug level for printing form components


---
-- Test whether a given string (presumably a HTML fragment) contains
-- a given form field
--
-- @param html The HTML string to analyze
-- @param fldname The field name to look for
-- @return Verdict (true or false)
local contains_form_field = function (html, fldname)
  for _, f in pairs(http.grab_forms(html)) do
    local form = http.parse_form(f)
    for _, fld in pairs(form.fields) do
      if fld.name == fldname then return true end
    end
  end
  return false
end


---
-- Detect a login form in a given HTML page
--
-- @param host HTTP host
-- @param port HTTP port
-- @param path Path for retrieving the page
-- @return Form object (see http.parse_form() for description)
--         or nil (if the operation failed)
-- @return Error string that describes any failure
local detect_form = function (host, port, path)
  local response = http.get(host, port, path)
  if not (response and response.body and response.status == 200) then
    return nil, string.format("Unable to retrieve a login form from path %q", path)
  end

  for _, f in pairs(http.grab_forms(response.body)) do
    local form = http.parse_form(f)
    local unfld, pnfld, ptfld
    for _, fld in pairs(form.fields) do
      if fld.name then
        local name = fld.name:lower()
        if not unfld and name:match("^user") then
          unfld = fld
        end
        if not pnfld and (name:match("^pass") or name:match("^key")) then
          pnfld = fld
        end
        if not ptfld and fld.type and fld.type == "password" then
          ptfld = fld
        end
      end
    end
    if pnfld or ptfld then
      form.method = form.method or "GET"
      form.uservar = (unfld or {}).name
      form.passvar = (ptfld or pnfld).name
      return form
    end
  end

  return nil, string.format("Unable to detect a login form at path %q", path)
end


Driver = {

  new = function (self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = nmap.registry.args['http-form-brute.hostname'] or host
    o.port = port
    o.options = options
    return o
  end,

  connect = function (self)
    -- This will cause problems, as there is no way for us to "reserve"
    -- a socket. We may end up here early with a set of credentials
    -- which won't be guessed until the end, due to socket exhaustion.
    return true
  end,

  submit_form = function (self, username, password)
    -- we need to supply the no_cache directive, or else the http library
    -- incorrectly tells us that the authentication was successful
    local path = self.options.path
    local opts = {no_cache = true, redirect_ok = false}
    local params = {[self.options.passvar] = password}
    if self.options.uservar then params[self.options.uservar] = username end
    local response
    if self.options.method == "POST" then
      response = http.post(self.host, self.port, path, opts, nil, params)
    else
      local uri = path
                  .. (path:find("?", 1, true) and "&" or "?")
                  .. url.build_query(params)
      response = http.get(self.host, self.port, uri, opts)
    end
    local rcount = 0
    while response do
      if self.options.is_success and self.options.is_success(response) then
        return response, true
      end
      if self.options.is_failure and self.options.is_failure(response) then
        return response, false
      end
      local status = tonumber(response.status) or 0
      local rpath = response.header.location
      if not (status > 300 and status < 400 and rpath and rcount < max_rcount) then
        break
      end
      rcount = rcount + 1
      path = url.absolute(path, rpath)
      response = http.get(self.host, self.port, path, opts)
    end
    -- Neither is_success nor is-failure condition applied. The login is deemed
    -- a success if the script is looking for a failure (which did not occur).
    return response, (response and self.options.is_failure)
  end,

  login = function (self, username, password)
    local response, success = self:submit_form(username, password)
    if not response then
      local err = brute.Error:new("Form submission failed")
      err:setRetry(true)
      return false, err
    end
    if not success then
      return false, brute.Error:new("Incorrect password")
    end
    return true, creds.Account:new(username, password, creds.State.VALID)
  end,

  disconnect = function (self)
    return true
  end,

  check = function (self)
    return true
  end,

}


action = function (host, port)
  local path = stdnse.get_script_args('http-form-brute.path') or "/"
  local method = stdnse.get_script_args('http-form-brute.method')
  local uservar = stdnse.get_script_args('http-form-brute.uservar')
  local passvar = stdnse.get_script_args('http-form-brute.passvar')
  local onsuccess = stdnse.get_script_args('http-form-brute.onsuccess')
  local onfailure = stdnse.get_script_args('http-form-brute.onfailure')

  if not passvar then
    local form, errmsg = detect_form(host, port, path)
    if not form then
      return stdnse.format_output(false, errmsg)
    end
    path = form.action and url.absolute(path, form.action) or path
    method = method or form.method
    uservar = uservar or form.uservar
    passvar = passvar or form.passvar
  end

  -- path should not change the origin
  local pparts = url.parse(path)
  if pparts.scheme or pparts.authority then
    return stdnse.format_output(false, string.format("Unusable form action %q", path))
  end
  stdnse.debug(form_debug, "Form submission path: " .. path)

  -- HTTP method POST is the default
  method = string.upper(method or "POST")
  if not (method == "GET" or method == "POST") then
    return stdnse.format_output(false, string.format("Invalid HTTP method %q", method))
  end
  stdnse.debug(form_debug, "HTTP method: " .. method)

  -- passvar must be specified or detected, uservar is optional
  if not passvar then
    return stdnse.format_output(false, "No passvar was specified or detected (see http-form-brute.passvar)")
  end
  stdnse.debug(form_debug, "Username field: " .. (uservar or "(not set)"))
  stdnse.debug(form_debug, "Password field: " .. passvar)

  if onsuccess and onfailure then
    return stdnse.format_output(false, "Either the onsuccess or onfailure argument should be passed, not both.")
  end

  -- convert onsuccess and onfailure to functions
  local is_success = onsuccess and function (response)
                                     return http.response_contains(response, onsuccess, true)
                                   end
  local is_failure = onfailure and function (response)
                                     return http.response_contains(response, onfailure, true)
                                   end
  -- the fallback test is to look for passvar field in the response
  if not (is_success or is_failure) then
    is_failure = function (response)
                   return response.body and contains_form_field(response.body, passvar)
                 end
  end

  local options = {
                  path = path,
                  method = method,
                  uservar = uservar,
                  passvar = passvar,
                  is_success = is_success,
                  is_failure = is_failure
                  }

  -- validate that the form submission behaves as expected
  local username = uservar and stdnse.generate_random_string(8)
  local password = stdnse.generate_random_string(8)
  local testdrv = Driver:new(host, port, options)
  local response, success = testdrv:submit_form(username, password)
  if not response then
    return stdnse.format_output(false, string.format("Failed to submit the form to path %q", path))
  end
  if success then
    return stdnse.format_output(false, string.format("Failed to recognize failed authentication. See http-form-brute.onsuccess and http-form-brute.onfailure"))
  end

  local engine = brute.Engine:new(Driver, host, port, options)
  -- there's a bug in http.lua that does not allow it to be called by
  -- multiple threads
  engine:setMaxThreads(1)
  engine.options.script_name = SCRIPT_NAME
  engine.options:setOption("passonly", not uservar)

  local status, result = engine:start()
  return result
end
