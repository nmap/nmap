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

The script contains a small database of known web apps' form information. This
improves form detection and also allows for form mangling and custom success
detection functions. If the script arguments aren't expressive enough, users
are encouraged to edit the database to fit.

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
-- @args http-form-brute.sessioncookies Attempt to grab session cookies before
--       submitting the form. Setting this to "false" could speed up cracking
--       against forms that do not require any cookies to be set before logging
--       in. Default: true

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
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")


-- Miscellaneous script-wide constants
local max_rcount = 2    -- how many times a form submission can be redirected
local form_debug = 1    -- debug level for printing form components

--- Database of known web apps for form detection
--
local known_apps = {
  joomla = {
    match = {
      action = "/administrator/index.php",
    },
    uservar = "username",
    passvar = "passwd",
    -- http-joomla-brute just checks for name="passwd" to indicate failure,
    -- so default onfailure should work. TODO: get onsuccess for this app.
  },
  django = {
    match = {
      action = "/login/",
      id = "login-form"
    },
    uservar = "username",
    passvar = "password",
    onsuccess = "Set%-Cookie:%s*sessionid=",
  },
  mediawiki = {
    match = {
      action = "action=submitlogin"
    },
    uservar = "wpName",
    passvar = "wpPassword",
    onsuccess = "Set%-Cookie:[^\n]*%wUserID=%d",
  },
  wordpress = {
    match = {
      action = "wp%-login%.php$",
    },
    uservar = "log",
    passvar = "pwd",
    onsuccess = "Location:[^\n]*/wp%-admin/",
    mangle = function(form)
      for i, f in ipairs(form.fields) do
        if f.name and f.name == "testcookie" then
          table.remove(form.fields, i)
          break
        end
      end
    end,
    sessioncookies = false,
  },
  websphere = {
    match = {
      action = "/ibm/console/j_security_check"
    },
    uservar = "j_username",
    passvar = "j_password",
    onfailure = function(response)
      local body = response.body
      local rpath = response.header.location
      return response.status < 300 and body and not (
        (rpath and rpath:match('logonError%.jsp'))
        or (
          body:match('Unable to login%.') or
          body:match('Login failed%.') or
          body:match('Invalid User ID or password')
          )
        )
    end,
    sessioncookies = false,
  },
}

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

local function urlencode_form(fields, uservar, username, passvar, password)
  local parts = {}
  for _, field in ipairs(fields) do
    if field.name then
      local val = field.value or ""
      if field.name == uservar then
        val = username
      elseif field.name == passvar then
        val = password
      end
      parts[#parts+1] = url.escape(field.name) .. "=" .. url.escape(val)
    end
  end
  return table.concat(parts, "&")
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
-- @return cookies that were set by the request
local detect_form = function (host, port, path, hostname)
  local response = http.get(host, port, path, {
    bypass_cache = true,
    header = {Host = hostname}
  })
  if not (response and response.body and response.status == 200) then
    return nil, string.format("Unable to retrieve a login form from path %q", path)
  end

  for _, f in pairs(http.grab_forms(response.body)) do
    local form = http.parse_form(f)
    for app, val in pairs(known_apps) do
      local match = true
      -- first check the 'match' table and be sure all values match
      for k, v in pairs(val.match) do
        -- ensure that corresponding field exists in form table also
        match = match and form[k] and string.match(form[k], v)
      end
      -- then check that uservar and passvar are in this form
      if match then
        -- how many field names must match?
        match = 2 - (val.uservar and 1 or 0) - (val.passvar and 1 or 0)
        for _, field in pairs(form.fields) do
          if field.name and
            field.name == val.uservar or field.name == val.passvar then
            -- found one, decrement
            match = match - 1
          end
          -- Have we found them all?
          if match <= 0 then break end
        end
        if match <= 0 then
          stdnse.debug1("Detected %s login form.", app)
          -- copy uservar, passvar, etc. from the fingerprint
          for k, v in pairs(val) do
            form[k] = v
          end
          -- apply any special mangling
          if val.mangle then
            val.mangle(form)
          end
          return form, nil, response.cookies
        end
        -- failed to match uservar and passvar
      end
      -- failed to match form
    end
    -- No known apps match, try generic matching
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
      return form, nil, response.cookies
    end
  end

  return nil, string.format("Unable to detect a login form at path %q", path)
end

-- Recursively copy a table.
-- Only recurs when a value is a table, other values are copied by assignment.
local function tcopy (t)
  local tc = {};
  for k,v in pairs(t) do
    if type(v) == "table" then
      tc[k] = tcopy(v);
    else
      tc[k] = v;
    end
  end
  return tc;
end

-- TODO: expire cookies
local function update_cookies (old, new)
  for i, c in ipairs(new) do
    local add = true
    for j, oc in ipairs(old) do
      if oc.name == c.name then
        old[j] = c
        add = false
        break
      end
    end
    if add then
      table.insert(old, c)
    end
  end
end

-- make sure this path is ok as a form action.
-- Also make sure we stay on the same host.
local function path_ok (path, hostname, port)
  local pparts = url.parse(path)
  if pparts.authority then
    if pparts.userinfo
      or ( pparts.host ~= hostname )
      or ( pparts.port and tonumber(pparts.port) ~= port.number ) then
      return false
    end
  end
  return true
end

Driver = {

  new = function (self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    if not options.http_options then
      -- we need to supply the no_cache directive, or else the http library
      -- incorrectly tells us that the authentication was successful
      options.http_options = {
        no_cache = true,
        bypass_cache = true,
        redirect_ok = false,
        cookies = options.cookies,
        header = {
          -- nil just means not set, so default http.lua behavior
          Host = options.hostname,
          ["Content-Type"] = "application/x-www-form-urlencoded"
        }
      }
    end
    o.host = host
    o.port = port
    o.options = options
    -- each thread may store its params table here under its thread id
    options.threads = options.threads or {}
    return o
  end,

  connect = function (self)
    -- This will cause problems, as there is no way for us to "reserve"
    -- a socket. We may end up here early with a set of credentials
    -- which won't be guessed until the end, due to socket exhaustion.
    return true
  end,

  submit_form = function (self, username, password)
    local path = self.options.path
    local tid = stdnse.gettid()
    local thread = self.options.threads[tid]
    if not thread then
      thread = {
        -- copy of form fields so we don't clobber another thread's passvar
        params = tcopy(self.options.formfields),
        -- copy of options so we don't clobber another thread's cookies
        opts = tcopy(self.options.http_options),
      }
      self.options.threads[tid] = thread
    end
    if self.options.sessioncookies and not (thread.opts.cookies and next(thread.opts.cookies)) then
      -- grab new session cookies
      local form, errmsg, cookies = detect_form(self.host, self.port, path, self.options.hostname)
      if not form then
        stdnse.debug1("Failed to get new session cookies: %s", errmsg)
      else
        thread.opts.cookies = cookies
        thread.params = form.fields
      end
    end
    local params = thread.params
    local opts = thread.opts
    local response
    if self.options.method == "POST" then
      response = http.post(self.host, self.port, path, opts, nil,
      urlencode_form(params, self.options.uservar, username, self.options.passvar, password))
    else
      local uri = path
        .. (path:find("?", 1, true) and "&" or "?")
        .. urlencode_form(params, self.options.uservar, username, self.options.passvar, password)
      response = http.get(self.host, self.port, uri, opts)
    end
    local rcount = 0
    while response do
      if self.options.is_success and self.options.is_success(response) then
        -- "log out"
        opts.cookies = nil
        return response, true
      end
      -- set cookies
      update_cookies(opts.cookies, response.cookies)
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
      if path_ok(path, self.options.hostname, self.port) then
        -- clean up the url (cookie check fails if path contains hostname)
        -- this strips off the smallest prefix followed by a non-doubled /
        path = path:gsub("^.-%f[/](/%f[^/])","%1")
        response = http.get(self.host, self.port, path, opts)
      else
        -- being redirected off-host. Stop and assume failure.
        response = nil
      end
    end
    if response and self.options.is_failure then
      -- "log out" to avoid dumb login attempt limits
      opts.cookies = nil
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
  local hostname = stdnse.get_script_args('http-form-brute.hostname') or stdnse.get_hostname(host)
  local sessioncookies = stdnse.get_script_args('http-form-brute.sessioncookies')
  -- Originally intended more granular control with "always" or other strings
  -- to say when to grab new session cookies. For now, only boolean, though.
  if not sessioncookies then
    sessioncookies = true
  elseif sessioncookies == "false" then
    sessioncookies = false
  end

  local formfields = {}
  local cookies = {}
  if not passvar then
    local form, errmsg, dcookies = detect_form(host, port, path, hostname)
    if not form then
      return stdnse.format_output(false, errmsg)
    end
    path = form.action and url.absolute(path, form.action) or path
    method = method or form.method
    uservar = uservar or form.uservar
    passvar = passvar or form.passvar
    onsuccess = onsuccess or form.onsuccess
    onfailure = onfailure or form.onfailure
    formfields = form.fields or formfields
    cookies = dcookies or cookies
    sessioncookies = form.sessioncookies == nil and sessioncookies or form.sessioncookies
  end

  -- path should not change the origin
  if not path_ok(path, hostname, port) then
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
  local is_success = onsuccess and (
    type(onsuccess) == "function" and onsuccess
    or function (response)
      return http.response_contains(response, onsuccess, true)
    end
    )
  local is_failure = onfailure and (
    type(onfailure) == "function" and onfailure
    or function (response)
      return http.response_contains(response, onfailure, true)
    end
    )
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
                  is_failure = is_failure,
                  hostname = hostname,
                  formfields = formfields,
                  cookies = cookies,
                  sessioncookies = sessioncookies,
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
    return stdnse.format_output(false, "Failed to recognize failed authentication. See http-form-brute.onsuccess and http-form-brute.onfailure")
  end

  local engine = brute.Engine:new(Driver, host, port, options)
  -- there's a bug in http.lua that does not allow it to be called by
  -- multiple threads
  -- TODO: is this even true any more? We should fix it if not.
  engine:setMaxThreads(1)
  engine.options.script_name = SCRIPT_NAME
  engine.options:setOption("passonly", not uservar)

  local status, result = engine:start()
  return result
end
