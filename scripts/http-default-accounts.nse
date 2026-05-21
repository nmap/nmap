local _G = require "_G"
local creds = require "creds"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Tests for access with default credentials used by a variety of web applications
and devices. It detects applications by matching web responses of known paths
and launching a login routine using default credentials when found.

This script depends on a fingerprint file containing the target's information:
name, category, location paths, default credentials, and detection and login
logic routines.

You may select a category if you wish to reduce the number of requests.
We have categories like:
* <code>web</code> - Web applications
* <code>routers</code> - Routers
* <code>security</code> - CCTVs and other security devices
* <code>industrial</code> - Industrial systems
* <code>printer</code> - Network-attached printers and printer servers
* <code>storage</code> - Storage devices
* <code>virtualization</code> - Virtualization systems
* <code>console</code> - Remote consoles

You can also select a specific fingerprint or a brand, such as BIG-IQ or
Siemens. This matching is based on case-insensitive words in the fingerprint
name. This means that "nas" will select fingerprint "Seagate BlackArmor NAS",
but not "Netgear ReadyNAS".

For a fingerprint to be used, it needs to satisfy both the category and name
criteria.

By default, the script produces output only when default credentials are found,
while staying silent when the target only matches some fingerprints (but no
credentials are found). With increased verbosity (option -v), the script will
also report all matching fingerprints.

Please help improve this script by adding new entries to
nselib/data/http-default-accounts-fingerprints.lua

Remember each fingerprint must have:
* <code>name</code> - Descriptive name
* <code>category</code> - Category
* <code>login_combos</code> - Table of login combinations
* <code>paths</code> - Table containing possible path locations of the target
* <code>login_check</code> - Login function of the target

In addition, a fingerprint should have:
* <code>target_check</code> - Target validation function. If defined, it will
  be called to validate the target before attempting any logins.
* <code>cpe</code> - Official CPE Dictionary entry (see https://nvd.nist.gov/cpe.cfm)

Default fingerprint file: /nselib/data/http-default-accounts-fingerprints.lua
This script was based on http-enum.
]]

---
-- @usage
-- nmap -p80 --script http-default-accounts host/ip
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-default-accounts:
-- |   [Cacti] at /
-- |     admin:admin
-- |   [Nagios] at /nagios/
-- |_    nagiosadmin:CactiEZ
--
-- @xmloutput
-- <table key="Cacti">
--   <elem key="cpe">cpe:/a:cacti:cacti</elem>
--   <elem key="path">/</elem>
--   <table key="credentials">
--     <table>
--       <elem key="username">admin</elem>
--       <elem key="password">admin</elem>
--     </table>
--   </table>
-- </table>
-- <table key="Nagios">
--   <elem key="cpe">cpe:/a:nagios:nagios</elem>
--   <elem key="path">/nagios/</elem>
--   <table key="credentials">
--     <table>
--       <elem key="username">nagiosadmin</elem>
--       <elem key="password">CactiEZ</elem>
--     </table>
--   </table>
-- </table>
--
-- @args http-default-accounts.basepath Base path to append to requests.
--         Default: "/"
-- @args http-default-accounts.fingerprintfile Fingerprint file name (assumed
--         in directory <code>nselib/data</code>).
--         Default: <code>http-default-accounts-fingerprints.lua</code>
-- @args http-default-accounts.category Selects a fingerprint category
--         (or a list of categories).
-- @args http-default-accounts.name Selects fingerprints by a word
--         (or a list of alternate words) in their names.

-- Revision History
-- 2013-08-13 nnposter
--   * added support for target_check()
-- 2014-04-27
--   * changed category from safe to intrusive
-- 2016-08-10 nnposter
--   * Share probe requests across fingerprints
-- 2016-10-30 nnposter
--   * Rectify a limitation that prevented testing of systems returning
--     status 200 for non-existent pages.
-- 2016-12-01 nnposter
--   * Implement XML structured output
--   * Change classic output to report empty credentials as <blank>
-- 2016-12-04 nnposter
--   * Add CPE entries to individual fingerprints (where known)
-- 2018-12-17 nnposter
--   * Add ability to select fingerprints by their name
-- 2020-07-11 nnposter
--   * Report all matched fingerprints when verbosity is increased
-- 2025-11-12 nnposter
--   * Enforce mandatory fingerprint elements
--   * Stop testing of passwords as soon as the correct password for a given
--     username is found
--   * The default target_check function is now only built when some
--     of the loaded fingerprints lack their own.
---

author = {"Paulino Calderon <calderon@websec.mx>", "nnposter"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "auth", "intrusive"}

portrule = shortport.http

---
-- Tests if a given argument is an array, namely that its type is table
-- and that its indices represent an uninterrupted sequence of integers,
-- starting with 1. Empty table is considered to be an array.
-- @param tbl Argument to test
-- @return verdict (true or false)
---
local function is_array (tbl)
  if type(tbl) ~= "table" then return false end

  local max, count = 0, 0
  for k in next, tbl do
    -- keys must be positive integers
    if type(k) ~= "number" or k <= 0 or k % 1 ~= 0 then
      return false
    end
    if k > max then max = k end
    count = count + 1
  end

  -- there must be no index gaps
  return count == max
end

local fingerprint_checks = stdnse.output_table()

fingerprint_checks.struct = function (fpr)
  if type(fpr) ~= "table" then
    return false, "Fingerprint is not a table"
  end
  return true, fpr
end

fingerprint_checks.name = function (fpr)
  local name = fpr.name
  if type(name) ~= "string" then
     return false, "Missing or invalid name"
  end
  return true, name
end

fingerprint_checks.category = function (fpr)
  local category = fpr.category
  if type(category) ~= "string" then
     return false, "Missing or invalid category"
  end
  return true, category
end

fingerprint_checks.paths = function (fpr)
  local paths = fpr.paths
  if type(paths) == "string" then
    paths = {paths}
    fpr.paths = paths
  end
  if not is_array(paths) then
    return false, "Invalid or missing 'paths' array"
  end
  if #paths == 0 then
    return false, "Empty 'paths' array"
  end
  for i, path in ipairs(paths) do
    -- Convert the path to a table if necessary
    if type(path) == "string" then
      path = {['path'] = path}
      paths[i] = path
    end
    if type(path) ~= "table" then
      return false, ("'paths' entry #%d is not a table"):format(i)
    end
    if type(path.path) ~= "string" then
      return false, ("'paths' entry #%d is missing element 'path'"):format(i)
    end
  end
  return true, paths
end

fingerprint_checks.combos = function (fpr)
  local combos = fpr.login_combos
  if not is_array(combos) then
    return false, "Invalid or missing 'login_combos' array"
  end
  if #combos == 0 then
    return false, "Empty 'login_combos' array"
  end
  for i, combo in pairs(combos) do
    if type(combo) ~= "table" then
      return false, ("'login_combos' entry #%d is not a table"):format(i)
    end
    if not (type(combo.username) == "string"
        and type(combo.password) == "string") then
      return false, ("'login_combos' entry #%d requires to have a 'username' and 'password'"):format(i)
    end
  end
return true, combos
end

fingerprint_checks.target_check = function (fpr)
  local target_check = fpr.target_check
  if target_check and type(target_check) ~= "function" then
    return "Invalid target_check function"
  end
  return true, target_check
end

fingerprint_checks.login_check = function (fpr)
  local login_check = fpr.login_check
  if type(login_check) ~= "function" then
    return "Missing or invalid login_check function"
  end
  return true, login_check
end

---
-- Validates that a given argument is a properly structed collection
-- of fingerprints.
-- @param fingerprints Fingerprint table
-- @return Verdict (true or false)
-- @return Error string describing the first encountered irregularity
---
local function validate_fingerprints (fingerprints)
  if not is_array(fingerprints) then
    return false, "Invalid or missing 'fingerprints' array"
  end
  for i, fpr in ipairs(fingerprints) do
    for _, check in pairs(fingerprint_checks) do
      local status, err = check(fpr)
      if not status then
        return status, ("Fingerprint #%d: %s"):format(i, err)
      end
    end
  end
  return true
end

-- Simplify unlocking the mutex, ensuring we don't try to load the fingerprints
-- again by storing and returning an error message in place of the cached
-- fingerprints.
-- @param mutex Mutex that controls fingerprint loading
-- @param err Error message
-- @return Status (always false)
-- @return Error message passed in
local function bad_prints(mutex, err)
  nmap.registry.http_default_accounts_fingerprints = err
  mutex "done"
  return false, err
end

---
-- Loads data from file and returns table of fingerprints if sanity checks are
-- passed.
-- @param filename Fingerprint filename
-- @param catlist Categories of fingerprints to use
-- @param namelist Alternate words required in fingerprint names
-- @return Status (true or false)
-- @return Table of fingerprints (or an error message)
---
local function load_fingerprints(filename, catlist, namelist)
  local file, filename_full, fingerprints

  -- Check if fingerprints are cached
  local mutex = nmap.mutex("http_default_accounts_fingerprints")
  mutex "lock"
  local cached_fingerprints = nmap.registry.http_default_accounts_fingerprints
  if type(cached_fingerprints) == "table" then
    stdnse.debug(1, "Loading cached fingerprints")
    mutex "done"
    return true, cached_fingerprints
  end
  if type(cached_fingerprints) == "string" then
    -- cached_fingerprints contains an error message from a prior load attempt
    return bad_prints(mutex, cached_fingerprints)
  end
  assert(type(cached_fingerprints) == "nil", "Unexpected cached fingerprints")

  -- Try and find the file
  -- If it isn't in Nmap's directories, take it as a direct path
  filename_full = nmap.fetchfile('nselib/data/' .. filename)
  if(not(filename_full)) then
    filename_full = filename
  end

  -- Load the file
  stdnse.debug(1, "Loading fingerprints: %s", filename_full)
  local env = setmetatable({fingerprints = {}}, {__index = _G});
  file = loadfile(filename_full, "t", env)
  if( not(file) ) then
    stdnse.debug(1, "Couldn't load the file: %s", filename_full)
    return bad_prints(mutex, "Couldn't load fingerprint file: " .. filename_full)
  end
  file()
  fingerprints = env.fingerprints

  -- Validate fingerprints
  local status, err = validate_fingerprints(fingerprints)
  if not status then
    return bad_prints(mutex, err)
  end

  -- Category filter
  if catlist then
    if type(catlist) ~= "table" then
      catlist = {catlist}
    end
    local filtered_fingerprints = {}
    for _, fingerprint in pairs(fingerprints) do
      for _, cat in ipairs(catlist) do
        if fingerprint.category == cat then
          table.insert(filtered_fingerprints, fingerprint)
          break
        end
      end
    end
    fingerprints = filtered_fingerprints
  end

  -- Name filter
  if namelist then
    if type(namelist) ~= "table" then
      namelist = {namelist}
    end
    local matchlist = {}
    for _, name in ipairs(namelist) do
      table.insert(matchlist, "%f[%w]"
                              .. tostring(name):lower():gsub("%W", "%%%1")
                              .. "%f[%W]")
    end
    local filtered_fingerprints = {}
    for _, fingerprint in pairs(fingerprints) do
      local fpname = fingerprint.name:lower()
      for _, match in ipairs(matchlist) do
        if fpname:find(match) then
          table.insert(filtered_fingerprints, fingerprint)
          break
        end
      end
    end
    fingerprints = filtered_fingerprints
  end

  -- Check there are fingerprints to use
  if(#fingerprints == 0 ) then
    return bad_prints(mutex, "No fingerprints were loaded after processing ".. filename)
  end

  -- Cache the fingerprints for other invocations, so we aren't reading the files every time
  nmap.registry.http_default_accounts_fingerprints = fingerprints
  mutex "done"
  return true, fingerprints
end

---
-- Generates the default target_check function, which will be used with
-- fingerprints that lack their own. This default check is just testing
-- for existence of the probe path on the target.
-- @param host table as received by the scripts action method
-- @param port table as received by the scripts action method
-- @return target_check function
---
local function target_check_404 (host, port)
  -- Determine the target's response to "404" HTTP requests
  local status_404, result_404, known_404 = http.identify_404(host, port)
  -- To reduce false-positives, the default target_check will fail if "404"
  -- responses from the target either cannot be properly identified or they
  -- have HTTP status 200
  if not status_404 or result_404 == 200 then
    return function () return false end
  end
  -- The default target_check is the existence of the probe path on the target
  return function (_host, _port, path, response)
           return http.page_exists(response, result_404, known_404, path, true)
         end
end

---
-- format_basepath(basepath)
-- Modifies a given path so that it can be later prepended to another absolute
-- path to form a new absolute path.
-- @param basepath Basepath string
-- @return Basepath string with a leading slash and no trailing slashes.
--                   (Empty string is returned if the input is an empty string
--                   or "/".)
---
local function format_basepath(basepath)
  if basepath:sub(1,1) ~= "/" then
    basepath = "/" .. basepath
  end
  return basepath:gsub("/+$","")
end

---
-- test_credentials(host, port, fingerprint, path)
-- Tests default credentials of a given fingerprint against a given path.
-- Any successful credentials are registered in the Nmap credential repository.
-- @param host table as received by the scripts action method
-- @param port table as received by the scripts action method
-- @param fingerprint as defined in the fingerprint file
-- @param path againt which the credentials will be tested
-- @return out table suitable for inclusion in the script structured output
--             (or nil if no credentials succeeded)
-- @return txtout table suitable for inclusion in the script textual output
---
local function  test_credentials (host, port, fingerprint, path)
  local credhits = stdnse.output_table()
  for _, login_combo in ipairs(fingerprint.login_combos) do
    local user = login_combo.username
    local pass = login_combo.password
    if not credhits[user] then
      stdnse.debug(1, "[%s] Trying login combo %s:%s", fingerprint.name,
                   stdnse.string_or_blank(user), stdnse.string_or_blank(pass))
      if fingerprint.login_check(host, port, path, user, pass) then
        stdnse.debug(1, "[%s] Valid default credentials found", fingerprint.name)
        credhits[user] = pass
      end
    end
  end
  if #credhits == 0 and nmap.verbosity() < 2 then return nil end
  -- Some credentials found or increased verbosity. Generate the output report
  local out = stdnse.output_table()
  out.cpe = fingerprint.cpe
  out.path = path
  out.credentials = {}
  local txtout = {}
  txtout.name = ("[%s] at %s"):format(fingerprint.name, path)
  if #credhits == 0 then
    table.insert(txtout, "(no valid default credentials found)")
    return out, txtout
  end
  for user, pass in pairs(credhits) do
    local cred = stdnse.output_table()
    cred.username = user
    cred.password = pass
    table.insert(out.credentials, cred)
    table.insert(txtout,("%s:%s"):format(stdnse.string_or_blank(user),
                                         stdnse.string_or_blank(pass)))
  end
  -- Register the credentials
  local credreg = creds.Credentials:new(SCRIPT_NAME, host, port)
  for user, pass in pairs(credhits) do
    credreg:add(user, pass, creds.State.VALID )
  end
  return out, txtout
end


action = function(host, port)
  local fingerprint_filename = stdnse.get_script_args("http-default-accounts.fingerprintfile")
                               or "http-default-accounts-fingerprints.lua"
  local catlist = stdnse.get_script_args("http-default-accounts.category")
  local namelist = stdnse.get_script_args("http-default-accounts.name")
  local basepath = stdnse.get_script_args("http-default-accounts.basepath") or "/"
  local output = stdnse.output_table()
  local text_output = {}

  -- Load fingerprint data or abort
  local status, fingerprints = load_fingerprints(fingerprint_filename, catlist, namelist)
  if not status then
    return stdnse.format_output(false, fingerprints)
  end
  stdnse.debug(1, "%d fingerprints were loaded", #fingerprints)

  -- Build the default target_check function
  -- This requires extra web requests to the target so we do it only if needed
  local default_target_check = nil
  for _, fpr in ipairs(fingerprints) do
    if not fpr.target_check then
      default_target_check = target_check_404(host, port)
      break
    end
  end

  -- Format basepath: Removes or adds slashes
  stdnse.debug(1, "Trying known locations under path '%s' (change with '%s.basepath' argument)", basepath, SCRIPT_NAME)
  basepath = format_basepath(basepath)

  -- Add requests to the http pipeline
  local pathmap = {}
  local requests = nil
  for _, fingerprint in ipairs(fingerprints) do
    for _, probe in ipairs(fingerprint.paths) do
      -- Multiple fingerprints may share probe paths so only unique paths will
      -- be added to the pipeline. Table pathmap keeps track of their position
      -- within the pipeline.
      local path = probe.path
      if not pathmap[path] then
        requests = http.pipeline_add(basepath .. path,
                                    {bypass_cache=true, redirect_ok=false},
                                    requests, 'GET')
        pathmap[path] = #requests
      end
    end
  end

  -- Nuclear launch detected!
  local results = http.pipeline_go(host, port, requests)
  if results == nil then
    return stdnse.format_output(false,
      "HTTP request table is empty. This should not happen since we at least made one request.")
  end

  -- Iterate through fingerprints to find a candidate for login routine
  for _, fingerprint in ipairs(fingerprints) do
    local target_check = fingerprint.target_check or default_target_check
    local credentials_found = false
    stdnse.debug(1, "[%s] Examining target", fingerprint.name)
    for _, probe in ipairs(fingerprint.paths) do
      local result = results[pathmap[probe.path]]
      if result and not credentials_found then
        local path = basepath .. probe.path
        if target_check(host, port, path, result) then
          stdnse.debug(1, "[%s] Target matched", fingerprint.name)
          local out, txtout = test_credentials(host, port, fingerprint, path)
          if out then
            output[fingerprint.name] = out
            table.insert(text_output, txtout)
            credentials_found = true
          end
        end
      end
    end
  end
  if #text_output > 0 then
    return output, stdnse.format_output(true, text_output)
  end
end
