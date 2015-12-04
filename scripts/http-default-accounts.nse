local _G = require "_G"
local creds = require "creds"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests for access with default credentials used by a variety of web applications and devices.

It works similar to http-enum, we detect applications by matching known paths and launching a login routine using default credentials when found.
This script depends on a fingerprint file containing the target's information: name, category, location paths, default credentials and login routine.

You may select a category if you wish to reduce the number of requests. We have categories like:
* <code>web</code> - Web applications
* <code>routers</code> - Routers
* <code>voip</code> - VOIP devices
* <code>security</code>

Please help improve this script by adding new entries to nselib/data/http-default-accounts.lua

Remember each fingerprint must have:
* <code>name</code> - Descriptive name
* <code>category</code> - Category
* <code>login_combos</code> - Table of login combinations
* <code>paths</code> - Paths table containing the possible location of the target
* <code>login_check</code> - Login function of the target

In addition, a fingerprint may have:
* <code>target_check</code> - Target validation function. If defined, it will be called to validate the target before attempting any logins.

Default fingerprint file: /nselib/data/http-default-accounts-fingerprints.lua
This script was based on http-enum.
]]

---
-- @usage
-- nmap -p80 --script http-default-accounts host/ip
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- |_http-default-accounts: [Cacti] credentials found -> admin:admin Path:/cacti/
--
-- @args http-default-accounts.basepath Base path to append to requests. Default: "/"
-- @args http-default-accounts.fingerprintfile Fingerprint filename. Default: http-default-accounts-fingerprints.lua
-- @args http-default-accounts.category Selects a category of fingerprints to use.

-- Revision History
-- 2013-08-13 nnposter
--   * added support for target_check()
-- 2014-04-27
--   * changed category from safe to intrusive
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "auth", "intrusive"}

portrule = shortport.http

---
--validate_fingerprints(fingerprints)
--Returns an error string if there is something wrong with
--fingerprint table.
--Modified version of http-enums validation code
--@param fingerprints Fingerprint table
--@return Error string if its an invalid fingerprint table
---
local function validate_fingerprints(fingerprints)

  for i, fingerprint in pairs(fingerprints) do
    if(type(i) ~= 'number') then
      return "The 'fingerprints' table is an array, not a table; all indexes should be numeric"
    end
    -- Validate paths
    if(not(fingerprint.paths) or
      (type(fingerprint.paths) ~= 'table' and type(fingerprint.paths) ~= 'string') or
      (type(fingerprint.paths) == 'table' and #fingerprint.paths == 0)) then
      return "Invalid path found in fingerprint entry #" .. i
    end
    if(type(fingerprint.paths) == 'string') then
      fingerprint.paths = {fingerprint.paths}
    end
    for i, path in pairs(fingerprint.paths) do
      -- Validate index
      if(type(i) ~= 'number') then
        return "The 'paths' table is an array, not a table; all indexes should be numeric"
      end
      -- Convert the path to a table if it's a string
      if(type(path) == 'string') then
        fingerprint.paths[i] = {path=fingerprint.paths[i]}
        path = fingerprint.paths[i]
      end
      -- Make sure the paths table has a 'path'
      if(not(path['path'])) then
        return "The 'paths' table requires each element to have a 'path'."
      end
    end
    -- Check login combos
    for i, combo in pairs(fingerprint.login_combos) do
      -- Validate index
      if(type(i) ~= 'number') then
        return "The 'login_combos' table is an array, not a table; all indexes should be numeric"
      end
      -- Make sure the login_combos table has at least one login combo
      if(not(combo['username']) or not(combo["password"])) then
        return "The 'login_combos' table requires each element to have a 'username' and 'password'."
      end
    end

     -- Make sure they include the login function
    if(type(fingerprint.login_check) ~= "function") then
      return "Missing or invalid login_check function in entry #"..i
    end
     -- Make sure that the target validation is a function
    if(fingerprint.target_check and type(fingerprint.target_check) ~= "function") then
      return "Invalid target_check function in entry #"..i
    end
      -- Are they missing any fields?
    if(fingerprint.category and type(fingerprint.category) ~= "string") then
      return "Missing or invalid category in entry #"..i
    end
    if(fingerprint.name and type(fingerprint.name) ~= "string") then
      return "Missing or invalid name in entry #"..i
    end
  end
end

---
-- load_fingerprints(filename, category)
-- Loads data from file and returns table of fingerprints if sanity checks are passed
-- Based on http-enum's load_fingerprints()
-- @param filename Fingerprint filename
-- @param cat Category of fingerprints to use
-- @return Table of fingerprints
---
local function load_fingerprints(filename, cat)
  local file, filename_full, fingerprints

  -- Check if fingerprints are cached
  if(nmap.registry.http_default_accounts_fingerprints ~= nil) then
    stdnse.debug(1, "Loading cached fingerprints")
    return nmap.registry.http_default_accounts_fingerprints
  end

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
    return false, "Couldn't load fingerprint file: " .. filename_full
  end
  file()
  fingerprints = env.fingerprints

  -- Validate fingerprints
  local valid_flag = validate_fingerprints(fingerprints)
  if type(valid_flag) == "string" then
    return false, valid_flag
  end

  -- Category filter
  if ( cat ) then
    local filtered_fingerprints = {}
    for _, fingerprint in pairs(fingerprints) do
      if(fingerprint.category == cat) then
        table.insert(filtered_fingerprints, fingerprint)
      end
    end
    fingerprints = filtered_fingerprints
  end

  -- Check there are fingerprints to use
  if(#fingerprints == 0 ) then
    return false, "No fingerprints were loaded after processing ".. filename
  end

  return true, fingerprints
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
-- register_http_credentials(username, password)
-- Stores HTTP credentials in the registry. If the registry entry hasn't been
-- initiated, it will create it and store the credentials.
-- @param login_username Username
-- @param login_password Password
---
local function register_http_credentials(host, port, login_username, login_password)
  local c = creds.Credentials:new( SCRIPT_NAME, host, port )
  c:add(login_username, login_password, creds.State.VALID )
end

---
-- MAIN
-- Here we iterate through the paths to try to find a target. When a target is found
-- the login routine is initialized to check for default credentials authentication
---
action = function(host, port)
  local fingerprintload_status, status, fingerprints, requests, results
  local fingerprint_filename = stdnse.get_script_args("http-default-accounts.fingerprintfile") or "http-default-accounts-fingerprints.lua"
  local category = stdnse.get_script_args("http-default-accounts.category") or false
  local basepath = stdnse.get_script_args("http-default-accounts.basepath") or "/"
  local output_lns = {}

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  --Load fingerprint data or abort
  status, fingerprints = load_fingerprints(fingerprint_filename, category)
  if(not(status)) then
    return stdnse.format_output(false, fingerprints)
  end
  stdnse.debug(1, "%d fingerprints were loaded", #fingerprints)

  --Format basepath: Removes or adds slashs
  basepath = format_basepath(basepath)

  -- Add requests to the http pipeline
  requests = {}
  stdnse.debug(1, "Trying known locations under path '%s' (change with '%s.basepath' argument)", basepath, SCRIPT_NAME)
  for i = 1, #fingerprints, 1 do
    for j = 1, #fingerprints[i].paths, 1 do
      requests = http.pipeline_add(basepath .. fingerprints[i].paths[j].path, nil, requests, 'GET')
    end
  end

  -- Nuclear launch detected!
  results = http.pipeline_go(host, port, requests, nil)
  if results == nil then
    return stdnse.format_output(false,
      "HTTP request table is empty. This should not happen since we at least made one request.")
  end

  -- Iterate through responses to find a candidate for login routine
  local j = 1

  for i, fingerprint in ipairs(fingerprints) do
    local credentials_found = false
    stdnse.debug(1, "Processing %s", fingerprint.name)
    for _, probe in ipairs(fingerprint.paths) do

      if (results[j] and not(credentials_found)) then
        local path = basepath .. probe['path']

        if http.page_exists(results[j], result_404, known_404, path, true)
          and (not fingerprint.target_check
          or fingerprint.target_check(host, port, path, results[j]))
        then
          for _, login_combo in ipairs(fingerprint.login_combos) do
            stdnse.debug(2, "Trying login combo -> %s:%s", login_combo["username"], login_combo["password"])
            --Check default credentials
            if( fingerprint.login_check(host, port, path, login_combo["username"], login_combo["password"]) ) then

              --Valid credentials found
              stdnse.debug(1, "[%s] valid default credentials found.", fingerprint.name)
              output_lns[#output_lns + 1] = string.format("[%s] credentials found -> %s:%s Path:%s",
                                          fingerprint.name, login_combo["username"], login_combo["password"], path)
              -- Add to http credentials table
              register_http_credentials(host, port, login_combo["username"], login_combo["password"])
              credentials_found = true
            end
          end
        end
      end
      j = j + 1
    end
  end

  if #output_lns > 0 then
    return stdnse.strjoin("\n", output_lns)
  end
end
