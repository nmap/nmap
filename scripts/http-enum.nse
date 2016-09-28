local _G = require "_G"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates directories used by popular web applications and servers.

This parses a fingerprint file that's similar in format to the Nikto Web application
scanner. This script, however, takes it one step further by building in advanced pattern matching as well
as having the ability to identify specific versions of Web applications.

You can also parse a Nikto-formatted database using http-fingerprints.nikto-db-path. This will try to parse
most of the fingerprints defined in nikto's database in real time. More documentation about this in the
nselib/data/http-fingerprints.lua file.

Currently, the database can be found under Nmap's directory in the nselib/data folder. The file is called
http-fingerprints and has a long description of its functionality in the file header.

Many of the finger prints were discovered by me (Ron Bowes), and a number of them are from the Yokoso
project, used with permission from Kevin Johnson (http://seclists.org/nmap-dev/2009/q3/0685.html).

Initially, this script attempts to access two different random files in order to detect servers
that don't return a proper 404 Not Found status. In the event that they return 200 OK, the body
has any non-static-looking data removed (URI, time, etc), and saved. If the two random attempts
return different results, the script aborts (since a 200-looking 404 cannot be distinguished from
an actual 200). This will prevent most false positives.

In addition, if the root folder returns a 301 Moved Permanently or 401 Authentication Required,
this script will also abort. If the root folder has disappeared or requires authentication, there
is little hope of finding anything inside it.

By default, only pages that return 200 OK or 401 Authentication Required are displayed. If the
<code>http-enum.displayall</code> script argument is set, however, then all results will be displayed (except
for 404 Not Found and the status code returned by the random files). Entries in the http-fingerprints
database can specify their own criteria for accepting a page as valid.

]]

---
-- @args http-enum.basepath         The base path to prepend to each request. Leading/trailing slashes are ignored.
-- @args http-enum.displayall       Set this argument to display all status codes that may indicate a valid page, not
--                                  just 200 OK and 401 Authentication Required pages. Although this is more likely
--                                  to find certain hidden folders, it also generates far more false positives.
-- @args http-enum.fingerprintfile  Specify a different file to read fingerprints from.
-- @args http-enum.category         Set to a category (as defined in the fingerprints file). Some options are 'attacks',
--                                  'database', 'general', 'microsoft', 'printer', etc.
-- @args http-fingerprints.nikto-db-path Looks at the given path for nikto database.
--       It then converts the records in nikto's database into our Lua table format
--       and adds them to our current fingerprints if they don't exist already.
--       Unfortunately, our current implementation has some limitations:
--          * It doesn't support records with more than one 'dontmatch' patterns for
--            a probe.
--          * It doesn't support logical AND for the 'match' patterns.
--          * It doesn't support sending additional headers for a probe.
--       That means, if a nikto fingerprint needs one of the above features, it
--       won't be loaded. At the time of writing this, 6546 out of the 6573 Nikto
--       fingerprints are being loaded successfully.  This runtime Nikto fingerprint integration was suggested by Nikto co-author Chris Sullo as described at http://seclists.org/nmap-dev/2013/q4/292
--
-- @output
-- Interesting ports on test.skullsecurity.org (208.81.2.52):
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-enum:
-- |   /icons/: Icons and images
-- |   /images/: Icons and images
-- |   /robots.txt: Robots file
-- |   /sw/auth/login.aspx: Citrix WebTop
-- |   /images/outlook.jpg: Outlook Web Access
-- |   /nfservlets/servlet/SPSRouterServlet/: netForensics
-- |_  /nfservlets/servlet/SPSRouterServlet/: netForensics

author = {"Ron Bowes", "Andrew Orr", "Rob Nicholls"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive", "vuln"}


portrule = shortport.http

-- TODO
-- o Automatically convert HEAD -> GET if the server doesn't support HEAD
-- o Add variables for common extensions, common CGI extensions, etc that expand the probes

-- File extensions (TODO: Implement this)
local cgi_ext = { 'php', 'asp', 'aspx', 'jsp', 'pl', 'cgi' }

local common_ext = { 'php', 'asp', 'aspx', 'jsp', 'pl', 'cgi', 'css', 'js', 'htm', 'html' }

---Convert the filename to backup variations. These can be valuable for a number of reasons.
-- First, because they may not have the same access restrictions as the main version (file.php
-- may run as a script, but file.php.bak or file.php~ might not). And second, the old versions
-- might contain old vulnerabilities
--
-- At the time of the writing, these were all decided by me (Ron Bowes).
local function get_variations(filename)
  local variations = {}

  if(filename == nil or filename == "" or filename == "/") then
    return {}
  end

  local is_directory = (string.sub(filename, #filename, #filename) == "/")
  if(is_directory) then
    filename = string.sub(filename, 1, #filename - 1)
  end

  -- Try some extensions
  table.insert(variations, filename .. ".bak")
  table.insert(variations, filename .. ".1")
  table.insert(variations, filename .. ".tmp")

  -- Strip off the extension, if it has one, and try it all again.
  -- For now, just look for three-character extensions.
  if(string.sub(filename, #filename - 3, #filename - 3) == '.') then
    local bare = string.sub(filename, 1, #filename - 4)
    local extension = string.sub(filename, #filename - 3)

    table.insert(variations, bare .. ".bak")
    table.insert(variations, bare .. ".1")
    table.insert(variations, bare .. ".tmp")
    table.insert(variations, bare .. "_1" .. extension)
    table.insert(variations, bare .. "2" .. extension)
  end


  -- Some Windowsy things
  local onlyname = string.sub(filename, 2)
  -- If the name contains a '/', forget it
  if(string.find(onlyname, "/") == nil) then
    table.insert(variations, "/Copy of " .. onlyname)
    table.insert(variations, "/Copy (2) of " .. onlyname)
    table.insert(variations, "/Copy of Copy of " .. onlyname)

    -- Word/Excel/etc replace the first two characters with '~$', it seems
    table.insert(variations, "/~$" .. string.sub(filename, 4))
  end

  -- Some editors add a '~'
  table.insert(variations, filename .. "~")

  -- Try some directories
  table.insert(variations, "/bak" .. filename)
  table.insert(variations, "/backup" .. filename)
  table.insert(variations, "/backups" .. filename)
  table.insert(variations, "/beta" .. filename)
  table.insert(variations, "/test" .. filename)

  -- If it's a directory, add a '/' after every entry
  if(is_directory) then
    for i, v in ipairs(variations) do
      variations[i] = v .. "/"
    end
  end

  -- Some compressed formats (we don't want a trailing '/' on these, so they go after the loop)
  table.insert(variations, filename .. ".zip")
  table.insert(variations, filename .. ".tar")
  table.insert(variations, filename .. ".tar.gz")
  table.insert(variations, filename .. ".tgz")
  table.insert(variations, filename .. ".tar.bz2")



  return variations
end

---Get the list of fingerprints from files. The files are defined in <code>fingerprint_files</code>. If category
-- is non-nil, only choose scripts that are in that category.
--
--@return An array of entries, each of which have a <code>checkdir</code> field, and possibly a <code>checkdesc</code>.
local function get_fingerprints(fingerprint_file, category)
  local entries  = {}
  local i
  local total_count = 0 -- Used for 'limit'

  -- Check if we've already read the file
  -- There might be a race condition here, where multiple scripts will read the file and set this variable, but the impact
  -- of that would be minimal (and definitely isn't security)
  if(nmap.registry.http_fingerprints ~= nil) then
    stdnse.debug1("Using cached HTTP fingerprints")
    return nmap.registry.http_fingerprints
  end

  -- Try and find the file; if it isn't in Nmap's directories, take it as a direct path
  local filename_full = nmap.fetchfile('nselib/data/' .. fingerprint_file)
  if(not(filename_full)) then
    filename_full = fingerprint_file
  end

  stdnse.debug1("Loading fingerprint database: %s", filename_full)
  local env = setmetatable({fingerprints = {}}, {__index = _G})
  local file = loadfile(filename_full, "t", env)
  if(not(file)) then
    stdnse.debug1("Couldn't load configuration file: %s", filename_full)
    return false, "Couldn't load fingerprint file: " .. filename_full
  end

  file()

  local fingerprints = env.fingerprints

  -- Sanity check our file to ensure that all the fields were good. If any are bad, we
  -- stop and don't load the file.
  for i, fingerprint in pairs(fingerprints) do
    -- Make sure we have a valid index
    if(type(i) ~= 'number') then
      return false, "The 'fingerprints' table is an array, not a table; all indexes should be numeric"
    end

    -- Make sure they have either a string or a table of probes
    if(not(fingerprint.probes) or
      (type(fingerprint.probes) ~= 'table' and type(fingerprint.probes) ~= 'string') or
      (type(fingerprint.probes) == 'table' and #fingerprint.probes == 0)) then
      return false, "Invalid path found for fingerprint " .. i
    end

    -- Make sure fingerprint.path is a table
    if(type(fingerprint.probes) == 'string') then
      fingerprint.probes = {fingerprint.probes}
    end

    -- Make sure the elements in the probes array are strings or arrays
    for i, probe in pairs(fingerprint.probes) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return false, "The 'probes' table is an array, not a table; all indexes should be numeric"
      end

      -- Convert the probe to a table if it's a string
      if(type(probe) == 'string') then
        fingerprint.probes[i] = {path=fingerprint.probes[i]}
        probe = fingerprint.probes[i]
      end

      -- Make sure the probes table has a 'path'
      if(not(probe['path'])) then
        return false, "The 'probes' table requires each element to have a 'path'."
      end

      -- If they didn't set a method, set it to 'GET'
      if(not(probe['method'])) then
        probe['method'] = 'GET'
      end

      -- Make sure the method's a string
      if(type(probe['method']) ~= 'string') then
        return false, "The 'method' in the probes file has to be a string"
      end
    end

    -- Ensure that matches is an array
    if(type(fingerprint.matches) ~= 'table') then
      return false, "'matches' field has to be a table"
    end

    -- Loop through the matches
    for i, match in pairs(fingerprint.matches) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return false, "The 'matches' table is an array, not a table; all indexes should be numeric"
      end

      -- Check that every element in the table is an array
      if(type(match) ~= 'table') then
        return false, "Every element of 'matches' field has to be a table"
      end

      -- Check the output field
      if(match['output'] == nil or type(match['output']) ~= 'string') then
        return false, "The 'output' field in 'matches' has to be present and a string"
      end

      -- Check the 'match' and 'dontmatch' fields, if present
      if((match['match'] and type(match['match']) ~= 'string') or (match['dontmatch'] and type(match['dontmatch']) ~= 'string')) then
        return false, "The 'match' and 'dontmatch' fields in 'matches' have to be strings, if they exist"
      end

      -- Change blank 'match' strings to '.*' so they match everything
      if(not(match['match']) or match['match'] == '') then
        match['match'] = '(.*)'
      end
    end

    -- Make sure the severity is an integer between 1 and 4. Default it to 1.
    if(fingerprint.severity and (type(fingerprint.severity) ~= 'number' or fingerprint.severity < 1 or fingerprint.severity > 4)) then
      return false, "The 'severity' field has to be an integer between 1 and 4"
    else
      fingerprint.severity = 1
    end

    -- Make sure ignore_404 is a boolean. Default it to false.
    if(fingerprint.ignore_404 and type(fingerprint.ignore_404) ~= 'boolean') then
      return false, "The 'ignore_404' field has to be a boolean"
    else
      fingerprint.ignore_404 = false
    end
  end

  -- Make sure we have some fingerprints fingerprints
  if(#fingerprints == 0) then
    return false, "No fingerprints were loaded"
  end

  -- If the user wanted to filter by category, do it
  if(category) then
    local filtered_fingerprints = {}
    for _, fingerprint in pairs(fingerprints) do
      if(fingerprint.category == category) then
        table.insert(filtered_fingerprints, fingerprint)
      end
    end

    fingerprints = filtered_fingerprints

    -- Make sure we still have fingerprints after the category filter
    if(#fingerprints == 0) then
      return false, "No fingerprints matched the given category (" .. category .. ")"
    end
  end


  --  -- If the user wants to try variations, add them
  --  if(try_variations) then
  --    -- Get a list of all variations for this directory
  --    local variations = get_variations(entry['checkdir'])
  --
  --    -- Make a copy of the entry for each of them
  --    for _, variation in ipairs(variations) do
  --      new_entry = {}
  --      for k, v in pairs(entry) do
  --        new_entry[k] = v
  --      end
  --      new_entry['checkdesc'] = new_entry['checkdesc'] .. " (variation)"
  --      new_entry['checkdir'] = variation
  --      table.insert(entries, new_entry)
  --      count = count + 1
  --    end
  --  end

  -- Cache the fingerprints for other scripts, so we aren't reading the files every time
  --  nmap.registry.http_fingerprints = fingerprints

  return true, fingerprints
end

action = function(host, port)
  local response = {}

  -- Read the script-args, keeping the old ones for reverse compatibility
  local basepath         = stdnse.get_script_args({'http-enum.basepath',        'path'})         or '/'
  local displayall       = stdnse.get_script_args({'http-enum.displayall',      'displayall'})   or false
  local fingerprint_file = stdnse.get_script_args({'http-enum.fingerprintfile', 'fingerprints'}) or 'http-fingerprints.lua'
  local category         = stdnse.get_script_args('http-enum.category')
  --  local try_variations   = stdnse.get_script_args({'http-enum.tryvariations',   'variations'})   or false
  --  local limit            = tonumber(stdnse.get_script_args({'http-enum.limit', 'limit'})) or -1

  -- Add URLs from external files
  local status, fingerprints = get_fingerprints(fingerprint_file, category)
  if(not(status)) then
    return stdnse.format_output(false, fingerprints)
  end
  stdnse.debug1("Loaded %d fingerprints", #fingerprints)

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  -- Queue up the checks
  local all = {}

  -- Remove trailing slash, if it exists
  if(#basepath > 1 and string.sub(basepath, #basepath, #basepath) == '/') then
    basepath = string.sub(basepath, 1, #basepath - 1)
  end

  -- Add a leading slash, if it doesn't exist
  if(#basepath <= 1) then
    basepath = ''
  else
    if(string.sub(basepath, 1, 1) ~= '/') then
      basepath = '/' .. basepath
    end
  end

  local results_nopipeline = {}
  -- Loop through the fingerprints
  stdnse.debug1("Searching for entries under path '%s' (change with 'http-enum.basepath' argument)", basepath)
  for i = 1, #fingerprints, 1 do
    -- Add each path. The order very much matters here.
    for j = 1, #fingerprints[i].probes, 1 do
      local probe = fingerprints[i].probes[j]
      if probe.nopipeline then
        local res = http.generic_request(host, port, probe.method or 'GET', basepath .. probe.path, probe.options or nil)
        if res.status then
          table.insert(results_nopipeline, res)
        else
          table.insert(results_nopipeline, false)
        end
      else
        all = http.pipeline_add(basepath .. probe.path, probe.options or nil, all, probe.method or 'GET')
      end
    end
  end

  -- Perform all the requests.
  local results = http.pipeline_go(host, port, all)

  -- Check for http.pipeline error
  if(results == nil) then
    stdnse.debug1("http.pipeline_go encountered an error")
    return stdnse.format_output(false, "http.pipeline_go encountered an error")
  end

  -- Loop through the fingerprints. Note that for each fingerprint, we may have multiple results
  local j = 1
  local j_nopipeline = 1
  for i, fingerprint in ipairs(fingerprints) do

    -- Loop through the paths for each fingerprint in the same order we did the requests. Each of these will
    -- have one result, so increment the result value at each iteration
    for _, probe in ipairs(fingerprint.probes) do
      local result
      if probe.nopipeline then
        result = results_nopipeline[j_nopipeline]
        j_nopipeline = j_nopipeline + 1
      else
        result = results[j]
        j = j + 1
      end
      if(result) then
        local path = basepath .. probe['path']
        local good = true
        local output = nil
        -- Unless this check said to ignore 404 messages, check if we got a valid page back using a known 404 message.
        if(fingerprint.ignore_404 ~= true and not(http.page_exists(result, result_404, known_404, path, displayall))) then
          good = false
        else
          -- Loop through our matches table and see if anything matches our result
          for _, match in ipairs(fingerprint.matches) do
            if(match.match) then
              local result, matches = http.response_contains(result, match.match)
              if(result) then
                output = match.output
                good = true
                for k, value in ipairs(matches) do
                  output = string.gsub(output, '\\' .. k, matches[k])
                end
              end
            else
              output = match.output
            end

            -- If nothing matched, turn off the match
            if(not(output)) then
              good = false
            end

            -- If we match the 'dontmatch' line, we're not getting a match
            if(match.dontmatch and match.dontmatch ~= '' and http.response_contains(result, match.dontmatch)) then
              output = nil
              good = false
            end

            -- Break the loop if we found it
            if(output) then
              break
            end
          end
        end

        if(good) then
          -- Save the path in the registry
          http.save_path(stdnse.get_hostname(host), port.number, path, result.status)

          -- Add the path to the output
          output = string.format("%s: %s", path, output)

          -- Build the status code, if it isn't a 200
          if(result.status ~= 200) then
            output = output .. " (" .. http.get_status_string(result) .. ")"
          end

          stdnse.debug1("Found a valid page! %s", output)

          table.insert(response, output)
        end
      end
    end
  end

  return stdnse.format_output(true, response)
end
