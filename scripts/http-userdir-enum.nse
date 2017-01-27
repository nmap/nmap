local datafiles = require "datafiles"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to enumerate valid usernames on web servers running with the mod_userdir
module or similar enabled.

The Apache mod_userdir module allows user-specific directories to be accessed
using the http://example.com/~user/ syntax.  This script makes http requests in
order to discover valid user-specific directories and infer valid usernames.  By
default, the script will use Nmap's
<code>nselib/data/usernames.lst</code>.  An HTTP response
status of 200 or 403 means the username is likely a valid one and the username
will be output in the script results along with the status code (in parentheses).

This script makes an attempt to avoid false positives by requesting a directory
which is unlikely to exist.  If the server responds with 200 or 403 then the
script will not continue testing it.

CVE-2001-1013: http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2001-1013.
]]

---
-- @args userdir.users The filename of a username list.
-- @args limit The maximum number of users to check.
--
-- @output
-- 80/tcp open  http    syn-ack Apache httpd 2.2.9
-- |_ http-userdir-enum: Potential Users: root (403), user (200), test (200)

author = "jah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}



portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)

  if(not nmap.registry.userdir) then
    init()
  end
  local usernames = nmap.registry.userdir

  -- speedy exit if no usernames
  if(#usernames == 0) then
    return fail("Didn't find any users to test (should be in nselib/data/usernames.lst)")
  end

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  -- Check if we can use HEAD requests
  local use_head = http.can_use_head(host, port, result_404)

  -- Queue up the checks
  local all = {}
  local i
  for i = 1, #usernames, 1 do
    if(nmap.registry.args.limit and i > tonumber(nmap.registry.args.limit)) then
      stdnse.debug1("Reached the limit (%d), stopping", nmap.registry.args.limit)
      break;
    end

    if(use_head) then
      all = http.pipeline_add("/~" .. usernames[i], nil, all, 'HEAD')
    else
      all = http.pipeline_add("/~" .. usernames[i], nil, all, 'GET')
    end
  end

  local results = http.pipeline_go(host, port, all)

  -- Check for http.pipeline error
  if(results == nil) then
    stdnse.debug1("http.pipeline returned nil")
    return fail("http.pipeline returned nil")
  end

  local found = {}
  for i, data in pairs(results) do
    if(http.page_exists(data, result_404, known_404, "/~" .. usernames[i], true)) then
      stdnse.debug1("Found a valid user: %s", usernames[i])
      table.insert(found, usernames[i])
    end
  end

  if(#found > 0) then
    return string.format("Potential Users: %s", table.concat(found, ", "))
  elseif(nmap.debugging() > 0) then
    return "Didn't find any users!"
  end

  return nil
end



---
-- Parses a file containing usernames (1 per line), defaulting to
-- "nselib/data/usernames.lst" and stores the resulting array of usernames in
-- the registry for use by all threads of this script.  This means file access
-- is done only once per Nmap invocation.  init() also adds a random string to
-- the array (in the first position) to attempt to catch false positives.
-- @return nil

function init()
  local customlist = nmap.registry.args.users or
    (nmap.registry.args.userdir and nmap.registry.args.userdir.users) or
    stdnse.get_script_args('userdir.users')
  local read, usernames = datafiles.parse_file(customlist or "nselib/data/usernames.lst", {})
  if not read then
    stdnse.debug1("%s", usernames or "Unknown Error reading usernames list.")
    nmap.registry.userdir = {}
    return nil
  end
  -- random dummy username to catch false positives (not necessary)
--  if #usernames > 0 then table.insert(usernames, 1, randomstring()) end
  nmap.registry.userdir = usernames
  stdnse.debug1("Testing %d usernames.", #usernames)
  return nil
end
