author = "jah"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}
description = [[
Attempts to enumerate valid usernames on webservers running with the mod_userdir
module or similar enabled.

The Apache mod_userdir module allows user-specific directories to be accessed
using the http://example.com/~user/ syntax.  This script makes http requests in
order to discover valid user-specific directories and infer valid usernames.  By
default, the script will use Nmaps nselib/data/usernames.lst  An http response
status of 200 or 403 means the username is likely a valid one and the username
will be output in the script results along with the status code (in parentheses).

This script makes an attempt to avoid false positives by requesting a directory
which is unlikely to exist.  If the server responds with 200 or 403 then the
script will not continue testing it.

Ref: CVE-2001-1013 http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2001-1013
]]
---
-- @args
-- users=path/to/custom/usernames.list or
-- userdir.users=path/to/custom/usernames.list
--@args limit      Limit the number of users to check. This option is useful if using a list from, for example, 
--                 the DirBuster projects which can have 80,000+ entries. 

--
-- @output
-- 80/tcp open  http    syn-ack Apache httpd 2.2.9
-- |_ apache-userdir-enum: Potential Users: root (403), user (200), test (200)



local http      = require 'http'
local stdnse    = require 'stdnse'
local datafiles = require 'datafiles'



---
-- The script will run against http[s] and http[s]-alt tcp ports.
portrule = function(host, port)
  local svc = { std = { ["http"] = 1, ["http-alt"] = 1 },
                ssl = { ["https"] = 1, ["https-alt"] = 1 } }
  if port.protocol ~= 'tcp' or not
  ( svc.std[port.service] or svc.ssl[port.service] ) then
    return false
  end
  -- Don't bother running on SSL ports if we don't have SSL.
  if (svc.ssl[port.service] or port.version.service_tunnel == 'ssl') and not
  nmap.have_ssl() then
    return false
  end
  return true
end



action = function(host, port)

  if(not nmap.registry.userdir) then 
    init()
  end
  local usernames = nmap.registry.userdir

  -- speedy exit if no usernames
  if(#usernames == 0) then
    if(nmap.debugging() > 0) then
      return "Didn't find any users to test (should be in nselib/data/usernames.lst)"
    else
      return nil
    end
  end

  -- Check what response we get for a 404
  local result, result_404, known_404 = http.identify_404(host, port)
  if(result == false) then
    if(nmap.debugging() > 0) then
      return "ERROR: " .. result_404
    else
      return nil
    end
  end

  -- Check if we can use HEAD requests
  local use_head = http.can_use_head(host, port, result_404)

  -- If we can't use HEAD, make sure we can use GET requests
  if(use_head == false) then
    local result, err = http.can_use_get(host, port)
    if(result == false) then
      if(nmap.debugging() > 0) then
        return "ERROR: " .. err
      else
        return nil
      end
    end
  end

  -- Queue up the checks
  local all = {}
  local i
  for i = 1, #usernames, 1 do
    if(nmap.registry.args.limit and i > tonumber(nmap.registry.args.limit)) then
      stdnse.print_debug(1, "http-userdir-enum.nse: Reached the limit (%d), stopping", nmap.registry.args.limit)
      break;
    end

    if(use_head) then
      all = http.pHead(host, port, "/~" .. usernames[i], nil, nil, all)
    else
      all = http.pGet(host, port, "/~" .. usernames[i], nil, nil, all)
    end
  end

  local results = http.pipeline(host, port, all, nil)

  -- Check for http.pipeline error
  if(results == nil) then
    stdnse.print_debug(1, "http-userdir-enum.nse: http.pipeline returned nil")
    if(nmap.debugging() > 0) then
      return "ERROR: http.pipeline returned nil"
    else
      return nil
    end
  end

  local found = {}
  for i, data in pairs(results) do
    if(http.page_exists(data, result_404, known_404, "/~" .. usernames[i], true)) then
      stdnse.print_debug(1, "http-userdir-enum.nse: Found a valid user: %s", usernames[i])
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
  local filename = filename and filename:match( "[\\/]([^\\/]+)\.nse$" ) or ""
  local customlist = nmap.registry.args.users or
    (nmap.registry.args.userdir and nmap.registry.args.userdir.users) or
    nmap.registry.args['userdir.users']
  local read, usernames = datafiles.parse_file(customlist or "nselib/data/usernames.lst", {})
  if not read then
    stdnse.print_debug(1, "%s %s", filename,
      usernames or "Unknown Error reading usernames list.")
    nmap.registry.userdir = {}
    return nil
  end
  -- random dummy username to catch false positives (not necessary)
--  if #usernames > 0 then table.insert(usernames, 1, randomstring()) end
  nmap.registry.userdir = usernames
  stdnse.print_debug(1, "%s Testing %d usernames.", filename, #usernames)
  return nil
end



---
-- Uses openssl.rand_pseudo_bytes (if available, os.time() if not) and base64.enc
-- to produce a randomish string of at least 11 alphanumeric chars.
-- @return String

function randomstring()
  local bin    = require"bin"
  local base64 = require"base64"
  local rnd, s, l, _
  if pcall(require, "openssl") then
    rnd = openssl.rand_pseudo_bytes
  end
  s = rnd and rnd(8) or tostring( os.time() )
  -- increase the length of the string by 0 to 7 chars
  _, l = bin.unpack(">C", s, 8) -- eighth byte should be safe for os.time() too
  s = l%8 > 0 and s .. s:sub(1,l%8) or s
  -- base 64 encode and replace any non alphanum chars (with 'n' for nmap!)
  s = base64.enc(s):sub(1,-2):gsub("%W", "n")
  return s
end
