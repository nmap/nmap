description = [[
Enumerates directories used by popular web applications and servers.

Initially performs checks of an unlikely file in an attempt to detect
servers that have been configured to return a 302 or 200 response,
which should help prevent false positives.
]]

---
--@output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_ http-enum: /icons/ Icons directory

author = "Rob Nicholls <robert@everythingeverything.co.uk>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive", "vuln"}

local url    = require 'url'
local http   = require 'http'
local ipOps  = require 'ipOps'
local stdnse = require 'stdnse'

portrule = function(host, port)
    local svc = { std = { ["http"] = 1, ["http-alt"] = 1 },
                ssl = { ["https"] = 1, ["https-alt"] = 1 } }
    if port.protocol ~= 'tcp'
    or not ( svc.std[port.service] or svc.ssl[port.service] ) then
        return false
    end
    -- Don't bother running on SSL ports if we don't have SSL.
    if (svc.ssl[port.service] or port.version.service_tunnel == 'ssl')
    and not nmap.have_ssl() then
        return false
    end
    return true
end

action = function(host, port)

  local data
  local check404 = "404"
  local check404body = ""
  local checkHEAD = "200"
  local result = ""
  local all = {}
  local safeURLcheck = {
    {checkdir="/_vti_bin/", checkdesc="FrontPage directory"},
    {checkdir="/_vti_cnf/", checkdesc="FrontPage directory"},
    {checkdir="/_vti_log/", checkdesc="FrontPage directory"},
    {checkdir="/_vti_pvt/", checkdesc="FrontPage directory"},
    {checkdir="/_vti_txt/", checkdesc="FrontPage directory"},
    {checkdir="/admin/", checkdesc="Admin directory"},
    {checkdir="/backup/", checkdesc="Backup directory"},
    {checkdir="/beta/", checkdesc="Beta directory"},
    {checkdir="/bin/", checkdesc="Bin directory"},
    {checkdir="/css", checkdesc="CSS directory"},
    {checkdir="/data/", checkdesc="Data directory"},
    {checkdir="/db/", checkdesc="Possible database directory"},
    {checkdir="/demo/", checkdesc="Demo directory"},
    {checkdir="/dev/", checkdesc="Possible development directory"},
    {checkdir="/downloads/", checkdesc="Downloads directory"},
    {checkdir="/etc/passwd", checkdesc="Password file served by website"},
    {checkdir="/exchange/", checkdesc="Outlook Web Access"},
    {checkdir="/exchweb/", checkdesc="Outlook Web Access"},
    {checkdir="/forum/", checkdesc="Forum software"},
    {checkdir="/forums/", checkdesc="Forum software"},
    {checkdir="/icons/", checkdesc="Icons directory"},
    {checkdir="/iissamples/", checkdesc="IIS sample scripts"},
    {checkdir="/images/", checkdesc="Images directory"},
    {checkdir="/includes/", checkdesc="Includes directory"},
    {checkdir="/incoming/", checkdesc="Incoming files directory"},
    {checkdir="/install/", checkdesc="Installation directory"},
    {checkdir="/intranet/", checkdesc="Intranet directory"},
    {checkdir="/logs/", checkdesc="Log directory"},
    {checkdir="/log.htm", checkdesc="Log file"},
    {checkdir="/login/", checkdesc="Login directory"},
    {checkdir="/mail/", checkdesc="Mail directory"},
    {checkdir="/manual/", checkdesc="Apache manual directory"},
    {checkdir="/phpmyadmin/", checkdesc="phpMyAdmin"},
    {checkdir="/phpMyAdmin/", checkdesc="phpMyAdmin"},
    {checkdir="/test.htm", checkdesc="Test file"},
    {checkdir="/test.html", checkdesc="Test file"},
    {checkdir="/test.asp", checkdesc="Test file"},
    {checkdir="/test.php", checkdesc="Test file"},
    {checkdir="/test.txt", checkdesc="Test file"},
    {checkdir="/test/", checkdesc="Test directory"},
    {checkdir="/webmail/", checkdesc="Webmail directory"},
  }

  -- check that the server supports HEAD (can't always rely on OPTIONS to tell the truth),
  -- otherwise we need to make GET requests from now on.
  -- might be worth checking that the HEAD request doesn't return anything in the body?
  data = http.head( host, port, '/' )
  if data then
    if data.status and tostring( data.status ):match( "302" ) and data.header and data.header.location then
      checkHEAD = "302"
      stdnse.print_debug( "http-enum.nse: Warning: Host returned 302 and not 200 when performing HEAD." )
    end
    if data.status and tostring( data.status ):match( "200" ) and data.header then
      -- check that a body wasn't returned
      if string.len(data.body) > 0 then
        checkHEAD = "xxx" -- fake code because HEAD shouldn't return a body
      else
        checkHEAD = "200"
        stdnse.print_debug( "http-enum.nse: Host supports HEAD, using this to speed up the scan." )
      end
    end
  end

  -- check for 302 or 200 when 404 is expected.
  -- Use GET request as we may need to store the body for comparison
  data = http.get( host, port, '/Nmap404Check' )
  if data then
    if data.status and tostring( data.status ):match( "302" ) and data.header and data.header.location then
      check404 = "302"
      stdnse.print_debug( "http-enum.nse: Host returns 302 instead of 404 File Not Found." )
    end
    if data.status and tostring( data.status ):match( "200" ) and data.header then
      check404 = "200"
      result = result .. "Warning: Host returns 200 instead of 404 File Not Found.\n"
      if data.body then
        check404body = data.body
      end
    end
  end

  if check404:match( "200" ) then
    -- check body for specific text, add confirmation message to result
    for _, combination in pairs (safeURLcheck) do
      all = http.pGet( host, port, combination.checkdir, nil, nil, all )
    end

    local results = http.pipeline(host, port, all, nil)

    for i, data in pairs( results ) do

      if data and data.status and tostring( data.status ):match( "403" ) then
        result = result .. safeURLcheck[i].checkdir .. " " .. safeURLcheck[i].checkdesc .. " (403 Forbidden)\n"
      else
        if data.body and check404body then
          -- compare body and look for matches
          if data.body == check404body then
            -- assume it's another 404 page
          else
            -- assume it's not a 404
            result = result .. safeURLcheck[i].checkdir .. " " .. safeURLcheck[i].checkdesc .. "\n"
          end
        end
      end

    end

  else

    if checkHEAD:match( "200" ) then
      for _, combination in pairs (safeURLcheck) do
        all = http.pHead( host, port, combination.checkdir, nil, nil, all )
      end
    else
      for _, combination in pairs (safeURLcheck) do
        all = http.pGet( host, port, combination.checkdir, nil, nil, all )
      end
    end

    local results = http.pipeline(host, port, all, nil)

    for i, data in pairs( results ) do

      if data and data.status and tostring( data.status ):match( "200" ) then
        result = result .. safeURLcheck[i].checkdir .. " " .. safeURLcheck[i].checkdesc .. "\n"
      end
      if data and data.status and tostring( data.status ):match( "403" ) then
        result = result .. safeURLcheck[i].checkdir .. " " .. safeURLcheck[i].checkdesc .. " (403 Forbidden)\n"
      end
    end

  end

  if string.len(result) > 0 then
    return result
  end

end
