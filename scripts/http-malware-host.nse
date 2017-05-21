local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Looks for signature of known server compromises.

Currently, the only signature it looks for is the one discussed here:
http://blog.unmaskparasites.com/2009/09/11/dynamic-dns-and-botnet-of-zombie-web-servers/.
This is done by requesting the page <code>/ts/in.cgi?open2</code> and
looking for an errant 302 (it attempts to detect servers that always
return 302). Thanks to Denis from the above link for finding this
technique!
]]

---
--@output
-- Interesting ports on www.sopharma.bg (84.242.167.49):
-- PORT     STATE SERVICE    REASON
-- 80/tcp   open  http       syn-ack
-- |_ http-malware-host: Host appears to be clean
-- 8080/tcp open  http-proxy syn-ack
-- | http-malware-host:
-- |   Host appears to be infected (/ts/in.cgi?open2 redirects to http://last-another-life.ru:8080/index.php)
-- |_  See: http://blog.unmaskparasites.com/2009/09/11/dynamic-dns-and-botnet-of-zombie-web-servers/
--

author = "Ron Bowes"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"malware", "safe"}


portrule = shortport.http

action = function(host, port)
  -- Check what response we get for a 404
  local result, result_404, known_404 = http.identify_404(host, port)
  if(result == false) then
    return stdnse.format_output(false, "Couldn't identify 404 message: " .. result_404)
  end

  -- If the 404 result is a 302, we're going to have trouble
  if(result_404 == 302) then
    return stdnse.format_output(false, "Unknown pages return a 302 response; unable to check")
  end

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the test
  if ( result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return false
  end

  -- Perform a GET request on the file
  result = http.get_url("http://" .. host.ip .. ":" .. port.number .. "/ts/in.cgi?open2")
  if(not(result)) then
    return stdnse.format_output(false, "Couldn't perform GET request")
  end

  if(result.status == 302) then
    local response = {}
    if(result.header.location) then
      table.insert(response, string.format("Host appears to be infected (/ts/in.cgi?open2 redirects to %s)", result.header.location))
    else
      table.insert(response, "Host appears to be infected (/ts/in.cgi?open2 return a redirect")
    end
    table.insert(response, "See: http://blog.unmaskparasites.com/2009/09/11/dynamic-dns-and-botnet-of-zombie-web-servers/")
    return stdnse.format_output(true, response)
  end

  -- Not infected
  if(nmap.verbosity() > 0) then
    return "Host appears to be clean"
  else
    return nil
  end
end
