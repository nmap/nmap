local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description = [[
Shows the title of the default page of a web server.

The script will follow no more than one HTTP redirect, and only if the
redirection leads to the same host. The script may send a DNS query to
determine whether the host the redirect leads to has the same IP address as the
original target.
]]

---
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


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

  local data, result, redir, title

  data = http.get( host, port, '/' )

  -- check for a redirect
  if data.location then
    if data.status and tostring( data.status ):match( "30%d" ) then
      redir = ("Did not follow redirect to %s"):format( data.location[#data.location] )
    else
      redir = ("Requested resource was %s"):format( data.location[#data.location] )
    end
  end

  -- check that body was received
  if data.body and data.body ~= "" then
    result = data.body
  else
    -- debug msg and no output; or no debug msg and some output if we were redirected.
    if not redir then stdnse.print_debug( "http-title.nse: %s did not respond with any data.", host.targetname or host.ip ) end
    return (redir and ("%s and no page was returned."):format( redir )) or nil
  end

  -- try and match title tags
  title = string.match(result, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

  if title and title ~= "" then
    result = string.gsub(title , "[\n\r\t]", "")
    if #title > 65 then
      stdnse.print_debug("http-title.nse: (%s) Title got truncated!", host.targetname or host.ip );
      result = string.sub(result, 1, 62) .. "..."
    end
  else
    result = ("Site doesn't have a title%s"):format( ( data.header and data.header["content-type"] and (" (%s)."):format( data.header["content-type"] ) ) or ".")
  end

  return (redir and ("%s\n%s"):format( result, redir )) or result

end
