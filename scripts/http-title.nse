description = [[
Shows the title of the default page of a web server.

The script will follow no more than one HTTP redirect, and only if the
redirection leads to the same host. The script may send a DNS query to
determine whether the host the redirect leads to has the same IP address as the
original target.
]]

---
--@output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_ http-title.nse: Go ahead and ScanMe!

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

local url    = require 'url'
local dns    = require 'dns'
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

  local data, result, redir, title, loc

  data = http.get( host, port, '/' )

  -- check for a redirect
  if data and data.status and tostring( data.status ):match( "30%d" ) and data.header and data.header.location then
    redir = ("Did not follow redirect to %s"):format( data.header.location )
    local url = url.parse( data.header.location )
    local loc = redirect_ok( url, host, port )
    if loc then
      -- follow redirect
      redir = ("Requested resource was %s://%s%s%s"):format( url.scheme or port.service, loc.host, (url.port and (":%s"):format(url.port)) or "", loc.path )
      data = http.get( loc.host, loc.port, loc.path )
    else
      loc = nil -- killed so we know we didn't follow a redirect
    end
  end

  -- check that body was received
  if data.body and data.body ~= "" then
    result = data.body
  else
    -- debug msg and no output; or no debug msg and some output if we were redirected.
    if not redir then stdnse.print_debug( "http-title.nse: %s did not respond with any data.", host.targetname or host.ip ) end
    return (redir and ("%s %s no page was returned."):format( redir, (loc and ", but") or "and" )) or nil
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


-- Check if the given URL is okay to redirect to. Return a table with keys
-- "host", "port", and "path" if okay, nil otherwise.
function redirect_ok(url, host, port)
  -- A battery of tests a URL is subjected to in order to decide if it may be
  -- redirected to. They incrementally fill in loc.host, loc.port, and loc.path.
  local rules = {
    function (loc, url, host, port)
      -- bail if userinfo is present
      return ( url.userinfo and false ) or true
    end,

    function (loc, url, host, port)
      -- if present, url.host must be the same scanned target
      -- loc.host must be set if returning true
      if not url.host then
        loc.host = ( host.targetname or host.ip )
        return true
      end
      if url.host and
      url.host == host.ip or
      url.host == host.targetname or
      url.host == ( host.name ~= '' and host.name ) or
      is_vhost( url.host, host ) then -- dns lookup as last resort
        loc.host = url.host
        return true
      end
      return false
    end,

    function (loc, url, host, port)
      -- if present, url.port must be the same as the scanned port
      -- loc.port must be set if returning true
      if (not url.port) or tonumber(url.port) == port.number then
        loc.port = port
        return true
      end
      return false
    end,

    function (loc, url, host, port)
      -- if url.scheme is present then it must match the scanned port
      if url.scheme and url.port then return true end
      if url.scheme and url.scheme ~= port.service then return false end
      return true
    end,

    function (loc, url, host, port)
      -- path cannot be unchanged unless host has changed
      -- loc.path must be set if returning true
      if ( not url.path or url.path == "/" ) and url.host == ( host.targetname or host.ip) then return false end
      if not url.path then loc.path = "/"; return true end
      loc.path = ( ( url.path:sub(1,1) == "/" and "" ) or "/" ) .. url.path -- ensuring leading slash
      return true
    end,

    function (loc, url, host, port)
      -- always true - jut add the query to loc.path
      if url.query then loc.path = ("%s?%s"):format( loc.path, url.query ) end
      return true
    end
  }

  local loc = {}
  for i, rule in ipairs( rules ) do
    if not rule( loc, url, host, port ) then return nil end
  end

  if loc.host and loc.port and loc.path then
    return loc
  else
    return nil
  end
end

function is_vhost( rhost, host )

  -- query is sane?
  if rhost:match( ":" ) or rhost:match( "^[%d%.]+$" ) then
    return false
  end

  local opts = {}
  opts.dtype = "A"
  opts.retAll = true
  if host.ip:match( ":" ) then opts.dtype = "AAAA" end

  local status, answer = dns.query( rhost, opts )

  if not status then
    stdnse.print_debug( "http-title.nse: DNS query failed for target %s.  Query was: %s. Error: %s", host.targetname or host.ip, rhost, answer or "nil" )
    return false
  end

  for i, ip_rec in ipairs( answer ) do
    if ipOps.compare_ip( ip_rec, "eq", host.ip ) then
      return true
    end
  end

  return false
end
