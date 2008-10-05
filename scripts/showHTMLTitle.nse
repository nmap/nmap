---
--@output
-- 80/tcp  open   http    syn-ack\n
-- |_ HTML title: Foo.\n
--@copyright Same as Nmap--See http://nmap.org/book/man-legal.html

id = "HTML title"

description = "Connects to an HTTP server and extracts the title of the default page."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "demo", "safe"}

local url    = require 'url'
local dns    = require 'dns'
local http   = require 'http'
local ipOps  = require 'ipOps'
local stdnse = require 'stdnse'

portrule = function(host, port)
	if not (port.service == 'http' or port.service == 'https') then
		return false
	end
	-- Don't bother running on SSL ports if we don't have SSL.
	if (port.service == 'https' or port.version.service_tunnel == 'ssl')
		and not nmap.have_ssl() then
		return false
	end
	return true
end

action = function(host, port)

  local data, result, redir, title

  data = http.get( host, port, '/' )

  -- check for a redirect
  if data and data.status and tostring( data.status ):match( "30%d" ) and data.header and data.header.location then
    redir = ("Did not follow redirect to %s"):format( data.header.location )
    local url = url.parse( data.header.location )
    local loc = {}
    -- test the redirect to see if we're allowed to go there
    for i, rule in ipairs( rules ) do
      if not rule( loc, url, host, port ) then break end
    end
    -- follow redirect
    if loc.host and loc.port and loc.path then
      redir = ("Requested resource was %s://%s%s"):format( url.scheme or port.service, loc.host, loc.path )
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
    if not redir then stdnse.print_debug( "showHTMLTitle.nse: %s did not respond with any data.", host.targetname or host.ip ) end
    return (redir and ("%s %s no page was returned."):format( redir, (loc and ", but") or "and" )) or nil
  end

  -- try and match title tags
  title = string.match(result, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

  if title and title ~= "" then
    result = string.gsub(title , "[\n\r\t]", "")
    if string.len(title) > 65 then
      stdnse.print_debug("showHTMLTitle.nse: (%s) Title got truncated!", host.targetname or host.ip );
      result = string.sub(result, 1, 62) .. "..."
    end
  else
    result = ("Site doesn't have a title%s"):format( ( data.header and data.header["content-type"] and (" (%s)."):format( data.header["content-type"] ) ) or ".")
  end

  return (redir and ("%s\n%s"):format( result, redir )) or result

end



rules = {
          function (loc, url, host, port)
            -- if url.scheme is present then it must match the scanned port
            if url.scheme and url.scheme ~= port.service then return false end
            return true
          end,

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
            if (not url.port) or url.port == port.number then
              loc.port = port
              return true
            end
            return false
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


function is_vhost( rhost, host )

  -- query is sane?
  if rhost:match( ":" ) or rhost:match( "^[%d%.]+$" ) then
    return false
  end

  local opts = {}
  opts.dtype = "A"
  opts.retAll = true
  if host.ip:match( ":" ) then opts.dtype = "AAAA" end

  local answer, msg = dns.query( rhost, opts )

  if not answer then
    stdnse.print_debug( "showHTMLTitle: DNS query failed for target %s.  Query was: %s. Error Code: %s", host.targetname or host.ip, rhost, msg or "nil" )
    return false
  end

  for i, ip_rec in ipairs( answer ) do
    if ipOps.compare_ip( ip_rec, "eq", host.ip ) then
      return true
    end
  end

  return false
end
