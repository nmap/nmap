local http = require "http"
local httpspider = require "httpspider"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[
Spiders a web site to find web pages requiring form-based or HTTP-based authentication. The results are returned in a table with each url and the
detected method.
]]

---
-- @usage
-- nmap -p 80 --script http-auth-finder <ip>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-auth-finder:
-- |   url                                   method
-- |   http://192.168.1.162/auth1/index.html  HTTP: Basic, Digest, Negotiate
-- |_  http://192.168.1.162/auth2/index.html  FORM
--
-- @args http-auth-finder.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-auth-finder.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-auth-finder.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-auth-finder.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-auth-finder.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http

local function parseAuthentication(resp)
  local www_authenticate = resp.header["www-authenticate"]
  if ( not(www_authenticate) ) then
    return false, "Server returned no authentication headers."
  end

  local challenges = http.parse_www_authenticate(www_authenticate)
  if ( not(challenges) ) then
    return false, ("Authentication header (%s) could not be parsed."):format(www_authenticate)
  end
  return true, challenges
end


action = function(host, port)

  -- create a new crawler instance
  local crawler = httpspider.Crawler:new( host, port, nil, { scriptname = SCRIPT_NAME } )

  if ( not(crawler) ) then
    return
  end

  -- create a table entry in the registry
  nmap.registry.auth_urls = nmap.registry.auth_urls or {}
  crawler:set_timeout(10000)

  local auth_urls = tab.new(2)
  tab.addrow(auth_urls, "url", "method")
  while(true) do
    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    -- HTTP-based authentication
    if ( r.response.status == 401 ) then
      local status, auth = parseAuthentication(r.response)
      if ( status ) then
        local schemes = {}
        for _, item in ipairs(auth) do
          if ( item.scheme ) then
            table.insert(schemes, item.scheme)
          end
        end
        tab.addrow(auth_urls, r.url, ("HTTP: %s"):format(stdnse.strjoin(", ", schemes)))
      else
        tab.addrow(auth_urls, r.url, ("HTTP: %s"):format(auth))
      end
      nmap.registry.auth_urls[r.url] = "HTTP"
    -- FORM-based authentication
    elseif r.response.body then
      -- attempt to detect a password input form field
      if ( r.response.body:match("<[Ii][Nn][Pp][Uu][Tt].-[Tt][Yy][Pp][Ee]%s*=\"*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]") ) then
        tab.addrow(auth_urls, r.url, "FORM")
        nmap.registry.auth_urls[r.url] = "FORM"
      end
    end
  end
  if ( #auth_urls > 1 ) then
    local result = { tab.dump(auth_urls) }
    result.name = crawler:getLimitations()
    return stdnse.format_output(true, result)
  end
end
