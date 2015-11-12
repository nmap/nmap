description = [[
Checks if various crawling utilities are allowed by the host.
]]

---
-- @usage nmap -p80 --script http-useragent-tester.nse <host>
--
-- This script sets various User-Agent headers that are used by different
-- utilities and crawling libraries (for example CURL or wget). If the request is
-- redirected to a page different than a (valid) browser request would be, that
-- means that this utility is banned.
--
-- @args http-useragent-tester.useragents A table with more User-Agent headers.
--       Default: nil
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-useragent-tester:
-- |
-- |     Allowed User Agents:
-- |
-- |     lwp-trivial
-- |     PHP/
-- |     Python-urllib/2.5
-- |     GT::WWW
-- |     Snoopy
-- |     MFC_Tear_Sample
-- |     HTTP::Lite
-- |     PHPCrawl
-- |     URI::Fetch
-- |     Zend_Http_Client
-- |     http client
-- |     PECL::HTTP
-- |     WWW-Mechanize/1.34
-- |
-- |     Forbidden User Agents:
-- |
-- |     libwww redirected to: https://www.some-random-page.com/unsupportedbrowser (different host)
-- |     libcurl-agent/1.0 redirected to: https://www.some-random-page.com/unsupportedbrowser (different host)
-- |_    Wget/1.13.4 (linux-gnu) redirected to: https://www.some-random-page.com/unsupportedbrowser (different host)
--
---

categories = {"discovery", "safe"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local target = require "target"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

getLastLoc = function(host, port, useragent)

  local options

  options = {header={}, no_cache=true, bypass_cache=true, redirect_ok=function(host,port)
      local c = 3
      return function(url)
        if ( c==0 ) then return false end
        c = c - 1
        return true
      end
  end }


  options['header']['User-Agent'] = useragent

  stdnse.debug2("Making a request with User-Agent: " .. useragent)

  local response = http.get(host, port, '/', options)

  if response.location then
    return response.location[#response.location] or false
  end

  return false

end

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)

  local moreagents = stdnse.get_script_args("http-useragent-tester.useragents") or nil
  local newtargets = stdnse.get_script_args("newtargets") or nil

  -- We don't crawl any site. We initialize a crawler to use its iswithinhost method.
  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME } )

  local HTTPlibs = {
    http.USER_AGENT,
    "libwww",
    "lwp-trivial",
    "libcurl-agent/1.0",
    "PHP/",
    "Python-urllib/2.5",
    "GT::WWW",
    "Snoopy",
    "MFC_Tear_Sample",
    "HTTP::Lite",
    "PHPCrawl",
    "URI::Fetch",
    "Zend_Http_Client",
    "http client",
    "PECL::HTTP",
    "Wget/1.13.4 (linux-gnu)",
    "WWW-Mechanize/1.34"
  }

  if moreagents then
    for _, l in ipairs(moreagents) do
      table.insert(HTTPlibs, l)
    end
  end

  -- We perform a normal browser request and get the returned location
  local loc = getLastLoc(host, port, "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17")

  local allowed, forb = {}, {}

  for _, l in ipairs(HTTPlibs) do

    local libloc = getLastLoc(host, port, l)

    -- If the library's request returned a different location, that means the request was redirected somewhere else, hence is forbidden.
    if loc ~= libloc then
      local msg = l .. " redirected to: " .. libloc
      local libhost = http.parse_url(libloc)
      if not crawler:iswithinhost(libhost.host) then
        msg = msg .. " (different host)"
        if newtargets then
          target.add(libhost.host)
        end
      end
      table.insert(forb, msg)
    else
      table.insert(allowed, l)
    end

  end

  if next(allowed) ~= nil then
    table.insert(allowed, 1, "Allowed User Agents:")
  end

  if next(forb) ~= nil then
    table.insert(forb, 1, "Forbidden User Agents:")
  end

  return {allowed, forb}

end
