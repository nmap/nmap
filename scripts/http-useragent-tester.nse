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
-- |   Status for browser useragent: 200
-- |   Redirected To: https://www.example.com/
-- |   Allowed User Agents:
-- |     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
-- |     libwww
-- |     lwp-trivial
-- |     libcurl-agent/1.0
-- |     PHP/
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
-- |   Change in Status Code:
-- |     Python-urllib/2.5: 403
-- |_    Wget/1.13.4 (linux-gnu): 403
--
-- @xmloutput
-- <elem key="Status for browser useragent">200</elem>
-- <elem key="Redirected To">https://www.example.com/</elem>
-- <table key="Allowed User Agents">
--   <elem>Mozilla/5.0 (compatible; Nmap Scripting Engine;
--   https://nmap.org/book/nse.html)</elem>
--   <elem>libwww</elem>
--   <elem>lwp-trivial</elem>
--   <elem>libcurl-agent/1.0</elem>
--   <elem>PHP/</elem>
--   <elem>GT::WWW</elem>
--   <elem>Snoopy</elem>
--   <elem>MFC_Tear_Sample</elem>
--   <elem>HTTP::Lite</elem>
--   <elem>PHPCrawl</elem>
--   <elem>URI::Fetch</elem>
--   <elem>Zend_Http_Client</elem>
--   <elem>http client</elem>
--   <elem>PECL::HTTP</elem>
--   <elem>WWW-Mechanize/1.34</elem>
-- </table>
-- <table key="Change in Status Code">
--   <elem key="Python-urllib/2.5">403</elem>
--   <elem key="Wget/1.13.4 (linux-gnu)">403</elem>
-- </table>
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
local url = require "url"

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
    return response.location[#response.location],response.status or false, response.status
  end

  return false, response.status

end

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)

  local moreagents = stdnse.get_script_args("http-useragent-tester.useragents") or nil
  local newtargets = stdnse.get_script_args("newtargets") or nil
  local output = stdnse.output_table()

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
  local loc, status = getLastLoc(host, port, "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17")
  output['Status for browser useragent'] = status

  if loc then
    output['Redirected To'] = loc
  end

  local allowed, forb, status_changed = {}, {}, {}

  for _, l in ipairs(HTTPlibs) do

    local libloc, libstatus = getLastLoc(host, port, l)

    -- If the library's request returned a different location, that means the request was redirected somewhere else, hence is forbidden.
    if libloc and loc ~= libloc then
      forb[l] = {}
      local libhost = url.parse(libloc)
      if not crawler:iswithinhost(libhost.host) then
        forb[l]['Different Host'] = tostring(libloc)
        if newtargets then
          target.add(libhost.host)
        end
      else
        forb[l]['Same Host'] = tostring(libloc)
      end
    elseif status ~= libstatus then
      status_changed[l] = libstatus
    else
      table.insert(allowed, l)
    end

  end

  if next(allowed) ~= nil then
    output['Allowed User Agents'] = allowed
  end

  if next(forb) ~= nil then
    output['Forbidden/Redirected User Agents'] = forb
  end

  if next(status_changed) ~= nil then
    output['Change in Status Code'] = status_changed
  end

  return output

end
