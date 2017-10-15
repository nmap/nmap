description = [[
Checks if the website holds a mobile version.
]]

---
-- @usage nmap -p80 --script http-mobileversion-checker.nse <host>
--
-- This script sets an Android User-Agent header and checks if the request
-- will be redirected to a page different than a (valid) browser request
-- would be. If so, this page is most likely to be a mobile version of the
-- app.
--
-- @args newtargets If this is set, add any newly discovered hosts to nmap
--                  scanning queue. Default: nil
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- |_ http-mobileversion-checker: Found mobile version: https://m.some-very-random-website.com (Redirected to a different host)
--
-- @see http-useragent-tester.nse

categories = {"discovery", "safe"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local target = require "target"
local shortport = require "shortport"
local httpspider = require "httpspider"
local stdnse = require "stdnse"
local url = require "url"

getLastLoc = function(host, port, useragent)

  local options

  options = {header={}, no_cache=true, redirect_ok=function(host,port)
      local c = 3
      return function(url)
        if ( c==0 ) then return false end
        c = c - 1
        return true
      end
  end }


  options['header']['User-Agent'] = useragent

  local response = http.get(host, port, '/', options)

  if response.location then
    return response.location[#response.location] or false
  end

  return false

end

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)

  local newtargets = stdnse.get_script_args("newtargets") or nil

  -- We don't crawl any site. We initialize a crawler to use its iswithinhost method.
  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME } )

  local loc = getLastLoc(host, port, "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17")
  local mobloc = getLastLoc(host, port, "Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")

  -- If the mobile browser request is redirected to a different page, that must be the mobile version's page.
  if loc ~= mobloc then
    local msg = "Found mobile version: " .. mobloc
    local mobhost = url.parse(mobloc)
    if not crawler:iswithinhost(mobhost.host) then
      msg = msg .. " (Redirected to a different host)"
      if newtargets then
        target.add(mobhost.host)
      end
    end
    return msg
  end

  return "No mobile version detected."

end
