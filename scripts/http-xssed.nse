description = [[
This script searches the xssed.com database and outputs the result.
]]

---
-- @usage nmap -p80 --script http-xssed.nse <target>
--
-- This script will search the xssed.com database and it will output any
-- results. xssed.com is the largest online archive of XSS vulnerable
-- websites.
--
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-xssed:
-- |   xssed.com found the following previously reported XSS vulnerabilities marked as unfixed:
-- |
-- |     /redirect/links.aspx?page=http://xssed.com
-- |
-- |     /derefer.php?url=http://xssed.com/
-- |
-- |   xssed.com found the following previously reported XSS vulnerabilities marked as fixed:
-- |
-- |_    /myBook/myregion.php?targetUrl=javascript:alert(1);
--
-- @see http-stored-xss.nse
-- @see http-dombased-xss.nse
-- @see http-phpself-xss.nse

author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "external", "discovery"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local string = require "string"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local XSSED_SITE = "xssed.com"
local XSSED_SEARCH = "/search?key="
local XSSED_FOUND = "<b>XSS:</b>"
local XSSED_FIXED = "<img src='http://data.xssed.org/images/fixed.gif'>&nbsp;FIXED</th>"
local XSSED_MIRROR = "<a href='(/mirror/%d+/)' target='_blank'>"
local XSSED_URL = "URL: ([^%s]+)</th>"

action = function(host, port)

  local fixed, unfixed

  local target = XSSED_SEARCH .. (host.targetname or host.name or host.ip)

  -- Only one instantiation of the script should ping xssed at once.
  local mutex = nmap.mutex("http-xssed")
  mutex "lock"

  local response = http.get(XSSED_SITE, 80, target, {any_af=true})

  if string.find(response.body, XSSED_FOUND) then
    fixed = {}
    unfixed = {}
    for m in string.gmatch(response.body, XSSED_MIRROR) do
      local mirror = http.get(XSSED_SITE, 80, m, {any_af=true})
      for v in string.gmatch(mirror.body, XSSED_URL) do
        if string.find(mirror.body, XSSED_FIXED) then
          table.insert(fixed, "\t" .. v .. "\n")
        else
          table.insert(unfixed, "\t" ..  v .. "\n")
        end
      end
    end
  end

  mutex "done"

  -- Fix the output.
  if not fixed and not unfixed then
    return "No previously reported XSS vuln."
  end

  if next(unfixed) ~= nil then
    table.insert(unfixed, 1, "UNFIXED XSS vuln.\n")
  end

  if next(fixed) ~= nil then
    table.insert(fixed, 1, "FIXED XSS vuln.\n")
  end

  return {unfixed, fixed}

end
