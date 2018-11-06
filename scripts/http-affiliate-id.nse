local http = require "http"
local nmap = require "nmap"
local re = require "re"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local tableaux = require "tableaux"

description = [[
Grabs affiliate network IDs (e.g. Google AdSense or Analytics, Amazon
Associates, etc.) from a web page. These can be used to identify pages
with the same owner.

If there is more than one target using an ID, the postrule of this
script shows the ID along with a list of the targets using it.

Supported IDs:
* Google Analytics
* Google AdSense
* Amazon Associates
]]

---
-- @args http-affiliate-id.url-path The path to request. Defaults to
-- <code>/</code>.
--
-- @usage
-- nmap --script=http-affiliate-id.nse --script-args http-affiliate-id.url-path=/website <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-affiliate-id:
-- |   Amazon Associates ID: XXXX-XX
-- |   Google Adsense ID: pub-YYYY
-- |_  Google Analytics ID: UA-ZZZZ-ZZ
-- Post-scan script results:
-- | http-affiliate-id: Possible related sites
-- | Google Analytics ID: UA-2460010-99 used by:
-- |   thisisphotobomb.memebase.com:80/
-- |   memebase.com:80/
-- | Google Adsense ID: pub-0766144451700556 used by:
-- |   thisisphotobomb.memebase.com:80/
-- |_  memebase.com:80/

author = {"Hani Benhabiles", "Daniel Miller", "Patrick Donnelly"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


-- these are the regular expressions for affiliate IDs
local AFFILIATE_PATTERNS = {
  ["Google Analytics ID"] = re.compile [[{| ({'UA-' [%d]^6 [%d]^-3 '-' [%d][%d]?} / .)* |}]],
  ["Google Adsense ID"] = re.compile [[{| ({'pub-' [%d]^16} / .)* |}]],
  ["Amazon Associates ID"] = re.compile [[
  body <- {| (uri / .)* |}
  uri <- 'http://' ('www.amazon.com/' ([\?&;] 'tag=' tag / [^"'])*) / ('rcm.amazon.com/' ([\?&;] 't=' tag / [^"'])*)
  tag <- {[%w]+ '-' [%d]+}
]],
}

local URL_SHORTENERS = {
  ["amzn.to"] = re.compile [[{| ( 'http://' ('www.')? 'amzn.to' {'/' ([%a%d])+ } / .)*|}]]
}


portrule = shortport.http

postrule = function() return (nmap.registry["http-affiliate-id"] ~= nil) end

--- put id in the nmap registry for usage by other scripts
--@param host nmap host table
--@param port nmap port table
--@param affid affiliate id table
local add_key_to_registry = function(host, port, path, affid)
  local site = host.targetname or host.ip
  site = site .. ":" .. port.number .. path
  nmap.registry["http-affiliate-id"] = nmap.registry["http-affiliate-id"] or {}

  nmap.registry["http-affiliate-id"][site] = nmap.registry["http-affiliate-id"][site] or {}
  table.insert(nmap.registry["http-affiliate-id"][site], affid)
end

portaction = function(host, port)
  local result = {}
  local url_path = stdnse.get_script_args("http-affiliate-id.url-path") or "/"
  local body = http.get(host, port, url_path).body

  if ( not(body) ) then
    return
  end

  local followed = {}

  for shortener, pattern in pairs(URL_SHORTENERS) do
    for i, shortened in ipairs(pattern:match(body)) do
      stdnse.debug1("Found shortened Url: " .. shortened)
      local response = http.get(shortener, 80, shortened)
      stdnse.debug1("status code: %d", response.status)
      if (response.status == 301 or response.status == 302) and response.header['location'] then
        followed[#followed + 1] = response.header['location']
      end
    end
  end
  followed = table.concat(followed, "\n")

  -- Here goes affiliate matching
  for name, pattern in pairs(AFFILIATE_PATTERNS) do
    local ids = {}
    for i, id in ipairs(pattern:match(body..followed)) do
      if not ids[id] then
        result[#result + 1] = name .. ": " .. id
        stdnse.debug1("found id:" .. result[#result])
        add_key_to_registry(host, port, url_path, result[#result])
        ids[id] = true
      end
    end
  end

  return stdnse.format_output(true, result)
end

--- iterate over the list of gathered ids and look for related sites (sharing the same siteids)
local function postaction()
  local siteids = {}
  local output = {}

  -- create a reverse mapping affiliate ids -> site(s)
  for site, ids in pairs(nmap.registry["http-affiliate-id"]) do
    for _, id in ipairs(ids) do
      if not siteids[id] then
        siteids[id] = {}
      end
      -- discard duplicate IPs
      if not tableaux.contains(siteids[id], site) then
        table.insert(siteids[id], site)
      end
    end
  end

  -- look for sites using the same affiliate id
  for id, sites in pairs(siteids) do
    if #siteids[id] > 1 then
      local str = id .. ' used by:'
      for _, site in ipairs(siteids[id]) do
        str = str .. '\n  ' .. site
      end
      table.insert(output, str)
    end
  end

  if #output > 0 then
    return 'Possible related sites\n' .. table.concat(output, '\n')
  end
end

local ActionsTable = {
  -- portrule: get affiliate ids
  portrule = portaction,
  -- postrule: look for related sites (same affiliate ids)
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
