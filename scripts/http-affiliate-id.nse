local http = require "http"
local nmap = require "nmap"
local pcre = require "pcre"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

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

author = "Hani Benhabiles, Daniel Miller"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


-- these are the regular expressions for affiliate IDs
local AFFILIATE_PATTERNS = {
	["Google Analytics ID"] = "(?P<id>UA-[0-9]{6,9}-[0-9]{1,2})",
	["Google Adsense ID"] = "(?P<id>pub-[0-9]{16,16})",
	["Amazon Associates ID"] = "http://(www%.amazon%.com/[^\"']*[\\?&;]tag|rcm%.amazon%.com/[^\"']*[\\?&;]t)=(?P<id>\\w+-\\d+)",
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

--- check for the presence of a value in a table
--@param tab the table to search into
--@param item the searched value
--@return a boolean indicating whether the value has been found or not
local function contains(tab, item)
	for _, val in pairs(tab) do
		if val == item then
			return true
		end
	end
	return false
end

portaction = function(host, port)
	local result = {}
	local url_path = stdnse.get_script_args("http-affiliate-id.url-path") or "/"
	local body = http.get(host, port, url_path).body

	if ( not(body) ) then
		return
	end

	-- Here goes affiliate matching
	for name, re in pairs(AFFILIATE_PATTERNS) do
		local regex = pcre.new(re, 0, "C")
		local limit, limit2, matches = regex:match(body)
		if limit ~= nil then
			local affiliateid = matches["id"]
			result[#result + 1] = name .. ": " .. affiliateid
			add_key_to_registry(host, port, url_path, result[#result])
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
			if not contains(siteids[id], site) then
				table.insert(siteids[id], site)
			end
		end
	end

	-- look for sites using the same affiliate id
	for id, sites in pairs(siteids) do
		if #siteids[id] > 1 then
			local str = id .. ' used by:'
			for _, site in ipairs(siteids[id]) do
				str = str .. '\n	' .. site
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
