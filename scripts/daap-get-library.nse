local bin = require "bin"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves a list of music from a DAAP server. The list includes artist
names and album and song titles.

Output will be capped to 100 items if not otherwise specified in the
<code>daap_item_limit</code> script argument. A
<code>daap_item_limit</code> below zero outputs the complete contents of
the DAAP library.

Based on documentation found here:
http://www.tapjam.net/daap/.
]]

---
-- @args daap_item_limit Changes the output limit from 100 songs. If set to a negative value, no limit is enforced.
--
-- @output
-- | daap-get-library:  
-- |   BUBBA|TWO
-- |     Fever Ray
-- |       Fever Ray (Deluxe Edition)
-- |         Concrete Walls
-- |         I'm Not Done
-- |         Here Before
-- |         Now's The Only Time I Know
-- |         Stranger Than Kindness
-- |         Dry And Dusty
-- |         Keep The Streets Empty For Me
-- |         Triangle Walks
-- |         If I Had A Heart
-- |         Seven
-- |         When I Grow Up
-- |_        Coconut

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


-- Version 0.2
-- Created 01/14/2010 - v0.1 - created by Patrik Karlsson
-- Revised 01/23/2010 - v0.2 - changed to port_or_service, added link to documentation, limited output to 100 songs or to daap_item_limit script argument.

portrule = shortport.port_or_service(3689, "daap")

--- Gets the name of the library from the server
--
-- @param host table containing an ip field. 
-- @param port table containing number and protocol fields. 
-- @return string containing the name of the library
function getLibraryName( host, port )
	local _, libname, pos
	local url = "daap://" .. host.ip .. "/server-info"
	local response = http.get( host, port, url, nil, nil, nil)

	if response == nil or response.body == nil or response.body=="" then
		return
	end
		
	pos = string.find(response.body, "minm")

	if pos > 0 then
	  local len
		pos = pos + 4
		pos, len = bin.unpack( ">I", response.body, pos )
		pos, libname = bin.unpack( "A" .. len, response.body, pos )
	end
	
	return libname
end

--- Reads the first item value specified by name 
--
-- @param data string containing the unparsed item
-- @param name string containing the name of the value to read
-- @return number 
local function getAttributeAsInt( data, name )

	local pos = string.find(data, name)
	local attrib
	
	if pos and pos > 0 then
		pos = pos + 4
		local len
		pos, len = bin.unpack( ">I", data, pos )
		
		if ( len ~= 4 ) then
			stdnse.print_debug( string.format("Unexpected length returned: %d", len ) )
			return
		end
		
		pos, attrib = bin.unpack( ">I", data, pos )
	end
	
	return attrib
	
end

--- Gets the revision number for the library
--
-- @param host table containing an ip field. 
-- @param port table containing number and protocol fields. 
-- @return number containing the session identity received from the server
function getSessionId( host, port )

	local _, sessionid
	local response = http.get( host, port, "/login", nil, nil, nil )
	
	if response ~= nil then
		sessionid = getAttributeAsInt( response.body, "mlid")	
	end
	
	return sessionid
end

--- Gets the revision number for the library
--
-- @param host table containing an ip field. 
-- @param port table containing number and protocol fields. 
-- @param sessionid number containing session identifier from <code>getSessionId</code>
-- @return number containing the revision number for the library
function getRevisionNumber( host, port, sessionid )
	local url = "/update?session-id=" .. sessionid .. "&revision-number=1"
	local _, revision
	local response = http.get( host, port, url, nil, nil, nil )
	
	if response ~= nil then
		revision = getAttributeAsInt( response.body, "musr")
	end
	
	return revision	
end

--- Gets the database identitity for the library
--
-- @param host table containing an ip field. 
-- @param port table containing number and protocol fields. 
-- @param sessionid number containing session identifier from <code>getSessionId</code>
-- @param revid number containing the revision id as retrieved from <code>getRevisionNumber</code>
function getDatabaseId( host, port, sessionid, revid )
	local url = "/databases?session-id=" .. sessionid .. "&revision-number=" .. revid
	local response = http.get( host, port, url, nil, nil, nil )
	local miid
	
	if response ~= nil then
		miid = getAttributeAsInt( response.body, "miid")
	end
	
	return miid	
end

--- Gets a string item type from data
--
-- @param data string starting with the 4-bytes of length
-- @param pos number containing offset into data
-- @return pos number containing new position after reading string
-- @return value string containing the string item that was read
local function getStringItem( data, pos )
	local len
	
	pos, len = bin.unpack(">I", data, pos)
	
	if ( len > 0 ) then
		return bin.unpack( "A"..len, data, pos )
	end
	
end

local itemFetcher = {}

itemFetcher["mikd"] = function( data, pos )	return getStringItem( data, pos ) end
itemFetcher["miid"] = itemFetcher["mikd"]
itemFetcher["minm"] = itemFetcher["mikd"]
itemFetcher["asal"] = itemFetcher["mikd"]
itemFetcher["asar"] = itemFetcher["mikd"]

--- Parses a single item (mlit)
--
-- @param data string containing the unparsed item starting at the first available tag
-- @param len number containing the length of the item
-- @return item table containing <code>mikd</code>, <code>miid</code>, <code>minm</code>, 
-- <code>asal</code> and <code>asar</code> when available
parseItem = function( data, len )

	local pos, name, value = 1, nil, nil
	local item = {}
	
	while( len - pos > 0 ) do
		pos, name = bin.unpack( "A4", data, pos )
		
		if itemFetcher[name] then
			pos, item[name] = itemFetcher[name](data, pos )
		else
			stdnse.print_debug( string.format("No itemfetcher for: %s", name) )
			break
		end

	end
	
	return item
	
end

--- Request and process all music items
--
-- @param host table containing an ip field. 
-- @param port table containing number and protocol fields. 
-- @param sessionid number containing session identifier from <code>getSessionId</code>
-- @param dbid number containing database id from <code>getDatabaseId</code>
-- @param limit number containing the maximum amount of songs to return
-- @return table containing the following structure [artist][album][songs]
function getItems( host, port, sessionid, revid, dbid, limit )
	local meta = "dmap.itemid,dmap.itemname,dmap.itemkind,daap.songalbum,daap.songartist"
	local url = "/databases/" .. dbid .. "/items?type=music&meta=" .. meta .. "&session-id=" .. sessionid .. "&revision-number=" .. revid
	local response = http.get( host, port, url, nil, nil, nil )
	local item, data, pos, len
	local items = {}
	local limit = limit or -1

	if response == nil then
		return
	end
	
	-- get our position to the list of items
	pos = string.find(response.body, "mlcl")
	pos = pos + 4
	
	while ( pos > 0 and pos + 8 < response.body:len() ) do

		-- find the next single item
		pos = string.find(response.body, "mlit", pos)		
		pos = pos + 4
		
		pos, len = bin.unpack( ">I", response.body, pos )
		
		if ( pos < response.body:len() and pos + len < response.body:len() ) then
			pos, data = bin.unpack( "A" .. len, response.body, pos )
		else
			break
		end

		-- parse a single item
		item = parseItem( data, len )
		
		local album = item.asal or "unknown"
		local artist= item.asar or "unknown"
		local song  = item.minm or ""
		
		if items[artist] == nil then
			items[artist] = {}
		end
		
		if items[artist][album] == nil then
			items[artist][album] = {}
		end
		
		if limit == 0 then
			break
		elseif limit > 0 then
			limit = limit - 1
		end
		
		table.insert( items[artist][album], song )

	end


	return items
	
end


action = function(host, port)
	
	local limit = tonumber(nmap.registry.args.daap_item_limit) or 100
	local libname = getLibraryName( host, port )	
	
	if libname == nil then
		return
	end
	
	local sessionid = getSessionId( host, port )	

	if sessionid == nil then
		return stdnse.format_output(true, "Libname: " .. libname)
	end

	local revid = getRevisionNumber( host, port, sessionid )

	if revid == nil then
		return stdnse.format_output(true, "Libname: " .. libname)
	end

	local dbid = getDatabaseId( host, port, sessionid, revid )

	if dbid == nil then
		return
	end

	local items = getItems( host, port, sessionid, revid, dbid, limit )

	if items == nil then
		return
	end

	local albums, songs, artists, results = {}, {}, {}, {}

	table.insert( results, libname )

	for artist, v in pairs(items) do
		albums = {}
		for album, v2 in pairs(v) do
			songs = {}
			for _, song in pairs( v2 ) do
				table.insert( songs, song )
			end
			table.insert( albums, album )
			table.insert( albums, songs )
		end		
		table.insert( artists, artist )
		table.insert( artists, albums )
	end
	
	table.insert( results, artists )
	local output = stdnse.format_output( true, results )
	
	if limit > 0 then
		output = output .. string.format("\n\nOutput limited to %d items", limit )
	end
	
	return output

end
