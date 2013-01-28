local _G = require "_G"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local math = require "math"
local io = require "io"


description = [[
A very basic IKE library.

The current funcionality includes:
	1. Generating a Main or Aggressive Mode IKE request packet with a variable amount of transforms and a vpn group.
	2. Sending a packet
	3. Receiving the response
 	4. Parsing the response for VIDs
 	5. Searching for the VIDs in 'ike-fingerprints.lua'
 	6. returning a parsed info table

This library is meant for extension, which could include:
 	1. complete parsing of the response packet (might allow for better fingerprinting)
 	2. adding more options to the request packet
 		vendor field (might give better fingerprinting of services, e.g. Checkpoint)
	3. backoff pattern analyses
	...

An a implementation resembling 'ike-scan' could be built.
]]


_ENV = stdnse.module("ike", stdnse.seeall)

author = "Jesper Kueckelhahn"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local authentication= { ["psk"]="80030001", ["rsa"] ="80030003", ["Hybrid"] = "8003FADD", ["XAUTH"] = "8003FDE9"}
local enc_methods	= { ["des"]="80010001", ["3des"]="80010005", ["aes/128"]="80010007/800E0080", ["aes/192"]="80010007/800E00C0", ["aes/256"]="80010007/800E0100" }
local hash_algo		= { ["md5"]="80020001", ["sha1"]="80020002"}
local group_desc	= { ["768"]="80040001", ["1024"]="80040002", ["1536"]="80040005"}
local exchange_mode = { ["Main"] = "02", ["Aggressive"]= "04"}
local protocol_ids	= { ["tcp"]  = "06", ["udp"]= "11"}


-- Response packet types
local response_exchange_type = {
	["02"] = "Main",
	["04"] = "Aggressive",
	["05"] = "Informational"
}

-- Payload names
local payloads = {
	["00"] = "None",
	["01"] = "SA",
	["03"] = "Transform",
	["04"] = "Key Exchange",
	["05"] = "ID",
	["08"] = "Hash",
	["0A"] = "Nonce",
	["0D"] = "VID"
}


-- Load the fingerprint file
-- (located in: nselib/data/ike-fingerprints.lua)
--
local function load_fingerprints()
	local file, filename_full, fingerprints

	-- Check if fingerprints are cached
	if(nmap.registry.ike_fingerprints ~= nil) then
		stdnse.print_debug(1, "ike: Loading cached fingerprints")
		return nmap.registry.ike_fingerprints
	end

	-- Try and find the file
	-- If it isn't in Nmap's directories, take it as a direct path
	filename_full = nmap.fetchfile('nselib/data/ike-fingerprints.lua')

	-- Load the file
	stdnse.print_debug(1, "ike: Loading fingerprints: %s", filename_full)
	local env = setmetatable({fingerprints = {}}, {__index = _G});
	file = loadfile(filename_full, "t", env)
	if( not(file) ) then
		stdnse.print_debug(1, "ike: Couldn't load the file: %s", filename_full)
		return false, "Couldn't load fingerprint file: " .. filename_full
	end
	file()
	fingerprints = env.fingerprints

	-- Check there are fingerprints to use
	if(#fingerprints == 0 ) then
		return false, "No fingerprints were loaded after processing ".. filename
	end

	return true, fingerprints
end


-- generate a random hex-string of length 'length'
--
local function generate_random(length)
	local rnd = ""
	
	for i=1, length do 
		rnd = rnd .. string.format("%.2X", math.random(255))
	end
	return rnd
end


-- convert a string to a hex-string (of the ASCII representation)
--
local function convert_to_hex(id)
	local hex_str = ""

	for c in string.gmatch(id, ".") do 
		hex_str = hex_str .. string.format("%X", c:byte()) 
	end
	return hex_str
end


-- Extract Payloads
local function extract_payloads(packet)
	
	-- packet only contains HDR
	if packet:len() < 61 then return {} end

	local np = packet:sub(33,34)	-- next payload
	local index = 61				-- starting point for search
	local ike_headers = {}			-- ike headers
	local payload = ''

	-- loop over packet
	while payloads[np] ~= "None" and index <= packet:len() do
		payload_length = tonumber("0x"..packet:sub(index, index+3)) * 2
		payload = string.lower(packet:sub(index+4, index+payload_length-5))

		-- debug
		if payloads[np] == 'VID' then
			stdnse.print_debug(2, 'IKE: Found IKE Header: %s: %s - %s', np, payloads[np], payload)
		else
			stdnse.print_debug(2, 'IKE: Found IKE Header: %s: %s', np, payloads[np])
		end

		-- Store payload
		if ike_headers[payloads[np]] == nil then
			ike_headers[payloads[np]] = {payload}
		else
			table.insert(ike_headers[payloads[np]], payload)
		end

		-- find the next payload type
		np = packet:sub(index-4, index-3)

		-- jump to the next payload
		index = index + payload_length
	end
	return ike_headers	

end




-- Search the fingerprint database for matches
--	This is a (currently) divided into two parts
--		1) version detection based on single fingerprints
--		2) version detection based on the order of all vendor ids
--
--	NOTE: the second step currently only has support for CISCO devices
--
-- Input is a table of collected vendor-ids, output is a table 
-- with fields: 
--	vendor, version, name, attributes (table), guess (table), os
local function lookup(vendor_ids)
	if vendor_ids == {} or vendor_ids == nil then return {} end

	-- concat all vids to one string
	local all_vids = ''
	for _,vid in pairs(vendor_ids) do all_vids = all_vids .. vid end

	-- the results
	local info = {
		vendor = nil,
		attribs = {},
	}

	local status, fingerprints
	status, fingerprints = load_fingerprints()

	if status then

		-- loop over the vendor_ids returned in ike request
		for _,vendor_id in pairs(vendor_ids) do
	
			-- loop over the fingerprints found in database	
			for _,row in pairs(fingerprints) do

				if vendor_id:find(row.fingerprint) then

					-- if a match is found, check if it's a version detection or attribute
					if row.category == 'vendor' then
						
						-- Only store the first match
						if info.vendor == nil then

							-- the fingerprint contains information about the VID
							info.vendor = row

							local debug_string = ''
							if row.vendor  ~= nil then debug_string = debug_string .. row.vendor .. ' ' end
							if row.version ~= nil then debug_string = debug_string .. row.version       end	

							stdnse.print_debug(2, "IKE: Fingerprint: %s matches %s", vendor_id,  debug_string)
						end
					
					elseif row.category == 'attribute' then
						info.attribs[ #info.attribs + 1] = row
						stdnse.print_debug(2, "IKE: Attribute: %s matches %s", vendor_id, row.text)
						break
					end
				end
			end 
		end
	end


	---------------------------------------------------
	-- Search for the order of the vids
	-- Uses category 'vid_ordering'
	---
	
	-- search in the 'vid_ordering' category
	local debug_string = ''
	for _,row in pairs(fingerprints) do

		if row.category == 'vid_ordering' and all_vids:find(row.fingerprint) then
			
			-- Use ordering information if there where no vendor matches from prevoius step
			if info.vendor == nil then
				info.vendor = row
				
				-- Debugging info
				debug_string = ''
				if info.vendor.vendor  ~= nil then debug_string = debug_string .. info.vendor.vendor  .. ' ' end
				if info.vendor.version ~= nil then debug_string = debug_string .. info.vendor.version .. ' ' end
				if info.vendor.ostype  ~= nil then debug_string = debug_string .. info.vendor.ostype         end
				stdnse.print_debug(2, 'IKE: No vendor match, but ordering match found: %s', debug_string)
				
				return info
			
			-- Update OS based on ordering
			elseif info.vendor.vendor == row.vendor then
				info.vendor.ostype = row.ostype
				
				-- Debugging info
				debug_string = ''
				if info.vendor.vendor	~= nil then debug_string = debug_string .. info.vendor.vendor  .. ' to ' end
				if row.ostype			~= nil then debug_string = debug_string .. row.ostype end
				stdnse.print_debug(2, 'IKE: Vendor and ordering match. OS updated: %s', debug_string)
				
				return info

			-- Only print debugging information if conflicting information is detected
			else
				-- Debugging info
				debug_string = ''
				if info.vendor.vendor	~= nil then debug_string = debug_string .. info.vendor.vendor  .. ' vs ' end
				if row.vendor			~= nil then debug_string = debug_string .. row.vendor end
				stdnse.print_debug(2, 'IKE: Found an ordering match, but vendors do not match. %s', debug_string)
			
			end
		end
	end

	return info
end


-- Handle a response packet
--	A very limited response parser
--	Currently only the VIDs are extracted
--	This could be made more advanced to 
--  allow for fingerprinting via the order 
--	of the returned headers
---
function response(packet)
	local resp = { ["mode"] = "", ["info"] = nil, ['vids']={}, ['success'] = false }

	if packet:len() > 38 then

		-- extract the return type
		local resp_type = response_exchange_type[packet:sub(37,38)]
		local ike_headers = {}

		-- simple check that the type is something other than 'Informational'
		-- as this type does not include VIDs 
		if resp_type ~= "Informational" then
			resp["mode"]	= resp_type

			ike_headers = extract_payloads(packet)

			-- Extract the VIDs
			resp['vids']	= ike_headers['VID']

			-- search for fingerprints
			resp["info"]	= lookup(resp['vids'])

			-- indicate that a packet 'useful' packet was returned
			resp['success'] = true
		end
	end

	return resp
end


-- Send a request
-- The 'packet' argument must be generated by the function 'request'
-- and is a hex string
--
function send_request( host, port, packet )
	
	local socket = nmap.new_socket()
	local s_status, r_status, data, i, hexstring

	-- send the request packet
	socket:set_timeout(1000)
	socket:bind(nil, port.number)
	socket:connect(host, port, "udp")
	s_status,_ = socket:send(bin.pack("H", packet))

	-- receive answer
	if s_status then	
		r_status, data = socket:receive_lines(1)
		
		if r_status then
			i, hexstring = bin.unpack("H" .. data:len(), data)
			socket:close()
			return response(hexstring)	
		else
			socket:close()
		end
	else
		socket:close()
	end

	return {}
end

-- Create the aggressive part of a packet
--	Aggressive mode includes the user-id, so the 
--	length of this has to be taken into account
--
local function generate_aggressive(port, protocol, id, diffie)
	local hex_port = string.format("%.4X", port)
	local hex_prot = protocol_ids[protocol]
	local id_len = string.format("%.4X", 8 + id:len())

	-- get length of key data based on diffie
	local key_length
	if diffie == 1 then
		key_length = 96
	elseif diffie == 2 then
		key_length = 128
	end 


	return "" ..
		-- Key Exchange
		"0a00"								.. -- Next payload (Nonce)
		string.format("%04X", key_length+4)	.. -- Length (132-bit)
		generate_random(key_length) 		.. -- Random key data

		-- Nonce
		"0500"				.. -- Next payload (Identification)
		"0018"				.. -- Length (24)
		generate_random(20)	.. -- Nonce data

		-- Identification	
		"0000"				.. -- Next Payload (None)
		id_len				.. -- Payload length (id + 8)
		"03"				.. -- ID Type (USER_FQDN)
		hex_prot			.. -- Protocol ID (UDP)
		hex_port			.. -- Port (500)
		convert_to_hex(id)	   -- Id Data (as hex)
end


-- Create the transform
--	AES encryption needs an extra value to define the key length
--	Currently only DES, 3DES and AES encryption is supported 
--
local function generate_transform(auth, encryption, hash, group, number, total)
	local key_length, trans_length, aes_enc, sep
	local next_payload, payload_number
	
	-- handle special case of aes
	if encryption:sub(1,3) == "aes" then
		trans_length = "0028"
		aes_enc = enc_methods[encryption]
		sep = aes_enc:find("/")
		enc 		= aes_enc:sub(1,sep-1)
		key_length	= aes_enc:sub(sep+1, aes_enc:len())
	else
		trans_length = "0024"
		key_length = ""
		enc = enc_methods[encryption]
	end

	-- check if there are more transforms
	if number == total then
		next_payload = "0000" -- none
	else
		next_payload = "0300" -- transform
	end

	-- set the payload number
	payload_number = string.format("%.2X", number)

	return ""				.. 
		next_payload		.. -- Next payload
		trans_length		.. -- Transform length (36-bit)
		payload_number		.. -- Transform number
		"01"				.. -- Transform ID (IKE)
		"0000"				.. -- spacers ?
		enc					.. -- Encryption algorithm
		hash_algo[hash]		.. -- Hash algorithm
		authentication[auth].. -- Authentication method
		group_desc[group]	.. -- Group Description
		key_length			.. -- only set for aes
		"800b0001"			.. -- Life type (seconds)
		"000c000400007080"	   -- Life duration (28800)
end


-- Generate multiple transforms
-- 	Input nust be a table of complete transforms
--
local function generate_transforms(transform_table)
	local transforms = ""

	for i,t in pairs(transform_table) do
		transforms = transforms .. generate_transform(t.auth, t.encryption, t.hash, t.group, i, #transform_table)
	end

	return transforms
end


-- Create a request packet
--	Support for multiple transforms, which minimizes the
--	the amount of traffic/packets needed to be sendt
--
function request(port, proto, mode, transforms, diffie, id)
	local payload_after_sa, str_aggressive, l, l_sa, l_pro
	local number_transforms, transform_string

	transform_string = generate_transforms(transforms)
	number_transforms = string.format("%.2X", #transforms)

	-- check for aggressive vs Main mode 
	if mode == "Aggressive" then
		str_aggressive = generate_aggressive(port, proto, id, diffie)		
		payload_after_sa = "0400"
	else
		str_aggressive = ""
		payload_after_sa = "0000"
	end

	-- calculate lengths
	l		= string.format("%.8X", 48 + transform_string:len()/2 + str_aggressive:len()/2)
	l_sa	= string.format("%.4X", 20 + transform_string:len()/2)
	l_pro	= string.format("%.4X", 8 + transform_string:len()/2)


	-- Build the packet
	local packet = "" .. 
		generate_random(8)	.. -- Initiator cookie
		"0000000000000000"	.. -- Responder cookie
		"01"				.. -- Next payload (SA)
		"10"				.. -- Version
		exchange_mode[mode]	.. -- Exchange type
		"00"				.. -- Flags
		"00000000"			.. -- Message id
		l					.. -- packet length


		--# Security Association
		payload_after_sa	.. -- Next payload (Key exchange, if aggressive mode)
		l_sa				.. -- Length (56-bit)
		"00000001"			.. -- IPSEC
		"00000001"			.. -- Situation

		--## Proposal
		"0000"				.. -- Next payload (None)
		l_pro				.. -- Payload length
		"01"				.. -- Proposal number
		"01"				.. -- Protocol ID (ISAKMP)
		"00"				.. -- SPI Size
		number_transforms	.. -- Proposal transforms

		--### Transform 
		transform_string	.. -- transform
	
		-- Aggressive mode 
		str_aggressive

	return packet
end


return _ENV