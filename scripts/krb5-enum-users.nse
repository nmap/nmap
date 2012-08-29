local asn1 = require "asn1"
local bin = require "bin"
local coroutine = require "coroutine"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local unpwdb = require "unpwdb"

description = [[
Discovers valid usernames by brute force querying likely usernames against a Kerberos service.
When an invalid username is requested the server will responde using the
Kerberos error code KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, allowing us to determine
that the user name was invalid. Valid user names will illicit either the
TGT in a AS-REP response or the error KRB5KDC_ERR_PREAUTH_REQUIRED, signaling
that the user is required to perform pre authentication.

The script should work against Active Directory and ?
It needs a valid Kerberos REALM in order to operate.
]]

---
-- @usage
-- nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'
--
-- @output
-- PORT   STATE SERVICE      REASON
-- 88/tcp open  kerberos-sec syn-ack
-- | krb5-enum-users: 
-- | Discovered Kerberos principals
-- |     administrator@test
-- |     mysql@test
-- |_    tomcat@test
--
-- @args krb5-enum-users.realm this argument is required as it supplies the
--       script with the Kerberos REALM against which to guess the user names.
--

--
--
-- Version 0.1
-- Created 10/16/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}


portrule = shortport.port_or_service( 88, {"kerberos-sec"}, {"udp","tcp"}, {"open", "open|filtered"} )

-- This an embryo of a Kerberos 5 packet creation and parsing class. It's very
-- tiny class and holds only the necessary functions to support this script.
-- This class be factored out into it's own library, once more scripts make use
-- of it.
KRB5 = {

	-- Valid Kerberos message types
	MessageType = {
		['AS-REQ'] = 10,
		['AS-REP'] = 11,
		['KRB-ERROR'] = 30,
	},

	-- Some of the used error messages
	ErrorMessages = {
		['KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN'] = 6,
		['KRB5KDC_ERR_PREAUTH_REQUIRED'] = 25,
		['KDC_ERR_WRONG_REALM'] = 68,
	},

	-- A list of some ot the encryption types
	EncryptionTypes = {
		{ ['aes256-cts-hmac-sha1-96'] = 18 },
		{ ['aes128-cts-hmac-sha1-96'] = 17 },
		{ ['des3-cbc-sha1'] = 16 },
		{ ['rc4-hmac'] = 23 },
		--	{ ['des-cbc-crc'] = 1 },
		--	{ ['des-cbc-md5'] = 3 },
		--	{ ['des-cbc-md4'] = 2 }
	},

	-- A list of principal name types
	NameTypes = {
		['NT-PRINCIPAL'] = 1,
		['NT-SRV-INST'] = 2,
	},

	-- Creates a new Krb5 instance
	-- @return o as the new instance
	new = function(self)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		return o
    end,

	-- A number of custom ASN1 decoders needed to decode the response
	tagDecoder = {

		["18"] = function( self, encStr, elen, pos )
		return bin.unpack("A" .. elen, encStr, pos)
		end,

		["1B"] = function( ... ) return KRB5.tagDecoder["18"](...) end,

		["6B"] = function( self, encStr, elen, pos )
		local seq
		pos, seq = self:decodeSeq(encStr, elen, pos)
		return pos, seq
		end,

		-- Not really sure what these are, but they all decode sequences
		["7E"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A0"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A1"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A2"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A3"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A4"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A5"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A6"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A7"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A8"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,
		["A9"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,	
		["AA"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,	
		["AC"] = function( ... ) return KRB5.tagDecoder["6B"](...) end,	

	},

	-- A few Kerberos ASN1 encoders
	tagEncoder = {

		['table'] = function(self, val)

			local types = {
				['GeneralizedTime'] = 0x18,
				['GeneralString'] = 0x1B,
			}

			local len = asn1.ASN1Encoder.encodeLength(#val[1])

			if ( val._type and types[val._type] ) then
				return bin.pack("CAA", types[val._type], len, val[1])
			elseif ( val._type and 'number' == type(val._type) ) then
				return bin.pack("CAA", val._type, len, val[1])
			end

		end,
	},

	-- Encodes a sequence using a custom type
	-- @param encoder class containing an instance of a ASN1Encoder
	-- @param seqtype number the sequence type to encode
	-- @param seq string containing the sequence to encode 
	encodeSequence = function(self, encoder, seqtype, seq)
		return encoder:encode( { _type = seqtype, seq } )
	end,

	-- Encodes a Kerberos Principal
	-- @param encoder class containing an instance of ASN1Encoder
	-- @param name_type number containing a valid Kerberos name type
	-- @param names table containing a list of names to encode
	-- @return princ string containing an encoded principal
	encodePrincipal = function(self, encoder, name_type, names )
		local princ = ""

		for _, n in ipairs(names) do
			princ = princ .. encoder:encode( { _type = 'GeneralString', n } ) 
		end

		princ = self:encodeSequence(encoder, 0x30, princ)
		princ = self:encodeSequence(encoder, 0xa1, princ)
		princ = encoder:encode( name_type ) .. princ

		-- not sure about how this works, but apparently it does
		princ = bin.pack("H", "A003") .. princ
		princ = self:encodeSequence(encoder,0x30, princ)

		return princ
	end,

	-- Encodes the Kerberos AS-REQ request
	-- @param realm string containing the Kerberos REALM
	-- @param user string containing the Kerberos principal name
	-- @param protocol string containing either of "tcp" or "udp"
	-- @return data string containing the encoded request
	encodeASREQ = function(self, realm, user, protocol)

		assert(protocol == "tcp" or protocol == "udp",
			"Protocol has to be either \"tcp\" or \"udp\"")

		local encoder = asn1.ASN1Encoder:new()
		encoder:registerTagEncoders(KRB5.tagEncoder)

		local data = ""

		-- encode encryption types
		for _,enctype in ipairs(KRB5.EncryptionTypes) do
			for k, v in pairs( enctype ) do
				data = data .. encoder:encode(v)
			end
		end

		data = self:encodeSequence(encoder, 0x30, data )
		data = self:encodeSequence(encoder, 0xA8, data )

		-- encode nonce
		local nonce = 155874945
		data = self:encodeSequence(encoder, 0xA7, encoder:encode(nonce) ) .. data

		-- encode from/to
		local fromdate = os.time() + 10 * 60 * 60
		local from = os.date("%Y%m%d%H%M%SZ", fromdate)
		data = self:encodeSequence(encoder, 0xA5, encoder:encode( { from, _type='GeneralizedTime' })) .. data

		local names = { "krbtgt", realm }
		local sname = self:encodePrincipal( encoder, KRB5.NameTypes['NT-SRV-INST'], names )
		sname = self:encodeSequence(encoder, 0xA3, sname)
		data = sname .. data

		-- realm
		data = self:encodeSequence(encoder, 0xA2, encoder:encode( { _type = 'GeneralString', realm })) .. data

		local cname = self:encodePrincipal(encoder, KRB5.NameTypes['NT-PRINCIPAL'], { user })
		cname = self:encodeSequence(encoder, 0xA1, cname)
		data = cname .. data

		-- forwardable
		local kdc_options = 0x40000000
		data = bin.pack(">I", kdc_options) .. data

		-- add padding
		data = bin.pack("C", 0) .. data

		-- hmm, wonder what this is
		data = bin.pack("H", "A0070305") .. data
		data = self:encodeSequence(encoder, 0x30, data)
		data = self:encodeSequence(encoder, 0xA4, data)
		data = self:encodeSequence(encoder, 0xA2, encoder:encode(KRB5.MessageType['AS-REQ'])) .. data

		local pvno = 5
		data = self:encodeSequence(encoder, 0xA1, encoder:encode(pvno) ) .. data

		data = self:encodeSequence(encoder, 0x30, data)
		data = self:encodeSequence(encoder, 0x6a, data)

		if ( protocol == "tcp" ) then
			data = bin.pack(">I", #data) .. data
		end

		return data
	end,

	-- Parses the result from the AS-REQ
	-- @param data string containing the raw unparsed data
	-- @return status boolean true on success, false on failure
	-- @return msg table containing the fields <code>type</code> and
	--         <code>error_code</code> if the type is an error.
	parseResult = function(self, data)

		local decoder = asn1.ASN1Decoder:new()
		decoder:registerTagDecoders(KRB5.tagDecoder)
		decoder:setStopOnError(true)
		local pos, result = decoder:decode(data)
		local msg = {}


		if ( #result == 0 or #result[1] < 2 or #result[1][2] < 1 ) then
			return false, nil
		end

		msg.type = result[1][2][1]

		if ( msg.type == KRB5.MessageType['KRB-ERROR'] ) then
			if ( #result[1] < 5 and #result[1][5] < 1 ) then
				return false, nil
			end

			msg.error_code = result[1][5][1]
			return true, msg
			elseif ( msg.type == KRB5.MessageType['AS-REP'] ) then
				return true, msg
			end

			return false, nil
		end,

}

-- Checks whether the user exists or not
-- @param host table as received by the action method
-- @param port table as received by the action method
-- @param realm string containing the Kerberos REALM
-- @param user string containing the Kerberos principal
-- @return status boolean, true on success, false on failure
-- @return state VALID or INVALID or error message if status was false
local function checkUser( host, port, realm, user )

	local krb5 = KRB5:new()
	local data = krb5:encodeASREQ(realm, user, port.protocol)
	local socket = nmap.new_socket()
	local status = socket:connect(host, port)

	if ( not(status) ) then
		return false, "ERROR: Failed to connect to Kerberos service"
	end

	socket:send(data)
	status, data = socket:receive()
	
	if ( port.protocol == 'tcp' ) then data = data:sub(5) end
	
	if ( not(status) ) then
		return false, "ERROR: Failed to receive result from Kerberos service"
	end
	socket:close()
	
	local msg
	status, msg = krb5:parseResult(data)

	if ( not(status) ) then
		return false, "ERROR: Failed to parse the result returned from the Kerberos service"
	end
	
	if ( msg and msg.error_code ) then
		if ( msg.error_code == KRB5.ErrorMessages['KRB5KDC_ERR_PREAUTH_REQUIRED'] ) then
			return true, "VALID"
		elseif ( msg.error_code == KRB5.ErrorMessages['KDC_ERR_WRONG_REALM'] ) then
			return false, "Invalid Kerberos REALM"
		end
	elseif ( msg.type == KRB5.MessageType['AS-REP'] ) then
		return true, "VALID"
	end
	return true, "INVALID"
end

-- Checks whether the Kerberos REALM exists or not
-- @param host table as received by the action method
-- @param port table as received by the action method
-- @param realm string containing the Kerberos REALM
-- @return status boolean, true on success, false on failure
local function isValidRealm( host, port, realm )
	return checkUser( host, port, realm, "nmap")
end

-- Wraps the checkUser function so that it is suitable to be called from
-- a thread. Adds a user to the result table in case it's valid.
-- @param host table as received by the action method
-- @param port table as received by the action method
-- @param realm string containing the Kerberos REALM
-- @param user string containing the Kerberos principal
-- @param result table to which all discovered users are added
local function checkUserThread( host, port, realm, user, result )
	local condvar = nmap.condvar(result)
	local status, state = checkUser(host, port, realm, user)
	if ( status and state == "VALID" ) then
		table.insert(result, ("%s@%s"):format(user,realm))
	end
	condvar "signal"
end

action = function( host, port )

	local realm = stdnse.get_script_args("krb5-enum-users.realm")
	local result = {}
	local condvar = nmap.condvar(result)

	-- did the user supply a realm
	if ( not(realm) ) then
		return "ERROR: No Kerberos REALM was supplied, aborting ..."
	end

	-- does the realm appear to exist
	if ( not(isValidRealm(host, port, realm)) ) then
		return "ERROR: Invalid Kerberos REALM, aborting ..."
	end

	-- load our user database from unpwdb
	local status, usernames = unpwdb.usernames()
	if( not(status) ) then return "ERROR: Failed to load unpwdb usernames" end
		
	-- start as many threads as there are names in the list
	local threads = {}
	for user in usernames do
		local co = stdnse.new_thread( checkUserThread, host, port, realm, user, result )
		threads[co] = true
	end
	
	-- wait for all threads to finish up
	repeat
		for t in pairs(threads) do
			if ( coroutine.status(t) == "dead" ) then threads[t] = nil end
		end
		if ( next(threads) ) then
			condvar "wait"
		end
	until( next(threads) == nil )
	
	if ( #result > 0 ) then
		result = { name = "Discovered Kerberos principals", result }
	end
	return stdnse.format_output(true, result)
end
