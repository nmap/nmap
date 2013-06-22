---
-- Simple Authentication and Security Layer (SASL).
--
-- The library contains some low level functions and a high level class.
--
-- The <code>DigestMD5</code> class contains all code necessary to calculate
-- a DIGEST-MD5 response based on the servers challenge and the other
-- necessary arguments (@see DigestMD5.new).
-- It can be called throught the SASL helper or directly like this:
-- <code>
-- 	local dmd5 = DigestMD5:new(chall, user, pass, "AUTHENTICATE", nil, "imap")
-- 	local digest = dmd5:calcDigest()
-- </code>
-- 
-- The <code>NTLM</code> class contains all code necessary to calculate a
-- NTLM response based on the servers challenge and the other necessary
-- arguments (@see NTLM.new). It can be called through the SASL helper or
-- directly like this:
-- <code>
-- 	local ntlm = NTLM:new(chall, user, pass)
--  local response = ntlm:calcResponse()
-- </code>
--
-- The Helper class contains the high level methodes:
-- * <code>new</code>: This is the SASL object constructor.
-- * <code>set_mechanism</code>: Sets the authentication mechanism to use.
-- * <code>set_callback</code>: Sets the encoding function to use.
-- * <code>encode</code>: Encodes the parameters according to the
--                        authentication mechanism.
-- * <code>reset_callback</code>: Resets the authentication function.
-- * <code>reset</code>: Resets the SASL object.
--
-- The script writers should use the Helper class to create SASL objects,
-- and they can also use the low level functions to customize their
-- encoding functions.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

-- Version 0.2
-- Created 07/17/2011 - v0.1 - 	Created by Djalal Harouini
-- Revised 07/18/2011 - v0.2 - 	Added NTLM, DIGEST-MD5 classes


local bin = require "bin"
local bit = require "bit"
local smbauth = require "smbauth"
local stdnse = require "stdnse"
local string = require "string"
_ENV = stdnse.module("sasl", stdnse.seeall)

local HAVE_SSL, openssl = pcall(require, 'openssl')
if ( not(HAVE_SSL) ) then
	 stdnse.print_debug(1,
	    "sasl.lua: OpenSSL not present, SASL support limited.")
end
local MECHANISMS = { }

if HAVE_SSL then 
  -- Calculates a DIGEST MD5 response
  DigestMD5 = {

  --- Instantiates DigestMD5
  --
  -- @param chall string containing the base64 decoded challenge
  -- @return a new instance of DigestMD5
    new = function(self, chall, username, password, method, uri, service, realm)
      local o = { nc = 0, 
        chall = chall, 
        challnvs = {},
        username = username,
        password = password,
        method = method,
        uri = uri,
        service = service,
        realm = realm }
          setmetatable(o, self)
          self.__index = self
      o:parseChallenge()
      return o
    end,

    -- parses a challenge received from the server
    -- takes care of both quoted and unqoted identifiers
    -- regardless of what RFC says
    parseChallenge = function(self)
      local results = {}
      local start, stop = 0,0
      if self.chall then
        while(true) do
          local name, value
          start, stop, name = self.chall:find("([^=]*)=%s*", stop + 1)
          if ( not(start) ) then break end
          if ( self.chall:sub(stop + 1, stop + 1) == "\"" ) then
            start, stop, value = self.chall:find("(.-)\"", stop + 2)
          else
            start, stop, value = self.chall:find("([^,]*)", stop + 1)
          end
          name = name:lower()
          if name == "digest realm" then name="realm" end
          self.challnvs[name] = value
          start, stop = self.chall:find("%s*,%s*", stop + 1)
          if ( not(start) ) then break end
        end
      end
    end,

    --- Calculates the digest
    calcDigest = function( self )
      local uri = self.uri or ("%s/%s"):format(self.service, "localhost")
      local realm = self.realm or self.challnvs.realm or ""
      local cnonce = stdnse.tohex(openssl.rand_bytes( 8 ))
      local qop = "auth"
      local qop_not_specified
      if self.challnvs.qop then
        qop_not_specified = false
      else
        qop_not_specified = true
      end
      self.nc = self.nc + 1
      local A1_part1 = openssl.md5(self.username .. ":" .. (self.challnvs.realm or "") .. ":" .. self.password)
      local A1 = stdnse.tohex(openssl.md5(A1_part1 .. ":" .. self.challnvs.nonce .. ':' .. cnonce))
      local A2 = stdnse.tohex(openssl.md5(("%s:%s"):format(self.method, uri)))
      local digest = stdnse.tohex(openssl.md5(A1 .. ":" .. self.challnvs.nonce .. ":" ..
            ("%08d"):format(self.nc)  .. ":" .. cnonce .. ":" ..
            qop .. ":" .. A2))

      local b1
      if not self.challnvs.algorithm or self.challnvs.algorithm == "MD5" then
        b1 = stdnse.tohex(openssl.md5(self.username..":"..(self.challnvs.realm or "")..":"..self.password))
      else
        b1 = A1
      end
      -- should we make it work when qop == "auth-int" (we would need entity-body here, which
      -- might be complicated)?

      local digest_http
      if not qop_not_specified then
        digest_http =  stdnse.tohex(openssl.md5(b1 .. ":" .. self.challnvs.nonce .. ":" ..
                        ("%08d"):format(self.nc)  .. ":" .. cnonce .. ":" .. qop .. ":" .. A2))
      else
        digest_http =  stdnse.tohex(openssl.md5(b1 .. ":" .. self.challnvs.nonce .. ":" .. A2))
      end

      local response = "username=\"" .. self.username .. "\""
      response = response .. (",%s=\"%s\""):format("realm", realm)
      response = response .. (",%s=\"%s\""):format("nonce", self.challnvs.nonce)
      response = response .. (",%s=\"%s\""):format("cnonce", cnonce)
      response = response .. (",%s=%08d"):format("nc", self.nc)
      response = response .. (",%s=%s"):format("qop", "auth")
      response = response .. (",%s=\"%s\""):format("digest-uri", uri)
      response = response .. (",%s=%s"):format("response", digest)
      response = response .. (",%s=%s"):format("charset", "utf-8")
      
      -- response_table is used in http library because the request should
      -- be a little bit different then the string generated above
      local response_table = {
        username = self.username,
        realm = realm,
        nonce = self.challnvs.nonce,
        cnonce = cnonce,
        nc = ("%08d"):format(self.nc),
        qop = qop,
        ["digest-uri"] = uri,
        algorithm = self.challnvs.algorithm,
        response = digest_http
      }
      
      return response, response_table
    end,

  }

	-- The NTLM class handling NTLM challenge response authentication
	NTLM = {

		--- Creates a new instance of the NTLM class
		--
		-- @param chall string containing the challenge received from the server
		-- @param username string containing the username
		-- @param password string containing the password
		-- @return new instance of NTML
		new = function(self, chall, username, password)
			local o = { nc = 0, 
				chall = chall, 
				username = username,
				password = password}
	       	setmetatable(o, self)
	        self.__index = self
			o:parseChallenge()
			return o
		end,

		--- Converst str to "unicode" (adds null bytes for every other byte)
		-- @param str containing string to convert
		-- @return unicode string containing the unicoded str
		to_unicode = function(str)
			local unicode = ""
			for i = 1, #str, 1 do
				unicode = unicode .. bin.pack("<S", string.byte(str, i))
			end
			return unicode
		end,

		--- Parses the NTLM challenge as received from the server
		parseChallenge = function(self)
			local NTLM_NegotiateUnicode 			= 0x00000001
			local NTLM_NegotiateExtendedSecurity 	= 0x00080000
			local pos, _, message_type

			pos, _, message_type, _, _, 
			_, self.flags, self.chall, _, 
			_, _, _	 = bin.unpack("<A8ISSIIA8LSSI", self.chall)

			if ( message_type ~= 0x02 ) then
				error("NTLM parseChallenge expected message type: 0x02")
			end

			self.is_extended = ( bit.band(self.flags, NTLM_NegotiateExtendedSecurity) == NTLM_NegotiateExtendedSecurity )
			local is_unicode  = ( bit.band(self.flags, NTLM_NegotiateUnicode) == NTLM_NegotiateUnicode )

			self.workstation = "NMAP-HOST"
			self.domain = self.username:match("^(.-)\\(.*)$") or "DOMAIN"

			if ( is_unicode ) then
				self.workstation = self.to_unicode(self.workstation)
				self.username = self.to_unicode(self.username)
				self.domain = self.to_unicode(self.domain)
			end	
		end,

		--- Calculates the response
		calcResponse = function(self)
			local ntlm, lm = smbauth.get_password_response(nil, self.username, self.domain, self.password, nil, "v1", self.chall, self.is_extended)
			local msg_type = 3
			local response
			local BASE_OFFSET = 72
			local offset
			local encrypted_random_sesskey = ""
			local flags = 0xa2888205  -- (NTLM_NegotiateUnicode | \
			                    		-- NTLM_RequestTarget | \
					                    -- NTLM_NegotiateNTLM | \
					                    -- NTLM_NegotiateAlwaysSign | \
					                    -- NTLM_NegotiateExtendedSecurity | \
					                    -- NTLM_NegotiateTargetInfo | \
					                    -- NTLM_NegotiateVersion | \
					                    -- NTLM_Negotiate128 | \
					                    -- NTLM_Negotiate56)

			response = bin.pack("<AI", "NTLMSSP\0", msg_type)

			offset = BASE_OFFSET + #self.workstation + #self.username + #self.domain
			response = response .. bin.pack("<SSI", #lm, #lm, offset)

			offset = offset + #lm
			response = response .. bin.pack("<SSI", #ntlm, #ntlm, offset)

			offset = BASE_OFFSET
			response = response .. bin.pack("<SSI", #self.domain, #self.domain, offset)

			offset = BASE_OFFSET + #self.domain
			response = response .. bin.pack("<SSI", #self.username, #self.username, offset)

			offset = BASE_OFFSET + #self.domain + #self.username
			response = response .. bin.pack("<SSI", #self.workstation, #self.workstation, offset)

			offset = offset + #self.workstation + #lm + #ntlm
			response = response .. bin.pack("<SSI", #encrypted_random_sesskey, #encrypted_random_sesskey, offset)

			response = response .. bin.pack("<I", flags)

			-- add version info (major 5, minor 1, build 2600, reserved(1-3) 0,
			-- NTLM Revision 15)
			response = response .. bin.pack("<CCSCCCC", 5, 1, 2600, 0, 0, 0, 15)
			response = response .. self.domain .. self.username .. self.workstation .. ntlm .. lm .. encrypted_random_sesskey

			return response
		end

	}
	
  --- Encodes the parameters using the <code>CRAM-MD5</code> mechanism.
  --
  -- @param username string.
  -- @param password string.
  -- @param challenge The challenge as it is returned by the server.
  -- @return string The encoded string on success, or nil if Nmap was
  --         compiled without OpenSSL.
  function cram_md5_enc(username, password, challenge)
    local encode = stdnse.tohex(openssl.hmac('md5',
                                             password,
                                             challenge))
    return username.." "..encode
  end

  --- Encodes the parameters using the <code>DIGEST-MD5</code> mechanism.
  --
  -- @param username string.
  -- @param password string.
  -- @param challenge The challenge as it is returned by the server.
  -- @param service string containing the service that is requesting the
  --        encryption (eg. POP, IMAP, STMP)
  -- @param uri string containing the URI
  -- @return string The encoded string on success, or nil if Nmap was
  --         compiled without OpenSSL.
  function digest_md5_enc(username, password, challenge, service, uri)
	return DigestMD5:new(challenge, 
							username, 
							password, 
							"AUTHENTICATE", 
							uri, 
							service):calcDigest()
  end

  function ntlm_enc(username, password, challenge)
	return NTLM:new(challenge, username, password):calcResponse()
  end

else
  function cram_md5_enc()
    error("cram_md5_enc not supported without OpenSSL")
  end

  function digest_md5_enc()
    error("digest_md5_enc not supported without OpenSSL")
  end

  function ntlm_enc()
    error("ntlm_enc not supported without OpenSSL")
  end
end

MECHANISMS["CRAM-MD5"] = cram_md5_enc
MECHANISMS["DIGEST-MD5"] = digest_md5_enc
MECHANISMS["NTLM"] = ntlm_enc


--- Encodes the parameters using the <code>PLAIN</code> mechanism.
--
-- @param username string.
-- @param password string.
-- @return string The encoded string.
function plain_enc(username, password)
  return username.."\0"..username.."\0"..password
end
MECHANISMS["PLAIN"] = plain_enc


--- Checks if the given mechanism is supported by this library.
--
-- @param mechanism string to check.
-- @return mechanism if it is supported, otherwise nil.
-- @return callback The mechanism encoding function on success.
function check_mechanism(mechanism)
  local lmech, lcallback
  if mechanism then
    mechanism = string.upper(mechanism)
    if MECHANISMS[mechanism] then
      lmech = mechanism
      lcallback = MECHANISMS[mechanism]
    else
      stdnse.print_debug(3,
        "sasl library does not support '%s' mechanism", mechanism)
    end
  end
  return lmech, lcallback
end

--- This is the SASL Helper class, script writers should use it to create
-- SASL objects.
--
-- Usage of the Helper class:
--
-- local sasl_enc = sasl.Helper.new("CRAM-MD5")
-- local result = sasl_enc:encode(username, password, challenge)
--
-- sasl_enc:set_mechanism("LOGIN")
-- local user, pass = sasl_enc:encode(username, password)
Helper = {

  --- SASL object constructor.
  --
  -- @param mechanism The authentication mechanism to use
  --        (optional parameter).
  -- @param callback The encoding function associated with the
  --        mechanism (optional parameter).
  -- @usage
  -- local sasl_enc = sasl.Helper:new()
  -- local sasl_enc = sasl.Helper:new("CRAM-MD5")
  -- local sasl_enc = sasl.Helper:new("CRAM-MD5", my_cram_md5_func)
  -- @return sasl object.
  new = function(self, mechanism, callback)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    if self:set_mechanism(mechanism) then
      self:set_callback(callback)
    end
    return o
  end,

  --- Sets the SASL mechanism to use.
  --
  -- @param string The authentication mechanism.
  -- @usage
  -- local sasl_enc = sasl.Helper:new()
  -- sasl_enc:set_mechanism("CRAM-MD5")
  -- sasl_enc:set_mechanism("PLAIN")
  -- @return mechanism on success, or nil if the mechanism is not
  --         supported.
  set_mechanism = function(self, mechanism)
    self.mechanism, self.callback = check_mechanism(mechanism)
    return self.mechanism
  end,

  --- Associates A custom encoding function with the authentication
  --  mechanism.
  --
  -- Note that the SASL object by default will have its own
  -- callback functions.
  --
  -- @param callback The function associated with the authentication
  --        mechanism.
  -- @usage
  -- -- My personal CRAM-MD5 encode function
  -- function cram_md5_encode_func(username, password, challenge)
  --    ...
  -- end
  -- local sasl_enc = sasl.Helper:new("CRAM-MD5")
  -- sasl_enc:set_callback(cram_md5_handle_func)
  -- local result = sasl_enc:encode(username, password, challenge)
  set_callback = function(self, callback)
    if callback then
      self.callback = callback
    end
  end,

  --- Resets the encoding function to the default SASL
  --  callback function.
  reset_callback = function(self)
    self.callback = MECHANISMS[self.mechanism]
  end,

  --- Resets all the data of the SASL object.
  --
  -- This methode will clear the specified SASL mechanism.
  reset = function(self)
    self:set_mechanism()
  end,

  --- Returns the current authentication mechanism.
  -- 
  -- @return mechanism on success, or nil on failures.
  get_mechanism = function(self)
    return self.mechanism
  end,

  --- Encodes the parameters according to the specified mechanism.
  --
  -- @param ... The parameters to encode.
  -- @usage
  -- local sasl_enc = sasl.Helper:new("CRAM-MD5")
  -- local result = sasl_enc:encode(username, password, challenge)
  -- local sasl_enc = sasl.Helper:new("PLAIN")
  -- local result = sasl_enc:encode(username, password)
  -- @return string The encoded string on success, or nil on failures.
  encode = function(self, ...)
    return self.callback(...)
  end,
}

return _ENV;
