---This module takes care of the authentication used in SMB (LM, NTLM, LMv2, NTLMv2). 
-- There is a lot to this functionality, so if you're interested in how it works, read
-- on. 
--
-- In SMB authentication, there are two distinct concepts. Each will be dealt with
-- separately. There are:
-- * Stored hashes
-- * Authentication
--
-- What's confusing is that the same names are used for each of those. 
--
-- Stored Hashes
-- Windows stores two types of hashes: Lanman and NT Lanman (or NTLM). Vista and later
-- store NTLM only. Lanman passwords are divided into two 7-character passwords and 
-- used as a key in DES, while NTLM is converted to unicode and MD4ed. 
--
-- The stored hashes can be dumped in a variety of ways (pwdump6, fgdump, metasploit's
-- priv module, smb-pwdump.nse, etc). Generally, two hashes are dumped together 
-- (generally, Lanman:NTLM). Sometimes, Lanman is empty and only NTLM is given. Lanman
-- is never required. 
--
-- The password hashes can be given instead of passwords when supplying credentials; 
-- this is done by using the <code>smbhash</code> argument. Either a pair of hashes
-- can be passed, in the form of Lanman:NTLM, or a single hash, which is assumed to
-- be NTLM. 
--
-- Authentication
-- There are four types of authentication. Confusingly, these have the same names as
-- stored hashes, but only slight relationships. The four types are Lanmanv1, NTLMv1, 
-- Lanmanv2, and NTLMv2. By default, Lanmanv1 and NTLMv1 are used together in most 
-- applications. These Nmap scripts default to NTLMv1 alone, except in special cases, 
-- but it can be overridden by the user. 
--
-- Lanmanv1 and NTLMv1 both use DES for their response. The DES mixes a server challenge
-- with the hash (Lanman hash for Lanmanv1 response and NTLMv1 hash for NTLM response). 
-- The way the challenge is DESed with the hashes is identical for Lanmanv1 and NTLMv1, 
-- the only difference is the starting hash (Lanman vs NTLM). 
--
-- Lanmanv2 and NTLMv2 both use HMAC-MD5 for their response. The HMAC-MD5 mixes a 
-- server challenge and a client challenge with the NTLM hash, in both cases. The 
-- difference between Lanmanv2 and NTLMv2 is the length of the client challenge;
-- Lanmanv2 has a maximum client challenge of 8 bytes, whereas NTLMv2 doesn't limit
-- the length of the client challenge. 
--
-- The primary advantage to the 'v2' protocols is the client challenge -- by 
-- incorporating a client challenge, a malicious server can't use a precomputation
-- attack. 
--
-- In addition to hashing the passwords, messages are also signed, by default, if a 
-- v1 protocol is being used (I (Ron Bowes) couldn't get signatures to work on v2 
-- protocols; if anybody knows how I'd love to implement it).
--
--@args  smbusername The SMB username to log in with. The forms "DOMAIN\username" and "username@DOMAIN"
--                   are not understood. To set a domain, use the <code>smbdomain</code> argument.
--@args  smbdomain   The domain to log in with. If you aren't in a domained environment, then anything
--                   will (should?) be accepted by the server.
--@args  smbpassword The password to connect with. Be cautious with this, since some servers will lock
--                   accounts if the incorrect password is given. Although it's rare that the
--                   Administrator account can be locked out, in the off chance that it can, you could
--                   get yourself in trouble. To use a blank password, leave this parameter off
--                   altogether. 
--@args  smbhash     A password hash to use when logging in. This is given as a single hex string (32
--                   characters) or a pair of hex strings (both 32 characters, optionally separated by a
--                   single character). These hashes are the LanMan or NTLM hash of the user's password,
--                   and are stored on disk or in memory. They can be retrieved from memory
--                   using the fgdump or pwdump tools.
--@args  smbtype     The type of SMB authentication to use. These are the possible options:
-- * <code>v1</code>:     Sends LMv1 and NTLMv1.
-- * <code>LMv1</code>:   Sends LMv1 only.
-- * <code>NTLMv1</code>: Sends NTLMv1 only (default).
-- * <code>v2</code>:     Sends LMv2 and NTLMv2.
-- * <code>LMv2</code>:   Sends LMv2 only.
-- * <code>NTLMv2</code>: Doesn't exist; the protocol doesn't support NTLMv2 alone. 
--                   The default, <code>NTLMv1</code>, is a pretty decent compromise between security and 
--                   compatibility. If you are paranoid, you might want to use <code>v2</code> or 
--                   <code>lmv2</code> for this. (Actually, if you're paranoid, you should be avoiding this 
--                   protocol altogether!). If you're using an extremely old system, you might need to set 
--                   this to <code>v1</code> or <code>lm</code>, which are less secure but more compatible.  
--                   For information, see <code>smbauth.lua</code>. 

module(... or "smbauth", package.seeall)

require 'bit'
require 'bin'
require 'netbios'
require 'stdnse'

have_ssl = (nmap.have_ssl() and pcall(require, "openssl"))

-- Constants
local NTLMSSP_NEGOTIATE = 0x00000001
local NTLMSSP_CHALLENGE = 0x00000002
local NTLMSSP_AUTH      = 0x00000003

local session_key = string.rep(string.char(0x00), 16)

local function to_unicode(str)
	local unicode = ""

	for i = 1, #str, 1 do
		unicode = unicode .. bin.pack("<S", string.byte(str, i))
	end

	return unicode
end

---Generate the Lanman v1 hash (LMv1). The generated hash is incredibly easy to reverse, because the input
-- is padded or truncated to 14 characters, then split into two 7-character strings. Each of these strings
-- are used as a key to encrypt the string, "KGS!@#$%" in DES. Because the keys are no longer than 
-- 7-characters long, it's pretty trivial to bruteforce them. 
--
--@param password the password to hash
--@return (status, hash) If status is true, the hash is returned; otherwise, an error message is returned.
local function lm_create_hash(password)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local str1, str2
	local key1, key2
	local result

	-- Convert the password to uppercase
	password = string.upper(password)

	-- If password is under 14 characters, pad it to 14
	if(#password < 14) then
		password = password .. string.rep(string.char(0), 14 - #password)
	end

	-- Take the first and second half of the password (note that if it's longer than 14 characters, it's truncated)
	str1 = string.sub(password, 1, 7)
	str2 = string.sub(password, 8, 14)

	-- Generate the keys
	key1 = openssl.DES_string_to_key(str1)
	key2 = openssl.DES_string_to_key(str2)

	-- Encrypt the string "KGS!@#$%" with each half, and concatenate it
	result = openssl.encrypt("DES", key1, nil, "KGS!@#$%") .. openssl.encrypt("DES", key2, nil, "KGS!@#$%")

	return true, result
end

---Generate the NTLMv1 hash. This hash is quite a bit better than LMv1, and is far easier to generate. Basically,
-- it's the MD4 of the Unicode password. 
--
--@param password the password to hash
--@return (status, hash) If status is true, the hash is returned; otherwise, an error message is returned.
function ntlm_create_hash(password)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	return true, openssl.md4(to_unicode(password))
end

---Create the Lanman response to send back to the server. To do this, the Lanman password is padded to 21 
-- characters and split into three 7-character strings. Each of those strings is used as a key to encrypt
-- the server challenge. The three encrypted strings are concatenated and returned. 
--
--@param lanman    The LMv1 hash
--@param challenge The server's challenge. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function lm_create_response(lanman, challenge)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local str1, str2, str3
	local key1, key2, key3
	local result

	-- Pad the hash to 21 characters
	lanman = lanman .. string.rep(string.char(0), 21 - #lanman)

	-- Take the first and second half of the password (note that if it's longer than 14 characters, it's truncated)
	str1 = string.sub(lanman, 1,  7)
	str2 = string.sub(lanman, 8,  14)
	str3 = string.sub(lanman, 15, 21)

	-- Generate the keys
	key1 = openssl.DES_string_to_key(str1)
	key2 = openssl.DES_string_to_key(str2)
	key3 = openssl.DES_string_to_key(str3)

	-- Print a warning message if a blank challenge is received, and create a phony challenge. A blank challenge is
	-- invalid in the protocol, and causes some versions of OpenSSL to abort with no possible error handling. 
	if(challenge == "") then
		stdnse.print_debug(1, "SMB: ERROR: Server returned invalid (blank) challenge value (should be 8 bytes); failing login to avoid OpenSSL crash.")
		challenge = "AAAAAAAA"
	end

	-- Encrypt the challenge with each key
	result = openssl.encrypt("DES", key1, nil, challenge) .. openssl.encrypt("DES", key2, nil, challenge) .. openssl.encrypt("DES", key3, nil, challenge)

	return true, result
end

---Create the NTLM response to send back to the server. This is actually done the exact same way as the Lanman hash,
-- so I call the <code>Lanman</code> function. 
--
--@param ntlm      The NTLMv1 hash
--@param challenge The server's challenge. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function ntlm_create_response(ntlm, challenge)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	return lm_create_response(ntlm, challenge)
end

---Create the NTLM mac key, which is used for message signing. For basic authentication, this is the md4 of the 
-- NTLM hash, concatenated with the response hash; for extended authentication, this is just the md4 of the NTLM
-- hash. 
--@param ntlm_hash The NTLM hash. 
--@param ntlm_response The NTLM response. 
--@param is_extended Should be set if extended security negotiations are being used. 
function ntlm_create_mac_key(ntlm_hash, ntlm_response, is_extended)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end
	if(is_extended) then
		return openssl.md4(ntlm_hash)
	else
		return openssl.md4(ntlm_hash) .. ntlm_response
	end
end

---Create the LM mac key, which is used for message signing. For basic authentication, it's the first 8 bytes 
-- of the lanman hash, followed by 8 null bytes, followed by the lanman response; for extended authentication, 
-- this is just the first 8 bytes of the lanman hash followed by 8 null bytes. 
--@param ntlm_hash The NTLM hash. 
--@param ntlm_response The NTLM response. 
--@param is_extended Should be set if extended security negotiations are being used. 
function lm_create_mac_key(lm_hash, lm_response, is_extended)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	if(is_extended) then
		return string.sub(lm_hash, 1, 8) .. string.rep(string.char(0), 8)
	else
		return string.sub(lm_hash, 1, 8) .. string.rep(string.char(0), 8) .. lm_response
	end
end

---Create the NTLMv2 hash, which is based on the NTLMv1 hash (for easy upgrading), the username, and the domain. 
-- Essentially, the NTLM hash is used as a HMAC-MD5 key, which is used to hash the unicode domain concatenated 
-- with the unicode username. 
--
--@param ntlm     The NTLMv1 hash. 
--@param username The username we're using. 
--@param domain   The domain. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function ntlmv2_create_hash(ntlm, username, domain)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local unicode = ""

	username = to_unicode(string.upper(username))
	domain   = to_unicode(string.upper(domain))

	return true, openssl.hmac("MD5", ntlm, username .. domain)
end

---Create the LMv2 response, which can be sent back to the server. This is identical to the <code>NTLMv2</code> function, 
-- except that it uses an 8-byte client challenge. 
--
-- The reason for LMv2 is a long and twisted story. Well, not really. The reason is basically that the v1 hashes
-- are always 24-bytes, and some servers expect 24 bytes, but the NTLMv2 hash is more than 24 bytes. So, the only
-- way to keep pass-through compatibility was to have a v2-hash that was guaranteed to be 24 bytes. So LMv1 was
-- born -- it has a 16-byte hash followed by the 8-byte client challenge, for a total of 24 bytes. And now you've
-- learned something
--
--@param ntlm      The NVLMv1 hash.
--@param username  The username we're using. 
--@param domain    The domain. 
--@param challenge The server challenge. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function lmv2_create_response(ntlm, username, domain, challenge)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	return ntlmv2_create_response(ntlm, username, domain, challenge, 8)
end

---Create the NTLMv2 response, which can be sent back to the server. This is done by using the HMAC-MD5 algorithm
-- with the NTLMv2 hash as a key, and the server challenge concatenated with the client challenge for the data. 
-- The resulting hash is concatenated with the client challenge and returned.
--
-- The "proper" implementation for this uses a certain structure for the client challenge, involving the time
-- and computer name and stuff (if you don't do this, Wireshark tells you it's a malformed packet). In my tests, 
-- however, I couldn't get Vista to recognize a client challenge longer than 24 bytes, and this structure was
-- guaranteed to be much longer than 24 bytes. So, I just use a random string generated by OpenSSL. I've tested
-- it on every Windows system from Windows 2000 to Windows Vista, and it has always worked. 
function ntlmv2_create_response(ntlm, username, domain, challenge, client_challenge_length)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local client_challenge = openssl.rand_bytes(client_challenge_length)

	local status, ntlmv2_hash = ntlmv2_create_hash(ntlm, username, domain)

	return true, openssl.hmac("MD5", ntlmv2_hash, challenge .. client_challenge) .. client_challenge
end

---Determines which hash type is going to be used, based on the function parameters and 
-- the nmap arguments (in that order).
--
--@param hash_type [optional] The function parameter version, which will override all others if set. 
--@return The highest priority hash type that's set.
local function get_hash_type(hash_type)
	
	if(hash_type ~= nil) then
		stdnse.print_debug(2, "SMB: Using logon type passed as a parameter: %s", hash_type)
	else
		if(nmap.registry.args.smbtype ~= nil) then
			hash_type = nmap.registry.args.smbtype
			stdnse.print_debug(2, "SMB: Using logon type passed as an nmap parameter: %s", hash_type)
		else
			hash_type = "ntlm"
			stdnse.print_debug(2, "SMB: Using default logon type: %s", hash_type)
		end
	end

	return string.lower(hash_type)
end


---Determines which username is going to be used, based on the function parameters, the nmap arguments, 
-- and the registry (in that order).
--
--@param ip       The ip address, used when reading from the registry
--@param username [optional] The function parameter version, which will override all others if set. 
--@return The highest priority username that's set.
local function get_username(ip, username)

	if(username ~= nil) then
		stdnse.print_debug(2, "SMB: Using username passed as a parameter: %s", username)
	else
		if(nmap.registry.args.smbusername ~= nil) then
			username = nmap.registry.args.smbusername
			stdnse.print_debug(2, "SMB: Using username passed as an nmap parameter (smbusername): %s", username)
		elseif(nmap.registry.args.smbuser ~= nil) then
			username = nmap.registry.args.smbuser
			stdnse.print_debug(2, "SMB: Using username passed as an nmap parameter (smbuser): %s", username)
		elseif(nmap.registry[ip] ~= nil and nmap.registry[ip]['smbaccount'] ~= nil and nmap.registry[ip]['smbaccount']['username'] ~= nil) then
			username = nmap.registry[ip]['smbaccount']['username']
			stdnse.print_debug(2, "SMB: Using username found in the registry: %s", username)
		else
			username = nil
			stdnse.print_debug(2, "SMB: Couldn't find a username to use, not logging in")
		end
	end

	return username
end

---Determines which domain is going to be used, based on the function parameters and 
-- the nmap arguments (in that order).
--
-- [TODO] registry
--
--@param domain [optional] The function parameter version, which will override all others if set. 
--@return The highest priority domain that's set.
local function get_domain(ip, domain)

	if(domain ~= nil) then
		stdnse.print_debug(2, "SMB: Using domain passed as a parameter: %s", domain)
	else
		if(nmap.registry.args.smbdomain ~= nil) then
			domain = nmap.registry.args.smbdomain
			stdnse.print_debug(2, "SMB: Using domain passed as an nmap parameter: %s", domain)
		else
			domain = ""
			stdnse.print_debug(2, "SMB: Couldn't find domain to use, using blank")
		end
	end

	return domain
end

---Generate the Lanman and NTLM password hashes. The password itself is taken from the function parameters,
-- the nmap arguments, and the registry (in that order). If no password is set, then the password hash
-- is used (which is read from all the usual places). If neither is set, then a blank password is used. 
--
-- The output passwords are hashed based on the hash type. 
--
--@param ip       The ip address of the host, used for registry lookups. 
--@param username The username, which is used for v2 passwords. 
--@param domain The username, which is used for v2 passwords. 
--@param password [optional] The overriding password. 
--@param password_hash [optional] The overriding password hash. Shouldn't be set if password is set. 
--@param challenge The server challenge.
--@param hash_type The way in which to hash the password. 
--@param is_extended Set to 'true' if extended security negotiations are being used (this has to be known for the
--                   message-signing key to be generated properly). 
--@return (lm_response, ntlm_response, mac_key) The two strings that can be sent directly back to the server, 
--                 and the mac_key, which is used for message signing. 
local function get_password_response(ip, username, domain, password, password_hash, challenge, hash_type, is_extended)

    local status
	local lm_hash   = nil
	local ntlm_hash = nil
	local mac_key   = nil
    local lm_response, ntlm_response

	-- Check if there's a password or hash set. This is a little tricky, because in all places (except the one passed
	-- as a parameter), it's based on whether or not the username was stored. This lets us use blank passwords by not
	-- specifying one. 
	if(password ~= nil) then
		stdnse.print_debug(2, "SMB: Using password/hash passed as a parameter (username = '%s')", username)

	elseif(nmap.registry.args.smbusername ~= nil or nmap.registry.args.smbuser ~= nil) then
		stdnse.print_debug(2, "SMB: Using password/hash passed as an nmap parameter")

		if(nmap.registry.args.smbpassword ~= nil) then
			password = nmap.registry.args.smbpassword
		elseif(nmap.registry.args.smbpass ~= nil) then
			password = nmap.registry.args.smbpass
		elseif(nmap.registry.args.smbhash ~= nil) then
			password_hash = nmap.registry.args.smbhash
		end

	elseif(nmap.registry[ip] ~= nil and nmap.registry[ip]['smbaccount'] ~= nil and nmap.registry[ip]['smbaccount']['username'] ~= nil) then
		stdnse.print_debug(2, "SMB: Using password/hash found in the registry")

		if(nmap.registry[ip]['smbaccount']['password'] ~= nil) then
			password = nmap.registry[ip]['smbaccount']['password']
		elseif(nmap.registry[ip]['smbaccount']['hash'] ~= nil) then
			password_hash = nmap.registry[ip]['smbaccount']['password']
		end

	else
		password = nil
		password_hash = nil
	end

	-- Check for a blank password
	if(password == nil and password_hash == nil) then
		stdnse.print_debug(2, "SMB: Couldn't find password or hash to use (assuming blank)")
		password = ""
	end

	-- If we got a password, hash it
	if(password ~= nil) then
		status, lm_hash   = lm_create_hash(password)
		status, ntlm_hash = ntlm_create_hash(password)
	else
		if(password_hash ~= nil) then
			if(string.find(password_hash, "^" .. string.rep("%x%x", 16) .. "$")) then
				stdnse.print_debug(2, "SMB: Found a 16-byte hex string")
				lm_hash   = bin.pack("H", password_hash:sub(1, 32))
				ntlm_hash = bin.pack("H", password_hash:sub(1, 32))
			elseif(string.find(password_hash, "^" .. string.rep("%x%x", 32) .. "$")) then
				stdnse.print_debug(2, "SMB: Found a 32-byte hex string")
				lm_hash   = bin.pack("H", password_hash:sub(1, 32))
				ntlm_hash = bin.pack("H", password_hash:sub(33, 64))
			elseif(string.find(password_hash, "^" .. string.rep("%x%x", 16) .. "." .. string.rep("%x%x", 16) .. "$")) then
				stdnse.print_debug(2, "SMB: Found two 16-byte hex strings")
				lm_hash   = bin.pack("H", password_hash:sub(1, 32))
				ntlm_hash = bin.pack("H", password_hash:sub(34, 65))
			else
				stdnse.print_debug(1, "SMB: ERROR: Hash(es) provided in an invalid format (should be 32, 64, or 65 hex characters)")
				lm_hash = nil
				ntlm_hash = nil
			end
		end
	end

	-- At this point, we should have a good lm_hash and ntlm_hash if we're getting one
	if(lm_hash == nil or ntlm_hash == nil) then
		stdnse.print_debug(2, "SMB: Couldn't determine which password to use, using a blank one")
		return "", ""
	end

	-- Output what we've got so far
	stdnse.print_debug(2, "SMB: Lanman hash: %s", stdnse.tohex(lm_hash))
	stdnse.print_debug(2, "SMB: NTLM   hash: %s", stdnse.tohex(ntlm_hash))
			
	-- Hash the password the way the user wants
	if(hash_type == "v1") then
		-- LM and NTLM are hashed with their respective algorithms
		stdnse.print_debug(2, "SMB: Creating v1 response")
		status, lm_response   = lm_create_response(lm_hash, challenge)
		status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)

		mac_key               = ntlm_create_mac_key(ntlm_hash, ntlm_response, is_extended)

	elseif(hash_type == "lm") then
		-- LM is hashed with its algorithm, NTLM is blank
		stdnse.print_debug(2, "SMB: Creating LMv1 response")
		status, lm_response   = lm_create_response(lm_hash, challenge)
		        ntlm_response = ""

		mac_key               = lm_create_mac_key(lm_hash, lm_response, is_extended)

	elseif(hash_type == "ntlm") then
		-- LM and NTLM both use the NTLM algorithm
		stdnse.print_debug(2, "SMB: Creating NTLMv1 response")
		status, lm_response   = ntlm_create_response(ntlm_hash, challenge)
		status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)

		mac_key               = ntlm_create_mac_key(ntlm_hash, ntlm_response, is_extended)

	elseif(hash_type == "v2") then
		-- LM and NTLM are hashed with their respective v2 algorithms
		stdnse.print_debug(2, "SMB: Creating v2 response")
		status, lm_response   = lmv2_create_response(ntlm_hash, username, domain, challenge)
		status, ntlm_response = ntlmv2_create_response(ntlm_hash, username, domain, challenge, 24)

	elseif(hash_type == "lmv2") then
		-- LM is hashed with its v2 algorithm, NTLM is blank
		stdnse.print_debug(2, "SMB: Creating LMv2 response")
		status, lm_response   = lmv2_create_response(ntlm_hash, username, domain, challenge)
		        ntlm_response = ""

	else
		-- Default to NTLMv1
		stdnse.print_debug(1, "SMB: Invalid login type specified, using default (NTLM)")
		status, lm_response   = ntlm_create_response(ntlm_hash, challenge)
		status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)

	end

	stdnse.print_debug(2, "SMB: Lanman response: %s", stdnse.tohex(lm_response))
	stdnse.print_debug(2, "SMB: NTLM   response: %s", stdnse.tohex(ntlm_response))

	return lm_response, ntlm_response, mac_key
end

---Get the list of accounts to use to log in. TODO: More description
function get_accounts(ip, overrides, use_defaults)
	local results = {}
	-- Just so we can index into it
	if(overrides == nil) then
		overrides = {}
	end
	-- By default, use defaults
	if(use_defaults == nil) then
		use_defaults = true
	end

	-- If we don't have OpenSSL, don't bother with any of this because we aren't going to 
	-- be able to hash the password
	if(have_ssl == true) then
		local result = {}

		-- Get the "real" information
		result['username']  = get_username(ip, overrides['username'])
		result['domain']    = get_domain(ip,   overrides['domain'])
		result['hash_type'] = get_hash_type(overrides['hash_type'])

		if(result['username'] ~= nil) then
			results[#results + 1] = result
		end

		-- Do the "guest" account, if use_defaults is set
		if(use_defaults) then
			result = {}
			result['username'] = "guest"
			result['domain']   = ""
			result['hash_type'] = get_hash_type(overrides['hash_type'])
			results[#results + 1] = result
		end
	end

	-- Do the "anonymous" account
	if(use_defaults) then
		local result = {}
		result['username'] = ""
		result['domain']   = ""
		results[#results + 1] = result
	end

	return results
end

function get_password_hashes(ip, username, domain, hash_type, overrides, challenge, is_extended)
	if(overrides == nil) then
		overrides = {}
	end

	if(username == "") then
		return string.char(0), '', nil
	elseif(username == "guest") then
		return get_password_response(ip, username, domain, "", nil, challenge, hash_type, is_extended)
	else
		return get_password_response(ip, username, domain, overrides['password'], overrides['password_hash'], challenge, hash_type, is_extended)
	end
end

function get_security_blob(security_blob, ip, username, domain, hash_type, overrides, use_default)
	local pos = 1
	local new_blob
	local flags = 0x00008211 -- (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | NEGOTIATE_UNICODE)

	if(security_blob == nil) then
		-- If security_blob is nil, this is the initial packet
		new_blob = bin.pack("<zIILL", 
					"NTLMSSP",            -- Identifier
					NTLMSSP_NEGOTIATE,    -- Type
					flags,                -- Flags 
					0,                    -- Calling workstation domain
					0                     -- Calling workstation name
				)

		return true, new_blob, "", ""
	else
		local identifier, message_type, domain_length, domain_max, domain_offset, server_flags, challenge, reserved

		-- Parse the old security blob
		pos, identifier, message_type, domain_length, domain_max, domain_offset, server_flags, challenge, reserved = bin.unpack("<LISSIIA8A8", security_blob, 1)

		-- Get the information for the current login
        local lanman, ntlm, mac_key = get_password_hashes(ip, username, domain, hash_type, overrides, challenge, true)

		-- Convert the username and domain to unicode (TODO: Disable the unicode flag, evaluate if that'll work)
		username = to_unicode(username)
		domain   = to_unicode(domain)

		new_blob = bin.pack("<zISSISSISSISSISSISSII", 
					"NTLMSSP",            -- Identifier
					NTLMSSP_AUTH,         -- Type
					#lanman,              -- Lanman (length, max, offset)
					#lanman,              -- 
					0x40,                 -- 
					#ntlm,                -- NTLM (length, max, offset)
					#ntlm,                -- 
					0x40 + #lanman,       -- 
					#domain,              -- Domain (length, max, offset)
					#domain,              --
					0x40 + #lanman + #ntlm,--
					#username,            -- Username (length, max, offset)
					#username,            -- 
					0x40 + #lanman + #ntlm + #domain,
					#domain,              -- Hostname (length, max, offset)
					#domain,              --
					0x40 + #lanman + #ntlm + #domain + #username,
					#session_key,         -- Session key (length, max, offset)
					#session_key,         --
					0x40 + #lanman + #ntlm + #domain + #username + #domain,
					flags                 -- Flags
				)

		new_blob = new_blob .. bin.pack("AAAAAA", lanman, ntlm, domain, username, domain, session_key)
		return true, new_blob, mac_key
	end

end

---Create an 8-byte message signature that's sent with all SMB packets. 
--
--@param mac_key The key used for authentication. It's the concatination of the session key and the
--               response hash. 
--@param data The packet to generate the signature for. This should be the packet that's about to be
--            sent, except with the signature slot replaced with the sequence number. 
--@return The 8-byte signature. The signature is equal to the first eight bytes of md5(mac_key .. smb_data)
function calculate_signature(mac_key, data)
	if(have_ssl) then
		return string.sub(openssl.md5(mac_key .. data), 1, 8)
	else
		return string.rep(string.char(0), 8)
	end
end











