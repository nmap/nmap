---
-- This module takes care of the authentication used in SMB (LM, NTLM, LMv2, NTLMv2). 
--
-- There is a lot to this functionality, so if you're interested in how it works, read
-- on. 
-- In SMB authentication, there are two distinct concepts. Each will be dealt with
-- separately. There are:
-- * Stored hashes
-- * Authentication
--
-- What's confusing is that the same names are used for each of those. 
--
-- Stored Hashes:
-- Windows stores two types of hashes: Lanman and NT Lanman (or NTLM). Vista and later
-- store NTLM only. Lanman passwords are divided into two 7-character passwords and 
-- used as a key in DES, while NTLM is converted to unicode and MD4ed. 
--
-- The stored hashes can be dumped in a variety of ways (pwdump6, fgdump, Metasploit's
-- <code>priv</code> module, <code>smb-psexec.nse</code>, etc). Generally, two hashes are dumped together 
-- (generally, Lanman:NTLM). Sometimes, Lanman is empty and only NTLM is given. Lanman
-- is never required. 
--
-- The password hashes can be given instead of passwords when supplying credentials; 
-- this is done by using the <code>smbhash</code> argument. Either a pair of hashes
-- can be passed, in the form of Lanman:NTLM, or a single hash, which is assumed to
-- be NTLM. 
--
-- Authentication:
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
--@args smbnoguest   Use to disable usage of the 'guest' account. 

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

-- Types of accounts (ordered by how useful they are
local ACCOUNT_TYPES = {
	ANONYMOUS = 0,
	GUEST     = 1,
	USER      = 2,
	ADMIN     = 3
}

local function account_exists(host, username, domain)
	if(nmap.registry[host.ip] == nil or nmap.registry[host.ip]['smbaccounts'] == nil) then
		return false
	end

	for i, j in pairs(nmap.registry[host.ip]['smbaccounts']) do
		if(j['username'] == username and j['domain'] == domain) then
			return true
		end
	end

	return false
end

function next_account(host, num)
	if(num == nil) then
		if(nmap.registry[host.ip]['smbindex'] == nil) then
			nmap.registry[host.ip]['smbindex'] = 1
		else
			nmap.registry[host.ip]['smbindex'] = nmap.registry[host.ip]['smbindex'] + 1
		end
	else
		nmap.registry[host.ip]['smbindex'] = num
	end
end

---Writes the given account to the registry. There are several places where accounts are stored:
-- * registry['usernames'][username]    => true
-- * registry['smbaccounts'][username]  => password
-- * registry[ip]['smbaccounts']        => array of table containing 'username', 'password', and 'is_admin'
--
-- The final place, 'smbaccount', is reserved for the "best" account. This is an administrator
-- account, if one's found; otherwise, it's the first account discovered that isn't <code>guest</code>. 
--
-- This has to be called while no SMB connections are made, since it potentially makes its own connection.
--
--@param host          The host object. 
--@param username      The username to add. 
--@param domain        The domain to add. 
--@param password      The password to add. 
--@param password_hash The password hash to add. 
--@param hash_type     The hash type to use.
--@param is_admin      [optional] Set to 'true' the account is known to be an administrator. 
function add_account(host, username, domain, password, password_hash, hash_type, is_admin)
	-- Save the username in a global list -- TODO: restore this
--	if(nmap.registry.usernames == nil) then
--		nmap.registry.usernames = {}
--	end
--	nmap.registry.usernames[username] = true
--
--	-- Save the username/password pair in a global list
--	if(nmap.registry.smbaccounts == nil) then
--		nmap.registry.smbaccounts = {}
--	end
--	nmap.registry.smbaccounts[username] = password

	-- Check if we've already recorded this account
	if(account_exists(host, username, domain)) then
		return
	end

	if(nmap.registry[host.ip] == nil) then
		nmap.registry[host.ip] = {}
	end
	if(nmap.registry[host.ip]['smbaccounts'] == nil) then
		nmap.registry[host.ip]['smbaccounts'] = {}
	end

	-- Determine the type of account, if it wasn't given
	local account_type = nil
	if(is_admin) then
		account_type = ACCOUNT_TYPES.ADMIN
	else
		if(username == '') then
			-- Anonymous account
			account_type = ACCOUNT_TYPES.ANONYMOUS
		elseif(string.lower(username) == 'guest') then
			-- Guest account
			account_type = ACCOUNT_TYPES.GUEST
		else
			-- We have to assume it's a user-level account (we just can't call any SMB functions from inside here)
			account_type = ACCOUNT_TYPES.USER
		end
	end

	-- Set some defaults
	if(hash_type == nil) then
		hash_type = 'ntlm'
	end

	-- Save the new account if this is our first one, or our other account isn't an admin
	local new_entry = {}
	new_entry['username']      = username
	new_entry['domain']        = domain
	new_entry['password']      = password
	new_entry['password_hash'] = password_hash
	new_entry['hash_type']     = string.lower(hash_type)
	new_entry['account_type']  = account_type

	-- Insert the new entry into the table
	table.insert(nmap.registry[host.ip]['smbaccounts'], new_entry)

	-- Sort the table based on the account type (we want anonymous at the end, administrator at the front)
	table.sort(nmap.registry[host.ip]['smbaccounts'], function(a,b) return a['account_type'] > b['account_type'] end)

	-- Print a debug message
	stdnse.print_debug(1, "SMB: Added account '%s' to account list", username)

	-- Reset the credentials
	next_account(host, 1)

--	io.write("\n\n" .. nsedebug.tostr(nmap.registry[host.ip]['smbaccounts']) .. "\n\n")
end

---Retrieve the current set of credentials set in the registry. If these fail, <code>next_credentials</code> should be
-- called. 
--
--@param host The host object. 
--@return (result, username, domain, password, password_hash, hash_type) If result is false, username is an error message. Otherwise, username and password are
--        the current username and password that should be used. 
function get_account(host)
	if(nmap.registry[host.ip]['smbindex'] == nil) then
		nmap.registry[host.ip]['smbindex'] = 1
	end

	local index = nmap.registry[host.ip]['smbindex']
	local account = nmap.registry[host.ip]['smbaccounts'][index]

	if(account == nil) then
		return false, "No accounts left to try"
	end

	return true, account['username'], account['domain'], account['password'], account['password_hash'], account['hash_type']
end

---Create the account table with the anonymous and guest users, as well as the user given in the script's
-- arguments, if there is one. 
--
--@param host The host object. 
function init_account(host)
	-- Create the key if it exists
	if(nmap.registry[host.ip] == nil) then
		nmap.registry[host.ip] = {}
	end

	-- Don't run this more than once for each host
	if(nmap.registry[host.ip]['smbaccounts'] ~= nil) then
		return
	end

	-- Create the list
	nmap.registry[host.ip]['smbaccounts'] = {}

	-- Add the anonymous/guest accounts
	add_account(host, '',      '', '', nil, 'none')

	if(not stdnse.get_script_args( "smbnoguest" )) then
		add_account(host, 'guest', '', '', nil, 'ntlm')
	end

	-- Add the account given on the commandline (TODO: allow more than one?)
	local args = nmap.registry.args
	local username      = nil
	local domain        = ''
	local password      = nil
	local password_hash = nil
	local hash_type     = 'ntlm'

	-- Do the username first
	if(args.smbusername ~= nil) then
		username = args.smbusername
	elseif(args.smbuser ~= nil) then
		username = args.smbuser
	end

	-- If the username exists, do everything else
	if(username ~= nil) then
		-- Domain
		if(args.smbdomain ~= nil) then
			domain = args.smbdomain
		end

		-- Type
		if(args.smbtype ~= nil) then
			hash_type = args.smbtype
		end

		-- Do the password
		if(args.smbpassword ~= nil) then
			password = args.smbpassword
		elseif(args.smbpass ~= nil) then
			password = args.smbpass
		end

		-- Only use the hash if there's no password
		if(password == nil) then
			password_hash = args.smbhash
		end

		-- Add the account, if we got a password
		if(password == nil and password_hash == nil) then
			stdnse.print_debug(1, "SMB: Either smbpass, smbpassword, or smbhash have to be passed as script arguments to use an account")
		else
			add_account(host, username, domain, password, password_hash, hash_type)
		end
	end
end

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
--@param lm_hash The NTLM hash. 
--@param lm_response The NTLM response. 
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
function get_password_response(ip, username, domain, password, password_hash, hash_type, challenge, is_extended)
    local status
	local lm_hash   = nil
	local ntlm_hash = nil
	local mac_key   = nil
    local lm_response, ntlm_response

	-- Check for a blank password
	if(password == nil and password_hash == nil) then
		stdnse.print_debug(2, "SMB: Couldn't find password or hash to use (assuming blank)")
		password = ""
	end

	-- The anonymous user requires a single 0-byte instead of a LANMAN hash (don't ask me why, but it doesn't work without)
	if(hash_type == 'none') then
		return string.char(0), '', nil
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
		if(hash_type ~= nil) then
			stdnse.print_debug(1, "SMB: Invalid login type specified ('%s'), using default (NTLM)", hash_type)
		else
			stdnse.print_debug(1, "SMB: No login type specified, using default (NTLM)")
		end
	
		status, lm_response   = ntlm_create_response(ntlm_hash, challenge)
		status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)

	end

	stdnse.print_debug(2, "SMB: Lanman response: %s", stdnse.tohex(lm_response))
	stdnse.print_debug(2, "SMB: NTLM   response: %s", stdnse.tohex(ntlm_response))

	return lm_response, ntlm_response, mac_key
end

function get_security_blob(security_blob, ip, username, domain, password, password_hash, hash_type)
	local pos = 1
	local new_blob
	local flags = 0x00008215 -- (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)

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
        local lanman, ntlm, mac_key = get_password_response(ip, username, domain, password, password_hash, hash_type, challenge, true)

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











