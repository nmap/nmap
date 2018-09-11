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
--@args  smbdomain   The domain to log in with. If you aren't in a domain environment, then anything
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

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unicode = require "unicode"
local unittest = require "unittest"
_ENV = stdnse.module("smbauth", stdnse.seeall)

local have_ssl, openssl = pcall(require, "openssl")

-- Constants
local NTLMSSP_NEGOTIATE = 0x00000001
local NTLMSSP_CHALLENGE = 0x00000002
local NTLMSSP_AUTH      = 0x00000003

local session_key = string.rep("\0", 16)

-- Types of accounts (ordered by how useful they are
local ACCOUNT_TYPES = {
  ANONYMOUS = 0,
  GUEST     = 1,
  USER      = 2,
  ADMIN     = 3
}

local function account_exists(host, username, domain)
  if(host.registry['smbaccounts'] == nil) then
    return false
  end

  for i, j in pairs(host.registry['smbaccounts']) do
    if(j['username'] == username and j['domain'] == domain) then
      return true
    end
  end

  return false
end

--- Try the next stored account for this host
-- @param host The host table
-- @param num If nil, the next account is chosen. If a number, the account at
--            that index is chosen
function next_account(host, num)
  if(num == nil) then
    if(host.registry['smbindex'] == nil) then
      host.registry['smbindex'] = 1
    else
      host.registry['smbindex'] = host.registry['smbindex'] + 1
    end
  else
    host.registry['smbindex'] = num
  end
end

---Writes the given account to the registry.
--
-- There are several places where accounts are stored:
-- * registry['usernames'][username]    => true
-- * registry['smbaccounts'][username]  => password
-- * registry[ip]['smbaccounts']        => array of table containing 'username', 'password', and 'is_admin'
--
-- The final place, 'smbaccount', is reserved for the "best" account. This is
-- an administrator account, if one's found; otherwise, it's the first account
-- discovered that isn't <code>guest</code>.
--
-- This has to be called while no SMB connections are made, since it
-- potentially makes its own connection.
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
  --  if(nmap.registry.usernames == nil) then
  --    nmap.registry.usernames = {}
  --  end
  --  nmap.registry.usernames[username] = true
  --
  --  -- Save the username/password pair in a global list
  --  if(nmap.registry.smbaccounts == nil) then
  --    nmap.registry.smbaccounts = {}
  --  end
  --  nmap.registry.smbaccounts[username] = password

  -- Check if we've already recorded this account
  if(account_exists(host, username, domain)) then
    return
  end

  if(host.registry['smbaccounts'] == nil) then
    host.registry['smbaccounts'] = {}
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
  table.insert(host.registry['smbaccounts'], new_entry)

  -- Sort the table based on the account type (we want anonymous at the end, administrator at the front)
  table.sort(host.registry['smbaccounts'], function(a,b) return a['account_type'] > b['account_type'] end)

  -- Print a debug message
  stdnse.debug1("SMB: Added account '%s' to account list", username)

  -- Reset the credentials
  next_account(host, 1)

  -- io.write("\n\n" .. nsedebug.tostr(host.registry['smbaccounts']) .. "\n\n")
end

---Retrieve the current set of credentials set in the registry.
--
-- If these fail, <code>next_account</code> should be called.
--
--@param host The host object.
--@return status true or false. If false, the next return value is an error
--        message and no other values are returned.
--@return username
--@return domain
--@return password
--@return password_hash
--@return hash_type
--@see next_account
function get_account(host)
  if(host.registry['smbindex'] == nil) then
    host.registry['smbindex'] = 1
  end

  local index = host.registry['smbindex']
  local account = host.registry['smbaccounts'][index]

  if(account == nil) then
    return false, "No accounts left to try"
  end

  return true, account['username'], account['domain'], account['password'], account['password_hash'], account['hash_type']
end

---Initialize the host's account table.
--
-- Create the account table with the anonymous and guest users, as well as the
-- user given in the script's arguments, if there is one.
--
--@param host The host object.
function init_account(host)
  -- Don't run this more than once for each host
  if(host.registry['smbaccounts'] ~= nil) then
    return
  end

  -- Create the list
  host.registry['smbaccounts'] = {}

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
      stdnse.debug1("SMB: Either smbpass, smbpassword, or smbhash have to be passed as script arguments to use an account")
    else
      add_account(host, username, domain, password, password_hash, hash_type)
    end
  end
end

---Generate the Lanman v1 hash (LMv1).
--
-- The generated hash is incredibly easy to reverse, because the input is
-- padded or truncated to 14 characters, then split into two 7-character
-- strings. Each of these strings are used as a key to encrypt the string,
-- "KGS!@#$%" in DES. Because the keys are no longer than 7-characters long,
-- it's pretty trivial to bruteforce them.
--
--@param password the password to hash
--@return true on success, or false on error
--@return The LMv1 hash
local function lm_create_hash(password)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  local str1, str2
  local key1, key2
  local result

  -- Convert the password to uppercase
  password = string.upper(password)

  -- Encode the password in OEM code page
  -- Supporting all the OEM code pages would be burdensome, so we try to
  -- convert to CP437, the default for US-English Windows, which is
  -- used for Alt+NumPad "unicode" entry in all versions of Windows.
  -- https://en.wikipedia.org/wiki/Code_page_437
  do
    local buf = {}
    for i, cp in ipairs(unicode.decode(password, unicode.utf8_dec)) do
      local ch = unicode.cp437_enc(cp)
      if ch == nil then
        return false, "Couldn't encode password in CP437"
      end
      buf[i] = ch
    end
    password = table.concat(buf)
  end

  -- If password is under 14 characters, pad it to 14
  password = password .. string.rep('\0', 14 - #password)

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

---Generate the NTLMv1 hash.
--
-- This hash is quite a bit better than LMv1, and is far easier to generate.
-- Basically, it's the MD4 of the Unicode password.
--
--@param password the password to hash
--@return true on success, or false on error
--@return The NTLMv1 hash
function ntlm_create_hash(password)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  return true, openssl.md4(unicode.utf8to16(password))
end

---Create the Lanman response to send back to the server.
--
-- To do this, the Lanman password is padded to 21 characters and split into
-- three 7-character strings. Each of those strings is used as a key to encrypt
-- the server challenge. The three encrypted strings are concatenated and
-- returned.
--
--@param lanman    The LMv1 hash
--@param challenge The server's challenge.
--@return true on success, or false on error
--@return The client challenge response, or an error message
function lm_create_response(lanman, challenge)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  local str1, str2, str3
  local key1, key2, key3
  local result

  -- Pad the hash to 21 characters
  lanman = lanman .. string.rep('\0', 21 - #lanman)

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
    stdnse.debug1("SMB: ERROR: Server returned invalid (blank) challenge value (should be 8 bytes); failing login to avoid OpenSSL crash.")
    challenge = "AAAAAAAA"
  end

  -- Encrypt the challenge with each key
  result = openssl.encrypt("DES", key1, nil, challenge) .. openssl.encrypt("DES", key2, nil, challenge) .. openssl.encrypt("DES", key3, nil, challenge)

  return true, result
end

---Create the NTLM response to send back to the server.
--
-- This is actually done the exact same way as the Lanman hash,
-- so I call the <code>Lanman</code> function.
--
--@param ntlm      The NTLMv1 hash
--@param challenge The server's challenge.
--@return true on success, or false on error
--@return The client challenge response, or an error message
function ntlm_create_response(ntlm, challenge)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  return lm_create_response(ntlm, challenge)
end

---Create the NTLM mac key, which is used for message signing.
--
-- For basic authentication, this is the md4 of the NTLM hash, concatenated
-- with the response hash; for extended authentication, this is just the md4 of
-- the NTLM hash.
--
--@param ntlm_hash The NTLM hash.
--@param ntlm_response The NTLM response.
--@param is_extended Should be set if extended security negotiations are being used.
--@return The NTLM mac key
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

---Create the LM mac key, which is used for message signing.
--
-- For basic authentication, it's the first 8 bytes of the lanman hash,
-- followed by 8 null bytes, followed by the lanman response; for extended
-- authentication, this is just the first 8 bytes of the lanman hash followed
-- by 8 null bytes.
--
--@param lm_hash The LM hash.
--@param lm_response The LM response.
--@param is_extended Should be set if extended security negotiations are being used.
--@return The LM mac key
function lm_create_mac_key(lm_hash, lm_response, is_extended)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  if(is_extended) then
    return string.sub(lm_hash, 1, 8) .. string.rep('\0', 8)
  else
    return string.sub(lm_hash, 1, 8) .. string.rep('\0', 8) .. lm_response
  end
end

---Create the NTLMv2 hash.
--
-- The NTLMv2 hash is based on the NTLMv1 hash (for easy upgrading), the
-- username, and the domain.  Essentially, the NTLM hash is used as a HMAC-MD5
-- key, which is used to hash the unicode domain concatenated with the unicode
-- username.
--
--@param ntlm     The NTLMv1 hash.
--@param username The username we're using.
--@param domain   The domain.
--@return true on success, or false on error
--@return The NTLMv2 hash or an error message
function ntlmv2_create_hash(ntlm, username, domain)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  username = unicode.utf8to16(string.upper(username))
  domain   = unicode.utf8to16(string.upper(domain))

  return true, openssl.hmac("MD5", ntlm, username .. domain)
end

---Create the LMv2 response, which can be sent back to the server.
--
-- This is identical to the <code>NTLMv2</code> function,
-- except that it uses an 8-byte client challenge.
--
-- The reason for LMv2 is a long and twisted story. Well, not really. The
-- reason is basically that the v1 hashes are always 24-bytes, and some servers
-- expect 24 bytes, but the NTLMv2 hash is more than 24 bytes. So, the only way
-- to keep pass-through compatibility was to have a v2-hash that was guaranteed
-- to be 24 bytes. So LMv2 was born -- it has a 16-byte hash followed by the
-- 8-byte client challenge, for a total of 24 bytes. And now you've learned
-- something
--
--@param ntlm      The NVLMv1 hash.
--@param username  The username we're using.
--@param domain    The domain.
--@param challenge The server challenge.
--@return true on success, or false on error
--@return The LMv2 response, or an error message
function lmv2_create_response(ntlm, username, domain, challenge)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  return ntlmv2_create_response(ntlm, username, domain, challenge, 8)
end

---Create the NTLMv2 response, which can be sent back to the server.
--
-- This is done by using the HMAC-MD5 algorithm with the NTLMv2 hash as a key,
-- and the server challenge concatenated with the client challenge for the
-- data.  The resulting hash is concatenated with the client challenge and
-- returned.
--
-- The "proper" implementation for this uses a certain structure for the client
-- challenge, involving the time and computer name and stuff (if you don't do
-- this, Wireshark tells you it's a malformed packet). In my tests, however, I
-- couldn't get Vista to recognize a client challenge longer than 24 bytes, and
-- this structure was guaranteed to be much longer than 24 bytes. So, I just
-- use a random string generated by OpenSSL. I've tested it on every Windows
-- system from Windows 2000 to Windows Vista, and it has always worked.
--
--@param ntlm      The NVLMv1 hash.
--@param username  The username we're using.
--@param domain    The domain.
--@param challenge The server challenge.
--@param client_challenge_length number of random bytes of client challenge to use
--@return true on success, or false on error
--@return The NTLMv2 response, or an error message
function ntlmv2_create_response(ntlm, username, domain, challenge, client_challenge_length)
  if(have_ssl ~= true) then
    return false, "SMB: OpenSSL not present"
  end

  local client_challenge = openssl.rand_bytes(client_challenge_length)

  local status, ntlmv2_hash = ntlmv2_create_hash(ntlm, username, domain)

  return true, openssl.hmac("MD5", ntlmv2_hash, challenge .. client_challenge) .. client_challenge
end


--- Generates the ntlmv2 session response.
-- It starts by generatng an 8 byte random client nonce, it is padded to 24 bytes.
-- The padded value is the lanman response. A session nonce is made by
-- concatenating the server challenge and the client nonce. The ntlm session hash
-- is first 8 bytes of the md5 hash of the session nonce.
-- The ntlm response is the lm response with session hash as challenge.
-- @param ntlm_passsword_hash The md4 hash of the utf-16 password.
-- @param challenge The challenge sent by the server.
function ntlmv2_session_response(ntlm_password_hash, challenge)
  local client_nonce = openssl.rand_bytes(8)

  local lm_response = client_nonce .. string.rep('\0', 24 - #client_nonce)
  local session_nonce = challenge .. client_nonce
  local ntlm_session_hash  = openssl.md5(session_nonce):sub(1,8)

  local status, ntlm_response =  lm_create_response(ntlm_password_hash, ntlm_session_hash)

  return status, lm_response, ntlm_response
end
---Generate the Lanman and NTLM password hashes.
--
-- The password itself is taken from the function parameters, the script
-- arguments, and the registry (in that order). If no password is set, then the
-- password hash is used (which is read from all the usual places). If neither
-- is set, then a blank password is used.
--
-- The output passwords are hashed based on the hash type.
--
--@param ip       The ip address of the host, used for registry lookups.
--@param username The username, which is used for v2 passwords.
--@param domain The username, which is used for v2 passwords.
--@param password [optional] The overriding password.
--@param password_hash [optional] The overriding password hash. Shouldn't be
--                     set if password is set.
--@param challenge The server challenge.
--@param hash_type The way in which to hash the password.
--@param is_extended Set to 'true' if extended security negotiations are being
--                   used (this has to be known for the message-signing key to
--                   be generated properly).
--@return lm_response, to be send directly back to the server
--@return ntlm_response, to be send directly back to the server
--@reutrn mac_key used for message signing.
function get_password_response(ip, username, domain, password, password_hash, hash_type, challenge, is_extended)
  local status
  local lm_hash   = nil
  local ntlm_hash = nil
  local mac_key   = nil
  local lm_response, ntlm_response

  -- Check for a blank password
  if(password == nil and password_hash == nil) then
    stdnse.debug2("SMB: Couldn't find password or hash to use (assuming blank)")
    password = ""
  end

  -- The anonymous user requires a single 0-byte instead of a LANMAN hash (don't ask me why, but it doesn't work without)
  if(hash_type == 'none') then
    return '\0', '', nil
  end

  -- If we got a password, hash it
  if(password ~= nil) then
    status, lm_hash   = lm_create_hash(password)
    status, ntlm_hash = ntlm_create_hash(password)
  else
    if(password_hash ~= nil) then
      if(string.find(password_hash, "^" .. string.rep("%x%x", 16) .. "$")) then
        stdnse.debug2("SMB: Found a 16-byte hex string")
        lm_hash   = stdnse.fromhex(password_hash:sub(1, 32))
        ntlm_hash = stdnse.fromhex(password_hash:sub(1, 32))
      elseif(string.find(password_hash, "^" .. string.rep("%x%x", 32) .. "$")) then
        stdnse.debug2("SMB: Found a 32-byte hex string")
        lm_hash   = stdnse.fromhex(password_hash:sub(1, 32))
        ntlm_hash = stdnse.fromhex(password_hash:sub(33, 64))
      elseif(string.find(password_hash, "^" .. string.rep("%x%x", 16) .. "." .. string.rep("%x%x", 16) .. "$")) then
        stdnse.debug2("SMB: Found two 16-byte hex strings")
        lm_hash   = stdnse.fromhex(password_hash:sub(1, 32))
        ntlm_hash = stdnse.fromhex(password_hash:sub(34, 65))
      else
        stdnse.debug1("SMB: ERROR: Hash(es) provided in an invalid format (should be 32, 64, or 65 hex characters)")
        lm_hash = nil
        ntlm_hash = nil
      end
    end
  end

  -- At this point, we should have a good lm_hash and ntlm_hash if we're getting one
  if(lm_hash == nil or ntlm_hash == nil) then
    stdnse.debug2("SMB: Couldn't determine which password to use, using a blank one")
    return "", ""
  end

  -- Output what we've got so far
  stdnse.debug2("SMB: Lanman hash: %s", stdnse.tohex(lm_hash))
  stdnse.debug2("SMB: NTLM   hash: %s", stdnse.tohex(ntlm_hash))

  -- Hash the password the way the user wants
  if(hash_type == "v1") then
    -- LM and NTLM are hashed with their respective algorithms
    stdnse.debug2("SMB: Creating v1 response")
    status, lm_response   = lm_create_response(lm_hash, challenge)
    status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)

    mac_key               = ntlm_create_mac_key(ntlm_hash, ntlm_response, is_extended)

  elseif(hash_type == "lm") then
    -- LM is hashed with its algorithm, NTLM is blank
    stdnse.debug2("SMB: Creating LMv1 response")
    status, lm_response   = lm_create_response(lm_hash, challenge)
    ntlm_response = ""

    mac_key               = lm_create_mac_key(lm_hash, lm_response, is_extended)

  elseif(hash_type == "ntlm") then
    -- LM and NTLM both use the NTLM algorithm
    stdnse.debug2("SMB: Creating NTLMv1 response")
    status, lm_response   = ntlm_create_response(ntlm_hash, challenge)
    status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)

    mac_key               = ntlm_create_mac_key(ntlm_hash, ntlm_response, is_extended)

  elseif(hash_type == "v2") then
    -- LM and NTLM are hashed with their respective v2 algorithms
    stdnse.debug2("SMB: Creating v2 response")
    status, lm_response   = lmv2_create_response(ntlm_hash, username, domain, challenge)
    status, ntlm_response = ntlmv2_create_response(ntlm_hash, username, domain, challenge, 24)

  elseif(hash_type == "lmv2") then
    -- LM is hashed with its v2 algorithm, NTLM is blank
    stdnse.debug2("SMB: Creating LMv2 response")
    status, lm_response   = lmv2_create_response(ntlm_hash, username, domain, challenge)
    ntlm_response = ""

  elseif(hash_type == "ntlmv2_session") then
    stdnse.debug2("SMB: Creating nltmv2 session response")
    status, lm_response, ntlm_response = ntlmv2_session_response(ntlm_hash, challenge)
  else
    -- Default to NTLMv1
    if(hash_type ~= nil) then
      stdnse.debug1("SMB: Invalid login type specified ('%s'), using default (NTLM)", hash_type)
    else
      stdnse.debug1("SMB: No login type specified, using default (NTLM)")
    end

    status, lm_response   = ntlm_create_response(ntlm_hash, challenge)
    status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)

  end

  stdnse.debug2("SMB: Lanman response: %s", stdnse.tohex(lm_response))
  stdnse.debug2("SMB: NTLM   response: %s", stdnse.tohex(ntlm_response))

  return lm_response, ntlm_response, mac_key
end

---Generate an NTLMSSP security blob.
--@param security_blob The server's security blob, or nil if this is the first
--                     message
--@param ip       The ip address of the host, used for registry lookups.
--@param username The username, which is used for v2 passwords.
--@param domain The username, which is used for v2 passwords.
--@param password [optional] The overriding password.
--@param password_hash [optional] The overriding password hash. Shouldn't be
--                     set if password is set.
--@param hash_type The way in which to hash the password.
--@param flags The NTLM flags as a number
function get_security_blob(security_blob, ip, username, domain, password, password_hash, hash_type, flags)
  local pos = 1
  local new_blob
  local flags = flags or 0x00008215 -- (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)

  if(security_blob == nil) then
    -- If security_blob is nil, this is the initial packet
    new_blob = string.pack("<zI4I4I8I8",
    "NTLMSSP",            -- Identifier
    NTLMSSP_NEGOTIATE,    -- Type
    flags,                -- Flags
    0,                    -- Calling workstation domain
    0                     -- Calling workstation name
    )

    return true, new_blob, "", ""
  else
    -- Parse the old security blob
    local identifier, message_type, domain_length, domain_max, domain_offset, server_flags, challenge, reserved = string.unpack("<I8I4I2I2I4I4c8c8", security_blob)
    local lanman, ntlm, mac_key = get_password_response(ip, username, domain, password, password_hash, hash_type, challenge, true)

    -- Convert the username and domain to unicode (TODO: Disable the unicode flag, evaluate if that'll work)
    local hostname = unicode.utf8to16("nmap")
    username = unicode.utf8to16(username)
    domain   = (#username > 0 ) and unicode.utf8to16(domain) or ""
    ntlm     = (#username > 0 ) and ntlm or ""
    lanman   = (#username > 0 ) and lanman or '\0'

    local domain_offset = 0x40
    local username_offset = domain_offset + #domain
    local hostname_offset = username_offset + #username
    local lanman_offset = hostname_offset + #hostname
    local ntlm_offset = lanman_offset + #lanman
    local sessionkey_offset = ntlm_offset + #ntlm

    new_blob = string.pack("<zI4 I2I2I4 I2I2I4 I2I2I4 I2I2I4 I2I2I4 I2I2I4 I4",
      "NTLMSSP",
      NTLMSSP_AUTH,
      #lanman,
      #lanman,
      lanman_offset,
      ( #ntlm > 0 and #ntlm - 16 or 0 ),
      ( #ntlm > 0 and #ntlm - 16 or 0 ),
      ntlm_offset,
      #domain,
      #domain,
      domain_offset,
      #username,
      #username,
      username_offset,
      #hostname,
      #hostname,
      hostname_offset,
      #session_key,
      #session_key,
      sessionkey_offset,
      flags)
      .. domain
      .. username
      .. hostname
      .. lanman
      .. ntlm
      .. session_key

    return true, new_blob, mac_key
  end

end

---
-- Host information for NTLM security
-- @class table
-- @name host_info
-- @field target_realm Target Name Data
-- @field netbios_computer_name Server name
-- @field netbios_domain_name Domain name
-- @field fqdn DNS server name
-- @field dns_domain_name DNS domain name
-- @field dns_forest_name DNS tree name
-- @field timestamp Timestamp

---
-- Gets host info from a security blob
-- @param security_blob The NTLM security blob
-- @return A host_info table containing the data in the blob.
-- @see host_info
function get_host_info_from_security_blob(security_blob)
  local identifier, message_type, domain_length, domain_max, domain_offset, server_flags, challenge, hpos = string.unpack("<c8I4 I2I2I4 I4I8", security_blob)

  -- Do some validation on the NTLMSSP message
  if ( identifier ~= "NTLMSSP\0" ) then
    stdnse.debug1("SMB: Invalid NTLM challenge message: unexpected signature." )
    return false, "Invalid NTLM challenge message"
    -- Per MS-NLMP, this field must be 2 for an NTLM challenge message
  elseif ( message_type ~= 0x2 ) then
    stdnse.debug1("SMB: Invalid NTLM challenge message: unexpected message type: %d.", message_type )
    return false, "Invalid message type in NTLM challenge message"
  end

  local ntlm_challenge = {}

  -- Parse the TargetName data (i.e. the server authentication realm)
  if ( domain_length > 0 ) then
    local length = domain_length
    local pos = domain_offset + 1 -- +1 to convert to Lua's 1-based indexes
    local target_realm
    target_realm = string.unpack("c" .. length, security_blob, pos )
    ntlm_challenge[ "target_realm" ] = unicode.utf16to8( target_realm )
  end

  if hpos + domain_length > #security_blob then
    -- Context, Target Information, and OS Version structure are all omitted
    -- Probably Win9x
    return ntlm_challenge
  end

  local context, target_info_length, target_info_max, target_info_offset, hpos = string.unpack("<I8 I2I2I4", security_blob, hpos)

  -- OS info is in the intervening 8 bytes, subtract 1 for lua 1-index
  if target_info_offset >= hpos + 7 and domain_offset >= hpos + 7 then
    local major, minor, build, reserved = string.unpack("<BBI2c4", security_blob, hpos)
    if reserved == "\0\0\0\x0f" then
      ntlm_challenge.os_major_version = major
      ntlm_challenge.os_minor_version = minor
      ntlm_challenge.os_build = build
    else
      stdnse.debug2("smbauth: Unknown OS info structure in NTLM handshake")
    end
  end

  -- Parse the TargetInfo data (Wireshark calls this the "Address List")
  if ( target_info_length > 0 ) then

    -- Definition of AvId values (IDs for AV_PAIR (attribute-value pair) structures),
    -- as defined by the NTLM Authentication Protocol specification [MS-NLMP].
    local NTLM_AV_ID_VALUES = {
      MsvAvEOL = 0x0,
      MsvAvNbComputerName = 0x1,
      MsvAvNbDomainName = 0x2,
      MsvAvDnsComputerName = 0x3,
      MsvAvDnsDomainName = 0x4,
      MsvAvDnsTreeName = 0x5,
      MsvAvFlags = 0x6,
      MsvAvTimestamp = 0x7,
      MsvAvRestrictions = 0x8,
      MsvAvTargetName = 0x9,
      MsvAvChannelBindings = 0xA,
    }
    -- Friendlier names for AvId values, to be used as keys in the results table
    -- e.g. ntlm_challenge[ "dns_computer_name" ] -> "host.test.local"
    local NTLM_AV_ID_NAMES = {
      [NTLM_AV_ID_VALUES.MsvAvNbComputerName] = "netbios_computer_name",
      [NTLM_AV_ID_VALUES.MsvAvNbDomainName] = "netbios_domain_name",
      [NTLM_AV_ID_VALUES.MsvAvDnsComputerName] = "fqdn",
      [NTLM_AV_ID_VALUES.MsvAvDnsDomainName] = "dns_domain_name",
      [NTLM_AV_ID_VALUES.MsvAvDnsTreeName] = "dns_forest_name",
      [NTLM_AV_ID_VALUES.MsvAvTimestamp] = "timestamp",
    }


    local length = target_info_length
    local pos = target_info_offset + 1 -- +1 to convert to Lua's 1-based indexes
    local target_info
    target_info = string.unpack("c" .. length, security_blob, pos)

    pos = 1 -- reset pos to 1, since we'll be working out of just the target_info
    repeat
      local value, av_id
      av_id, value, pos = string.unpack( "<I2s2", target_info, pos )
      local friendly_name = NTLM_AV_ID_NAMES[ av_id ]

      if ( av_id == NTLM_AV_ID_VALUES.MsvAvEOL ) then
        break
      elseif ( av_id == NTLM_AV_ID_VALUES.MsvAvTimestamp ) then
        -- this is a FILETIME value (see [MS-DTYP]), representing the time in 100-ns increments since 1/1/1601
        ntlm_challenge[ friendly_name ] = string.unpack( "<I8", value )
      elseif ( friendly_name ) then
        ntlm_challenge[ friendly_name ] = unicode.utf16to8( value )
      end
    until ( pos >= #target_info )
  end

  return ntlm_challenge
end

---Create an 8-byte message signature that's sent with all SMB packets.
--
--@param mac_key The key used for authentication. It's the concatenation of the
--               session key and the response hash.
--@param data The packet to generate the signature for. This should be the
--            packet that's about to be sent, except with the signature slot
--            replaced with the sequence number.
--@return The 8-byte signature. The signature is equal to the first eight bytes
--        of md5(mac_key .. smb_data)
function calculate_signature(mac_key, data)
  if(have_ssl) then
    return string.sub(openssl.md5(mac_key .. data), 1, 8)
  else
    return string.rep('\0', 8)
  end
end

if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()
-- OpenSSL-dependent crypto tests.
if have_ssl then
  test_suite:add_test(unittest.equal(
      stdnse.tohex(select(-1, lm_create_hash("passphrase"))),
      "855c3697d9979e78ac404c4ba2c66533"
      ),
    "lm_create_hash"
    )
  test_suite:add_test(unittest.equal(
      stdnse.tohex(select(-1, ntlm_create_hash("passphrase"))),
      "7f8fe03093cc84b267b109625f6bbf4b"
      ),
    "ntlm_create_hash"
    )
  test_suite:add_test(unittest.equal(
      stdnse.tohex(select(-1, lm_create_hash("ÅÇÅÇ"))),
      "1830f5732b438091aad3b435b51404ee"
      ),
    "lm_create_hash"
    )
  test_suite:add_test(unittest.equal(
      stdnse.tohex(select(-1, ntlm_create_hash("öäü"))),
      "4848bcb81cf018c3b70ea1479bd1374d"
      ),
    "ntlm_create_hash"
    )
end

return _ENV;
