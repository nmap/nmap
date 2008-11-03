id = "SMB Security"
description = [[
Returns information about the SMB security level determined by SMB.

Here is how to interpret the output:

User-level authentication: Each user has a separate username/password that is used
to log into the system. This is the default setup of pretty much everything
these days.

Share-level authentication: The anonymous account should be used to log in, then 
the password is given (in plaintext) when a share is accessed. All users who
have access to the share use this password. This was the original way of doing
things, but isn't commonly seen, now. If a server uses share-level security, 
it is vulnerable to sniffing.

Challenge/response passwords supported: If enabled, the server can accept any type of
password:
* Plaintext
* LM and NTLM
* LMv2 and NTLMv2
If it isn't set, the server can only accept plaintext passwords. Most servers
are configured to use challenge/response these days. If a server is configured
to accept plaintext passwords, it is vulnerable to sniffing. LM and NTLM are
fairly secure, although there are some brute-force attacks against them. 

Message signing: If required, all messages between the client and server must
be signed by a shared key, derived from the password and the server
challenge. If supported and not required, message signing is negotiated between
clients and servers and used if both support and request it. By default,
Windows clients don't sign messages, so if message signing isn't required by
the server, messages probably won't be signed; additionally, if performing a
man-in-the-middle attack, an attacker can negotiate no message signing. If
message signing isn't required, the server is vulnerable to man-in-the-middle
attacks.

This script will allow you to use the <code>smb*</code> script arguments (to
set the username and password, etc.), but it probably won't ever require them. 
]]

---
--@usage
-- nmap --script smb-security-mode.nse -p445 127.0.0.1
-- sudo nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 127.0.0.1
--
--@output
-- |  SMB Security: User-level authentication
-- |  SMB Security: Challenge/response passwords supported
-- |_ SMB Security: Message signing supported
-- 
--@args  smbusername The SMB username to log in with. The forms "DOMAIN\username" and "username@DOMAIN"
--                   are not understood. To set a domain, use the <code>smbdomain</code> argument. 
--@args  smbdomain   The domain to log in with. If you aren't in a domained environment, then anything
--                   will (should?) be accepted by the server. 
--@args  smbpassword The password to connect with. Be cautious with this, since some servers will lock
--                   accounts if the incorrect password is given. Although it's rare that the
--                   Administrator account can be locked out, in the off chance that it can, you could
--                   get yourself in trouble. 
--@args  smbhash     A password hash to use when logging in. This is given as a single hex string (32
--                   characters) or a pair of hex strings (both 32 characters, optionally separated by a 
--                   single character). These hashes are the LanMan or NTLM hash of the user's password,
--                   and are stored on disk or in memory. They can be retrieved from memory
--                   using the fgdump or pwdump tools. 
--@args  smbguest    If this is set to <code>true</code> or <code>1</code>, a guest login will be attempted if the normal one 
--                   fails. This should be harmless, but I thought I would disable it by default anyway
--                   because I'm not entirely sure of any possible consequences. 
--@args  smbtype     The type of SMB authentication to use. These are the possible options:
-- * <code>v1</code>: Sends LMv1 and NTLMv1.
-- * <code>LMv1</code>: Sends LMv1 only.
-- * <code>NTLMv1</code>: Sends NTLMv1 only (default).
-- * <code>v2</code>: Sends LMv2 and NTLMv2.
-- * <code>LMv2</code>: Sends LMv2 only.
--                   The default, <code>NTLMv1</code>, is a pretty
--                   decent compromise between security and compatibility. If you are paranoid, you might 
--                   want to use <code>v2</code> or <code>lmv2</code> for this. (Actually, if you're paranoid, you should be 
--                   avoiding this protocol altogether :P). If you're using an extremely old system, you 
--                   might need to set this to <code>v1</code> or <code>lm</code>, which are less secure but more compatible. 
-----------------------------------------------------------------------

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'smb'

-- Check whether or not this script should be run.
hostrule = function(host)

	local port = smb.get_port(host)

	if(port == nil) then
		return false
	else
		return true
	end

end


action = function(host)

	local state
	local status, err

	status, state = smb.start(host)
	if(status == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. state
		else
			return nil
		end
	end

	status, err = smb.negotiate_protocol(state)

	if(status == false) then
		smb.stop(state)
		if(nmap.debugging() > 0) then
			return "ERROR: " .. err
		else
			return nil
		end
	end

	local security_mode = state['security_mode']

	local response = ""
	
	-- User-level authentication or share-level authentication
    if(bit.band(security_mode, 1) == 1) then
        response = response .. "User-level authentication\n"
    else
        response = response .. " Share-level authentication\n"
    end

    -- Challenge/response supported?
    if(bit.band(security_mode, 2) == 0) then
        response = response .. "SMB Security: Plaintext only\n"
    else
        response = response .. "SMB Security: Challenge/response passwords supported\n"
    end

    -- Message signing supported/required?
    if(bit.band(security_mode, 8) == 8) then
        response = response .. "SMB Security: Message signing required\n"
    elseif(bit.band(security_mode, 4) == 4) then
        response = response .. "SMB Security: Message signing supported\n"
    else
        response = response .. "SMB Security: Message signing not supported\n"
    end

	smb.stop(state)
	return response
end


