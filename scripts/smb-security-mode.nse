description = [[
Returns information about the SMB security level determined by SMB.

Here is how to interpret the output:

* User-level authentication: Each user has a separate username/password that is used
to log into the system. This is the default setup of pretty much everything
these days.
* Share-level authentication: The anonymous account should be used to log in, then 
the password is given (in plaintext) when a share is accessed. All users who
have access to the share use this password. This was the original way of doing
things, but isn't commonly seen, now. If a server uses share-level security, 
it is vulnerable to sniffing.
* Challenge/response passwords supported: If enabled, the server can accept any 
type of password (plaintext, LM and NTLM, and LMv2 and NTLMv2).  If it isn't set, 
the server can only accept plaintext passwords. Most servers are configured to 
use challenge/response these days. If a server is configured to accept plaintext 
passwords, it is vulnerable to sniffing. LM and NTLM are fairly secure, although 
there are some brute-force attacks against them. Additionally, LM and NTLM can 
fall victim to man-in-the-middle attacks or relay attacks (see MS08-068 or my 
writeup of it: http://www.skullsecurity.org/blog/?p=110). 
* Message signing: If required, all messages between the client and server must
be signed by a shared key, derived from the password and the server
challenge. If supported and not required, message signing is negotiated between
clients and servers and used if both support and request it. By default,
Windows clients don't sign messages, so if message signing isn't required by
the server, messages probably won't be signed; additionally, if performing a
man-in-the-middle attack, an attacker can negotiate no message signing. If
message signing isn't required, the server is vulnerable to man-in-the-middle
attacks or SMB-relay attacks.

This script will allow you to use the <code>smb*</code> script arguments (to
set the username and password, etc.), but it probably won't ever require them. 
]]

---
--@usage
-- nmap --script smb-security-mode.nse -p445 127.0.0.1
-- sudo nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 127.0.0.1
--
--@output
-- |  smb-security-mode: User-level authentication
-- |  smb-security-mode: Challenge/response passwords supported
-- |_ smb-security-mode: Message signing supported
-- 
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, and <code>smbtype</code>
-- script arguments of the <code>smb</code> module.
-----------------------------------------------------------------------

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'smb'

-- Check whether or not this script should be run.
hostrule = function(host)
	return smb.get_port(host) ~= nil
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


