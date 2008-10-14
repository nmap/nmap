id = "SMB Security"
description = [[
Returns information about the SMB security level determined by SMB.
\n\n
Here is how to interpret the output:
\n\n
User-level security: Each user has a separate username/password that is used
to log into the system. This is the default setup of pretty much everything
these days.\n
Share-level security: The anonymous account should be used to log in, then 
the password is given (in plaintext) when a share is accessed. All users who
have access to the share use this password. This was the original way of doing
things, but isn't commonly seen, now. If a server uses share-level security, 
it is vulnerable to sniffing.
\n\n
Challenge/response passwords: If enabled, the server can accept any type of
password:\n
* Plaintext\n
* LM and NTLM\n
* LMv2 and NTLMv2\n
If it isn't set, the server can only accept plaintext passwords. Most servers
are configured to use challenge/response these days. If a server is configured
to accept plaintext passwords, it is vulnerable to sniffing.
\n\n
Message signing: If required, all messages between the client and server must
sign be signed by a shared key, derived from the password and the server
challenge. If supported and not required, message signing is negotiated between
clients and servers and used if both support and request it. By default,
Windows clients don't sign messages, so if message signing isn't required by
the server, messages probably won't be signed; additionally, if performing a
man-in-the-middle attack, an attacker can negotiate no message signing. If
message signing isn't required, the server is vulnerable to man-in-the-middle
attacks.
\n\n
See nselib/smb.lua for more information on the protocol itself.\n
]]

---
--@usage
-- nmap --script smb-security-mode.nse -p445 127.0.0.1\n
-- sudo nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 127.0.0.1\n
--
--@output
-- |  SMB Security: User-level authentication\n
-- |  SMB Security: Challenge/response passwords supported\n
-- |_ SMB Security: Message signing supported\n
-- 
-----------------------------------------------------------------------

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'smb'

--- Check whether or not this script should be run.
hostrule = function(host)

	local port = smb.get_port(host)

	if(port == nil) then
		return false
	else
		return true
	end

end


action = function(host)

	local status, socket = smb.start(host)

	if(status == false) then
		return "Error: " .. socket
	end

	status, result = smb.negotiate_protocol(socket)

	if(status == false) then
		smb.stop(socket)
		return "Error: " .. result
	end

	local security_mode = result['security_mode']
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

	smb.stop(socket)
	return response
end


