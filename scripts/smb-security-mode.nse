local bit = require "bit"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Returns information about the SMB security level determined by SMB.

Here is how to interpret the output:

* User-level authentication: Each user has a separate username/password that is used to log into the system. This is the default setup of pretty much everything these days.
* Share-level authentication: The anonymous account should be used to log in, then the password is given (in plaintext) when a share is accessed. All users who have access to the share use this password. This was the original way of doing things, but isn't commonly seen, now. If a server uses share-level security, it is vulnerable to sniffing.
* Challenge/response passwords supported: If enabled, the server can accept any type of password (plaintext, LM and NTLM, and LMv2 and NTLMv2).  If it isn't set, the server can only accept plaintext passwords. Most servers are configured to use challenge/response these days. If a server is configured to accept plaintext passwords, it is vulnerable to sniffing. LM and NTLM are fairly secure, although there are some brute-force attacks against them. Additionally, LM and NTLM can fall victim to man-in-the-middle attacks or relay attacks (see MS08-068 or my writeup of it: http://www.skullsecurity.org/blog/?p=110. 
* Message signing: If required, all messages between the client and server must be signed by a shared key, derived from the password and the server challenge. If supported and not required, message signing is negotiated between clients and servers and used if both support and request it. By default, Windows clients don't sign messages, so if message signing isn't required by the server, messages probably won't be signed; additionally, if performing a man-in-the-middle attack, an attacker can negotiate no message signing. If message signing isn't required, the server is vulnerable to man-in-the-middle attacks or SMB-relay attacks.

This script will allow you to use the <code>smb*</code> script arguments (to
set the username and password, etc.), but it probably won't ever require them. 
]]

---
--@usage
-- nmap --script smb-security-mode.nse -p445 127.0.0.1
-- sudo nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 127.0.0.1
--
--@output
-- Host script results:
-- |  smb-security-mode:
-- |  |  Account that was used for smb scripts: administrator
-- |  |  User-level authentication
-- |  |  SMB Security: Challenge/response passwords supported
-- |_ |_ Message signing disabled (dangerous, but default)
-----------------------------------------------------------------------

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"smb-brute"}


-- Check whether or not this script should be run.
hostrule = function(host)
	return smb.get_port(host) ~= nil
end


action = function(host)

	local state
	local status, err
	local overrides = {}

	status, state = smb.start(host)
	if(status == false) then
		return stdnse.format_output(false, state)
	end

	status, err = smb.negotiate_protocol(state, overrides)
	if(status == false) then
		smb.stop(state)
		return stdnse.format_output(false, err)
	end

	local security_mode = state['security_mode']

	local response = {}

	local result, username, domain = smb.get_account(host)
	if(result ~= false) then
		table.insert(response, string.format("Account that was used for smb scripts: %s%s", domain, stdnse.string_or_blank(username, '<blank>')))
	end
	
	-- User-level authentication or share-level authentication
	if(bit.band(security_mode, 1) == 1) then
		table.insert(response, "User-level authentication")
	else
		table.insert(response, "Share-level authentication (dangerous)")
	end

	-- Challenge/response supported?
	if(bit.band(security_mode, 2) == 0) then
		table.insert(response, "Plaintext passwords required (dangerous)")
	else
		table.insert(response, "SMB Security: Challenge/response passwords supported")
	end

	-- Message signing supported/required?
	if(bit.band(security_mode, 8) == 8) then
		table.insert(response, "Message signing required")
	elseif(bit.band(security_mode, 4) == 4) then
		table.insert(response, "Message signing supported")
	else
		table.insert(response, "Message signing disabled (dangerous, but default)")
	end

	smb.stop(state)
	return stdnse.format_output(true, response)
end


