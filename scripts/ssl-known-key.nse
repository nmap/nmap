-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
This script checks whether the SSL certificate used by a host has a fingerprint
that matches the ones in a database.

The database checked is currently from LittleBlackBox 0.1, but any file of
fingerprints will serve just as well. One suggestion is the list of the weak
Debian OpenSSL keys.
]]

---
-- @usage
-- nmap --script ssl-known-key -p 443 <host>
--
-- @args ssl-known-key.fingerprintfile  Specify a different file to read
--       fingerprints from.
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- |_ssl-known-key: 00:28:E7:D4:9C:FA:4A:A5:98:4F:E4:97:EB:73:48:56:07:87:E4:96 is in the database with reason Little Black Box 0.1.

author = "Mak Kolybabi"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require("bin")
require("nmap")
require("shortport")
require("stdnse")

local FINGERPRINT_FILE = "ssl-fingerprints"

local get_fingerprints = function(path)
	local pretty = function(key)
		local s = key:sub(1, 2)

		for i = 3, 40, 2 do
			s = s .. ":" .. key:sub(i, i + 1)
		end

		return s:upper()
	end

	-- Check registry for cached fingerprints.
	if nmap.registry.ssl_fingerprints then
		stdnse.print_debug(2, "Using cached SSL fingerprints.")
		return true, nmap.registry.ssl_fingerprints
	end

	-- Attempt to resolve path if it is relative.
	local full_path = nmap.fetchfile("nselib/data/" .. path)
	if not full_path then
		full_path = path
	end
	stdnse.print_debug(2, "Loading SSL fingerprints from %s.", full_path)

	-- Open database.
	local file = io.open(full_path, "r")
	if not file then
		return false, "Failed to open file " .. full_path
	end

	-- Parse database.
	local section = nil
	local fingerprints = {}
	for line in file:lines() do
		line = line:gsub("#.*", "")
		line = line:gsub("^%s*", "")
		line = line:gsub("%s*$", "")
		if line ~= "" then
			if line:sub(1,1) == "[" then
				-- Start a new section.
				line = line:sub(2, #line - 1)
				stdnse.print_debug(4, "Starting new section %s.", line)
				section = line
			elseif section ~= nil then
				-- Add fingerprint to section.
				line = pretty(line)
				stdnse.print_debug(4, "Added key %s to database.", line)
				fingerprints[line] = section
			else
				-- Key found outside of section.
				stdnse.print_debug(1, "Key %s is not in a section.", pretty(line))
			end
		end
	end

	-- Close database.
	file:close()

	-- Cache fingerprints in registry for future runs.
	nmap.registry.ssl_fingerprints = fingerprints

	return true, fingerprints
end

portrule = shortport.ssl

action = function(host, port)
	-- Get script arguments.
	local path = stdnse.get_script_args("ssl-known-key.fingerprintfile") or FINGERPRINT_FILE
	local status, result = get_fingerprints(path)
	if not status then
		stdnse.print_debug(1, result)
		return
	end
	local fingerprints = result

	-- Connect to host.
	local sock = nmap.new_socket()
	local status, err = sock:connect(host, port, "ssl")
	if not status then
		stdnse.print_debug(1, "Failed to connect: %s", err)
		return
	end

	-- Get SSL certificate.
	local cert = sock:get_ssl_certificate()
	sock:close()
	if not cert:digest("sha1") then
		stdnse.print_debug(2, "Certificate does not have a SHA-1 fingerprint.")
		return
	end

	-- Check SSL fingerprint against database.
	local fingerprint = stdnse.tohex(cert:digest("sha1"), {separator=":", group=2}):upper()
	local section = fingerprints[fingerprint]
	if not section then
		stdnse.print_debug(2, "%s was not in the database.", fingerprint)
		return
	end

	return "Found in " .. section .. " (certificate hash: " .. fingerprint .. ")"
end
