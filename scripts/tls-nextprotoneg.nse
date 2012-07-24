local nmap = require "nmap"
local string = require "string"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local bin = require "bin"
local os = require "os"

description = [[
Enumerates a TLS server's supported protocols by using the next protocol negotiation extension.

This works by adding the next protocol negotiation extension in the client hello 
packet and parsing the returned server hello's NPN extension data.

For more information , see:
    * https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03
]]

---
-- @usage
-- nmap --script=tls-nextprotoneg <targets>
--
--@output
-- 443/tcp open  https
-- | tls-nextprotoneg: 
-- |   spdy/3
-- |   spdy/2
-- |_  http/1.1


author = "Hani Benhabiles"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe", "default"}

portrule = shortport.ssl


--- Function that sends a client hello packet with the TLS NPN extension to the
-- target host and returns the response
--@args host The target host table.
--@args port The target port table.
--@return status true if response, false else.
--@return response if status is true.
local client_hello = function(host, port)
    local sock, status, response, err, cli_h

    -- Craft Client Hello
    -- Content Type: Client Handshake
    cli_h = bin.pack(">C", 0x16)
    -- Version: TLS 1.0
    cli_h = cli_h .. bin.pack(">S", 0x0301)
    -- Length, fixed
    cli_h = cli_h .. bin.pack(">S", 0x0037)
    -- Handshake protocol
    -- Handshake Type: Client Hello
    cli_h = cli_h .. bin.pack(">C", 0x01)
    -- Length, fixed
    cli_h = cli_h .. bin.pack(">CS", 0x00, 0x0033)
    -- Version: TLS 1.0 
    cli_h = cli_h .. bin.pack(">S", 0x0301)
    -- Random: epoch time
    cli_h = cli_h .. bin.pack(">I", os.time()) 
    -- Random: random 28 bytes
    cli_h = cli_h .. stdnse.generate_random_string(28)
    -- Session ID length
    cli_h = cli_h .. bin.pack(">C", 0x00)
    -- Cipher Suites length
    cli_h = cli_h .. bin.pack(">S", 0x0006)
    -- Ciphers
    cli_h = cli_h .. bin.pack(">S", 0xc011)
    cli_h = cli_h .. bin.pack(">S", 0x0039)
    cli_h = cli_h .. bin.pack(">S", 0x0004)
    -- Compression Methods length
    cli_h = cli_h .. bin.pack(">C", 0x01)
    -- Compression Methods: null
    cli_h = cli_h .. bin.pack(">C", 0x00)
    -- Extensions length
    cli_h = cli_h .. bin.pack(">S", 0x0004)
    -- TLS NPN Extension
    cli_h = cli_h .. bin.pack(">I", 0x33740000)

    -- Connect to the target server
    sock = nmap.new_socket()
    sock:set_timeout(5000)
    status, err = sock:connect(host, port)
    if not status then
	sock:close()
	stdnse.print_debug("Can't send: %s", err)
	return false
    end

    -- Send Client Hello to the target server
    status, err = sock:send(cli_h)
    if not status then
	stdnse.print_debug("Couldn't send: %s", err)
	sock:close()
	return false
    end

    -- Read response
    status, response = sock:receive()
    if not status then
	stdnse.print_debug("Couldn't receive: %s", err)
	sock:close()
	return false
    end

    return true, response
end

--- Function that checks for the returned protocols to a npn extension request.
--@args response Response to parse.
--@return results List of found protocols.
local check_npn = function(response)
    local results = {}
    local shlength, npndata, protocol

    if not response then
	stdnse.print_debug(SCRIPT_NAME .. ": Didn't get response.")
	return results
    end
    -- If content type not handshake
    if string.sub(response,1,1) ~= string.char(22) then
	stdnse.print_debug(SCRIPT_NAME .. ": Response type not handshake.")
	return results
    end
    -- If handshake protocol not server hello
    if string.sub(response, 6, 6) ~= string.char(02) then
	stdnse.print_debug(SCRIPT_NAME .. ": Handshake response not server hello.")
	return results
    end

    -- Get the server hello length
    local _
		_, shlength = bin.unpack(">S", response, 4)
    local serverhello = string.sub(response, 6, 6 + shlength)

    -- If server didn't return TLS NPN extension
    local npnextension, _ = string.find(serverhello, string.char(0x33) .. string.char(0x74))
    if not npnextension then
	stdnse.print_debug(SCRIPT_NAME .. ": Server doesn't support TLS NPN extension.")
	return results
    end

    -- Get NPN data length
    local _, npnlen = bin.unpack(">S", serverhello:sub(npnextension + 2, npnextension + 3))
    if not npnlen then
	return results
    end

    npndata = serverhello:sub(npnextension + 4, npnextension + 4 + npnlen)
    -- Parse data
    local i, len = 1
    while i < #npndata do
	len = npndata:byte(i)
	protocol = npndata:sub(i+1, i+len)
	table.insert(results, protocol)
	i = i + len + 1
    end

    return results
end

action = function(host, port)
    local status, response

    -- Send crafted client hello
    status, response = client_hello(host, port)
    if status and response then
	-- Analyze response
	local results = check_npn(response)
	return stdnse.format_output(true, results)
    end
end
