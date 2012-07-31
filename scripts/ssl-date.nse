local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local bin = require "bin"
local os = require "os"
local string = require "string"
description = [[
Script gets remote hosts time from ssl ServerHello response.
The first four bytes of server random are gmt_unix_time.

Original idea by Jacob Appelbaum and his TeaTime and tlsdate tools:
	- https://github.com/ioerror/TeaTime
	- https://github.com/ioerror/tlsdate
]]

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}
portrule = shortport.ssl

---
-- @usage
-- nmap <target> --script=ssl-date
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- |_ssl-date: Server time 2012-07-30 09:46:07 GMT; 0s from the local time.
--

--
-- most of the code snatched from tls-nextprotoneg until we decide if we want a separate library
--

--- Function that sends a client hello packet
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
    cli_h = cli_h .. bin.pack(">S", 0x0031)
    -- Handshake protocol
    -- Handshake Type: Client Hello
    cli_h = cli_h .. bin.pack(">C", 0x01)
    -- Length, fixed
    cli_h = cli_h .. bin.pack(">CS", 0x00, 0x002d)
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

-- extract time from ServerHello response
local extract_time = function(response)
    local result
    local shlength, npndata, protocol

    if not response then
	stdnse.print_debug(SCRIPT_NAME .. ": Didn't get response.")
	return false,result
    end
    -- If content type not handshake
    if string.sub(response,1,1) ~= string.char(22) then
	stdnse.print_debug(SCRIPT_NAME .. ": Response type not handshake.")
	return false,result
    end
    -- If handshake protocol not server hello
    if string.sub(response, 6, 6) ~= string.char(02) then
	stdnse.print_debug(SCRIPT_NAME .. ": Handshake response not server hello.")
	return false,result
    end

    -- Get the server hello length
    _, shlength = bin.unpack(">S", response, 4)
    local serverhello = string.sub(response, 6, 6 + shlength)
	local bin_res = string.sub(serverhello,7,10)
	_,result = bin.unpack(">I",bin_res)
	stdnse.print_debug("HERE: " ..result)
    return true,result
end

action = function(host, port)
    local status, response

    -- Send crafted client hello
    status, response = client_hello(host, port)
    if status and response then
		-- extract time from response
		local result
		status, result = extract_time(response)
		if status then
			return string.format("Server time %s GMT; %s from the local time.", 
										os.date("%Y-%m-%d %H:%M:%S",result),
										stdnse.format_difftime(os.date("!*t",result),os.date("!*t")))
			end
		end
end
