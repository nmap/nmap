--- Common communication functions for network discovery tasks like
-- banner grabbing and data exchange.
--
-- The functions in this module return values appropriate for use with
-- exception handling via <code>nmap.new_try()</code>.
--
-- These functions may be passed a table of options, but it's not
-- required. The keys for the options table are "bytes", "lines",
-- "proto", and "timeout". "bytes" sets a minimum number of bytes to
-- read. "lines" does the same for lines. "proto" sets the protocol to
-- communicate with, defaulting to "tcp" if not provided. "timeout" sets
-- the socket timeout (see the socket function
-- <code>set_timeout()</code> for details). 
--
-- If both "bytes" and "lines" are provided, "lines" takes precedence.
-- If neither are given, the functions read as many bytes as possible.
-- @author Kris Katterjohn 04/2008
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "comm", package.seeall)

-- Makes sure that opts exists and the default proto is there
local initopts = function(opts)
	if not opts then
		opts = {}
	end

	if not opts.proto then
		opts.proto = "tcp"
	end

	return opts
end

-- Sets up the socket and connects to host:port
local setup_connect = function(host, port, opts)
	if type(host) ~= "table" then
		host = {ip = host}
	end

	local target = host.targetname or host.ip or host.name

	if type(port) ~= "table" then
		port = {number = port}
	end

	local sock = nmap.new_socket()

	if opts.timeout then
		sock:set_timeout(opts.timeout)
	end

	local status, err = sock:connect(target, port.number, opts.proto)

	if not status then
		return status, err
	end

	-- If nothing is given, specify bytes=1 so NSE reads everything
	if not opts.lines and not opts.bytes then
		opts.bytes = 1
	end

	return true, sock
end

local read = function(sock, opts)
	local response, status

	if opts.lines then
		status, response = sock:receive_lines(opts.lines)
		return status, response
	end

	status, response = sock:receive_bytes(opts.bytes)
	return status, response
end

--- This function simply connects to the specified port number on the
-- specified host and returns any data received. bool is a Boolean value
-- indicating success. If bool is true, then the second returned value
-- is the response from the target host. If bool is false, an error
-- message is returned as the second value instead of a response. 
-- @param host The host to connect to.
-- @param port The port on the host.
-- @param opts The options. See module description.
-- @return bool, data
get_banner = function(host, port, opts)
	opts = initopts(opts)

	local status, sock = setup_connect(host, port, opts)
	local ret

	if not status then
		-- sock is an error message in this case
		return status, sock
	end

	status, ret = read(sock, opts)

	sock:close()

	return status, ret
end

--- This function connects to the specified port number on the specified
-- host, sends data, then waits for and returns the response, if any.
-- bool is a Boolean value indicating success. If bool is true, then the
-- second returned value is the response from the target host. If bool is
-- false, an error message is returned as the second value instead of a
-- response. 
-- @param host The host to connect to.
-- @param port The port on the host.
-- @param data The data to send initially.
-- @param opts The options. See module description.
-- @return bool, data
exchange = function(host, port, data, opts)
	opts = initopts(opts)

	local status, sock = setup_connect(host, port, opts)
	local ret

	if not status then
		-- sock is an error message in this case
		return status, sock
	end

	status, ret = sock:send(data)

	if not status then
		sock:close()
		return status, ret
	end

	status, ret = read(sock, opts)

	sock:close()

	return status, ret
end

