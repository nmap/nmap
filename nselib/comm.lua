--- Common communication functions for network discovery tasks like
-- banner grabbing and data exchange.
--
-- The functions in this module return values appropriate for use with
-- exception handling via <code>nmap.new_try()</code>.
--
-- These functions may be passed a table of options, but it's not required. The
-- keys for the options table are <code>"bytes"</code>, <code>"lines"</code>,
-- <code>"proto"</code>, and <code>"timeout"</code>. <code>"bytes"</code> sets
-- a minimum number of bytes to read. <code>"lines"</code> does the same for
-- lines. <code>"proto"</code> sets the protocol to communicate with,
-- defaulting to <code>"tcp"</code> if not provided. <code>"timeout"</code>
-- sets the socket timeout (see the socket function <code>set_timeout()</code>
-- for details). 
--
-- If both <code>"bytes"</code> and <code>"lines"</code> are provided,
-- <code>"lines"</code> takes precedence. If neither are given, the functions
-- read as many bytes as possible.
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
-- specified host and returns any data received.
--
-- The first return value is true to signal success or false to signal
-- failure. On success the second return value is the response from the
-- remote host. On failure the second return value is an error message.
-- @param host The host to connect to.
-- @param port The port on the host.
-- @param opts The options. See the module description.
-- @return Status (true or false).
-- @return Data (if status is true) or error string (if status is false).
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
--
-- The first return value is true to signal success or false to signal
-- failure. On success the second return value is the response from the
-- remote host. On failure the second return value is an error message.
-- @param host The host to connect to.
-- @param port The port on the host.
-- @param data The data to send initially.
-- @param opts The options. See the module description.
-- @return Status (true or false).
-- @return Data (if status is true) or error string (if status is false).
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

