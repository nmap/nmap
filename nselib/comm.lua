--- The comm module provides functions for common network discovery tasks.
-- Banner-grabbing and making a quick exchange of data are some of
-- these tasks. These
-- functions' return values are setup for use with exception handling
-- via nmap.new_try().\n
-- \n
-- These functions can all be passed a table of options, but it's not
-- required. The relevant indexes for this table are bytes, lines, proto
-- and timeout. bytes is used to provide the minimum number of bytes required
-- for a read. lines does the same, but for the minimum number of lines.
-- proto is used to set the protocol to communicate with, defaulting to
-- "tcp" if not provided. timeout is used to set the socket timeout (see
-- the socket function set_timeout() for details). 
-- @author Kris Katterjohn 04/2008

module(... or "comm", package.seeall)

--
--
-- The Functions:
--
--   get_banner(host, port, [opts])
--   exchange(host, port, data, [opts])
--
-- get_banner() does just what it sounds like it does: connects to the
-- host, reads whatever it gives us, and then returns it.
--
-- exchange() connects to the host, sends the requested data, reads
-- whatever it gives us, and then returns it.
--
-- Both of these functions return multiple values so that they can be
-- used with exception handling via nmap.new_try().  The second value
-- they return is either the response from the host, or the error message
-- from one of the previous calls (connect, send, receive*).
--
-- These functions can be passed a table of options with the following keys:
--
--   bytes: Specifies the minimum amount of bytes are to be read from the host
--   lines: Specifies the minimum amount of lines are to be read from the host
--   proto: Specifies the protocol to be used with the connect() call
--   timeout: Sets the socket's timeout with nmap.set_timeout()
--
-- If neither lines nor bytes are specified, the calls attempt to read as many
-- bytes as possible.  If only bytes is specified, then it only tries to read
-- that many bytes.  Likewise, it only lines if specified, then it only tries
-- to read that many lines.  If they're both specified, the lines value is used.
--
------

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

