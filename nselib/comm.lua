-- Kris Katterjohn 04/2008

module(... or "comm", package.seeall)

------
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

