---
-- Common communication functions for network discovery tasks like
-- banner grabbing and data exchange.
--
-- The functions in this module return values appropriate for use with
-- exception handling via <code>nmap.new_try</code>.
--
-- These functions may be passed a table of options, but it's not required. The
-- keys for the options table are <code>"bytes"</code>, <code>"lines"</code>,
-- <code>"proto"</code>, and <code>"timeout"</code>. <code>"bytes"</code> sets
-- a minimum number of bytes to read. <code>"lines"</code> does the same for
-- lines. <code>"proto"</code> sets the protocol to communicate with,
-- defaulting to <code>"tcp"</code> if not provided. <code>"timeout"</code>
-- sets the socket timeout (see the socket function <code>set_timeout</code>
-- for details). 
--
-- If both <code>"bytes"</code> and <code>"lines"</code> are provided,
-- <code>"lines"</code> takes precedence. If neither are given, the functions
-- read as many bytes as possible.
-- @author Kris Katterjohn 04/2008
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local nmap = require "nmap"
local stdnse = require "stdnse"
_ENV = stdnse.module("comm", stdnse.seeall)

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
    local sock = nmap.new_socket()

    if opts.timeout then
        sock:set_timeout(opts.timeout)
    end

    local status, err = sock:connect(host, port, opts.proto)

    if not status then
        return status, err
    end

    return true, sock
end

local read = function(sock, opts)
    local response, status

    if opts.lines then
        status, response = sock:receive_lines(opts.lines)
        return status, response
    end

    if opts.bytes then
        status, response = sock:receive_bytes(opts.bytes)
        return status, response
    end

    status, response = sock:receive()
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
    opts.recv_before = true
    local socket, nothing, correct, banner = tryssl(host, port, "", opts)
    if socket then
      socket:close()
      return true, banner
    end
    return false, banner
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

--- This function just checks if the provided port number is on a list
-- of ports that usually provide services with ssl
--
-- @param port_number The number of the port to check
-- @return bool True if port is usually ssl, otherwise false
local function is_ssl(port_number)
    local common_ssl_ports = {
      [443] = true,
      [465] = true,
      [989] = true,
      [990] = true,
      [992] = true,
      [993] = true,
      [994] = true,
      [995] = true,
      [587] = true,
      [6697] = true,
      [6679] = true,
      [8443] = true,
    }
    return not not common_ssl_ports[port_number]
end

--- This function returns best protocol order for trying  to open a 
-- connection based on port and service information
--
-- The first value is the best option, the second is the worst
-- @param port The port table
-- @return Best option ("tcp" or "ssl")
-- @return Worst option ("tcp" or "ssl")
local function bestoption(port)
    if type(port) == 'table' then
        if port.version and port.version.service_tunnel and port.version.service_tunnel == "ssl" then return "ssl","tcp" end
        if port.version and port.version.name_confidence and port.version.name_confidence > 6 then return "tcp","ssl" end
        if is_ssl(port.number) then return "ssl","tcp" end
    elseif type(port) == 'number' then
        if is_ssl(port) then return "ssl","tcp" end
    end
    return "tcp","ssl"
end

--- This function opens a connection, sends the first data payload and
--  check if a response is correctly received (what means that the 
--  protocol used is fine)
--
-- Possible options:
-- timeout: generic timeout value
-- connect_timeout: specific timeout for connection
-- request_timeout: specific timeout for requests
-- recv_before: receive data before sending first payload
--
-- Default timeout is set to 8000.
--
-- @param host The destination host IP
-- @param port The destination host port
-- @param protocol The protocol for the connection
-- @param data The first data payload of the connection
-- @return sd The socket descriptor, nil if no connection is established
-- @return response The response received for the payload
-- @return early_resp If opt recv_before is true, returns the value
-- of the first receive (before sending data)
local function opencon(host, port, protocol, data, opts)
    local sd = nmap.new_socket()

    -- check for connect_timeout or timeout option

    if opts and opts.connect_timeout then 
        sd:set_timeout(opts.connect_timeout)
    elseif opts and opts.timeout then
        sd:set_timeout(opts.timeout)
    else
        sd:set_timeout(8000)
    end

    local status = sd:connect(host, port, protocol)
    if not status then 
          sd:close()
          return nil, nil, nil 
        end

    -- check for request_timeout or timeout option

    if opts and opts.request_timeout then
        sd:set_timeout(opts.request_timeout)
    elseif opts and opts.timeout then
        sd:set_timeout(opts.timeout)
    else
        sd:set_timeout(8000)
    end

    local response, early_resp;
    if opts and opts.recv_before then status, early_resp = read(sd, opts) end
    if data and #data > 0 then
        sd:send(data)
        status, response = sd:receive()
    else
        if not (opts and opts.recv_before) then
            stdnse.print_debug("Using comm.tryssl without first data payload and recv_first." ..
                         "\nImpossible to test the connection for the correct protocol!")
        end
        response = early_resp
    end
    if not status then 
          sd:close()
          return nil, response, early_resp 
        end
    return sd, response, early_resp
end

--- This function tries to open a connection based on the best
--  option about which is the correct protocol
--
--  If the best option fails, the function tries the other option
--
--  This function allows writing nse scripts in a way that the
--  API will take care of ssl issues, making failure detection
--  transparent to the programmer
--
-- @param host The host table
-- @param port The port table
-- @param data The first data payload of the connection
-- @param opts Options, such as timeout
-- @return sd The socket descriptor
-- @return response The response received for the payload
-- @return correctOpt Correct option for connection guess
-- @return earlyResp If opt recv_before is true, returns the value
-- of the first receive (before sending data)
function tryssl(host, port, data, opts)
    local opt1, opt2 = bestoption(port)
    local best = opt1
    local sd, response, early_resp = opencon(host, port, opt1, data, opts)
    if not sd then
        sd, response, early_resp = opencon(host, port, opt2, data, opts)
        best = opt2
    end
    if not sd then best = "none" end
    return sd, response, best, early_resp
end

return _ENV;
