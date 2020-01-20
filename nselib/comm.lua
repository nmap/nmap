---
-- Common communication functions for network discovery tasks like
-- banner grabbing and data exchange.
--
-- The functions in this module return values appropriate for use with
-- exception handling via <code>nmap.new_try</code>.
--
-- These functions may be passed a table of options, but it's not required. The
-- keys for the options table are:
-- * <code>bytes</code> - minimum number of bytes to read.
-- * <code>lines</code> - minimum number of lines to read.
-- * <code>proto</code> - string, protocol to use. Default <code>"tcp"</code>
-- * <code>timeout</code> - override timeout in milliseconds. This overrides all other timeout defaults, but can be overridden by specific connect and request timeouts (below)
-- * <code>connect_timeout</code> - socket timeout for connection. Default: same as <code>stdnse.get_timeout</code>
-- * <code>request_timeout</code> - additional socket timeout for requests. This is added to the connect_timeout to get a total time for a request to receive a response. Default: 6000ms
-- * <code>recv_before</code> - boolean, receive data before sending first payload
-- * <code>any_af</code> - boolean, allow connecting to any address family, inet or inet6. By default, these functions will only use the same AF as nmap.address_family to resolve names.
--
-- If both <code>"bytes"</code> and <code>"lines"</code> are provided,
-- <code>"lines"</code> takes precedence. If neither are given, the functions
-- read as many bytes as possible.
-- @author Kris Katterjohn 04/2008
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local nmap = require "nmap"
local shortport
local stdnse = require "stdnse"
local oops = require "oops"
_ENV = stdnse.module("comm", stdnse.seeall)

-- This timeout value (in ms) is added to the connect timeout and represents
-- the amount of processing time allowed for the host before it sends a packet.
-- For justification of this value, see totalwaitms in nmap-service-probes
local REQUEST_TIMEOUT = 6000

-- Function used to get a connect and request timeout based on specified options
local function get_timeouts(host, opts)
  local connect_timeout, request_timeout
  -- connect_timeout based on options or stdnse.get_timeout()
  if opts and opts.connect_timeout then
    connect_timeout = opts.connect_timeout
  elseif opts and opts.timeout then
    connect_timeout = opts.timeout
  else
    connect_timeout = stdnse.get_timeout(host)
  end

  -- request_timeout based on options or REQUEST_TIMEOUT + connect_timeout
  if opts and opts.request_timeout then
    request_timeout = opts.request_timeout
  elseif opts and opts.timeout then
    request_timeout = opts.timeout
  else
    request_timeout = REQUEST_TIMEOUT
  end
  request_timeout = request_timeout + connect_timeout

  return connect_timeout, request_timeout
end

-- Sets up the socket and connects to host:port
local setup_connect = function(host, port, opts)
  local sock = nmap.new_socket()

  local connect_timeout, request_timeout = get_timeouts(host, opts)

  sock:set_timeout(connect_timeout)

  if type(host) == "string" and opts.any_af then
    local status, addrs = nmap.resolve(host)
    if status then
      host = {ip = addrs[1], targetname = host}
    end
  end

  local status, err = sock:connect(host, port, opts.proto)

  if not status then
    sock:close()
    return oops.raise("Could not connect", status, err)
  end

  sock:set_timeout(request_timeout)

  return true, sock
end

local read = function(sock, opts)
  if opts.lines then
    return oops.raise("receive_lines failed", sock:receive_lines(opts.lines))
  end

  if opts.bytes then
    return oops.raise("receive_bytes failed", sock:receive_bytes(opts.bytes))
  end

  return oops.raise("receive failed", sock:receive())
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
  opts = opts or {}
  opts.recv_before = true
  local socket, errmsg, correct, banner = oops.raise("tryssl failed", tryssl(host, port, nil, opts))
  if socket then
    socket:close()
    return true, banner
  end
  return false, errmsg
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
  opts = opts or {}

  local status, sock = setup_connect(host, port, opts)
  local ret

  if not status then
    -- sock is an error message in this case
    return oops.raise("Failed to connect", status, sock)
  end

  status, ret = sock:send(data)

  if not status then
    sock:close()
    return oops.raise("Failed to send", status, ret)
  end

  status, ret = read(sock, opts)

  sock:close()

  return oops.raise("Failed to read", status, ret)
end

--- This function uses shortport.ssl to check if the port is a likely SSL port
-- @see shortport.ssl
--
-- @param port The port table to check
-- @return bool True if port is usually ssl, otherwise false
local function is_ssl(port)
  shortport = shortport or require "shortport"
  return shortport.ssl(nil, port)
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
    if port.protocol == "udp" then
      stdnse.debug2("DTLS (SSL over UDP) is not supported")
      return "udp", "udp"
    end
    if port.version and port.version.service_tunnel and port.version.service_tunnel == "ssl" then return "ssl","tcp" end
    if port.version and port.version.name_confidence and port.version.name_confidence > 6 then return "tcp","ssl" end
    local _port = {
      number = port.number,
      service = port.service,
      protocol = port.protocol or "tcp",
      state = port.state or "open",
      version = port.version
    }
    if is_ssl(_port) then return "ssl","tcp" end
  elseif type(port) == 'number' then
    if is_ssl({number=port, protocol="tcp", state="open"}) then return "ssl","tcp" end
  end
  return "tcp","ssl"
end

--- This function opens a connection, sends the first data payload and
--  check if a response is correctly received (what means that the
--  protocol used is fine)
--
-- Possible options:
-- timeout, connect_timeout, request_timeout: See module documentation
-- recv_before: receive data before sending first payload
-- proto: the protocol to use ("tcp", "udp", or "ssl")
--
-- @param host The destination host IP
-- @param port The destination host port
-- @param data The first data payload of the connection
-- @param opts An options table
-- @return sd The socket descriptor, nil if no connection is established
-- @return response The response received for the payload, or an error message
-- @return early_resp If opt recv_before is true, returns the value
-- of the first receive (before sending data)
function opencon(host, port, data, opts)
  opts = opts or {}
  local status, sd = setup_connect(host, port, opts)
  if not status then
    return oops.raise("Failed to connect", false, sd)
  end

  local response, early_resp
  if opts.recv_before then status, early_resp = oops.raise("read failed", read(sd, opts)) end
  if data and #data > 0 then
    sd:send(data)
    status, response = oops.raise("receive failed", sd:receive())
  else
    response = early_resp
  end
  if not status then
    sd:close()
  end
  return status and sd, response, early_resp
end

--- Opens a SSL connection if possible, with fallback to plain text.
--
-- For likely-SSL services (as determined by <code>shortport.ssl</code>), SSL
-- is tried first. For UDP services, only plain text is currently supported.
--
-- Either <code>data</code> or <code>opts.recv_before</code> is required:
--
-- * If the service sends a banner first, use <code>opts.recv_before</code>
-- * If the service waits for client data first, provide that via <code>data</code>.
-- * If you provide neither, then a service that waits for client data will
--   only work with SSL and a service that sends a banner first will require you
--   to do a read to get that banner.
--
-- @param host The host table
-- @param port The port table
-- @param data The first data payload of the connection. Optional if
--             <code>opts.recv_before</code> is true.
-- @param opts Options, such as timeout
-- @return sd The socket descriptor, or nil on error
-- @return response The response received for the payload, or an error message
-- @return correctOpt Correct option for connection guess
-- @return earlyResp If opt recv_before is true, returns the value
-- of the first receive (before sending data)
function tryssl(host, port, data, opts)
  opts = opts or {}
  if not data and not opts.recv_before then
    stdnse.debug1(
      "Using comm.tryssl without either first data payload or opts.recv_before.\n\z
      Impossible to test the connection for the correct protocol!"
      )
  end
  local opt1, opt2 = bestoption(port)
  local best = opt1
  if opts.proto=="udp" then
    stdnse.debug2("DTLS (SSL over UDP) is not supported")
  end
  opts.proto = opt1
  local sd, response, early_resp = oops.raise(("%s failed"):format(opt1), opencon(host, port, data, opts))
  -- Try the second option (If udp, then both options are the same; skip it)
  if not sd and opt1 ~= "udp" then
    opts.proto = opt2
    sd, response, early_resp = oops.raise(("%s failed"):format(opt2), opencon(host, port, data, opts))
    best = opt2
  end
  if not sd then best = "none" end
  return sd, response, best, early_resp
end

local unittest = require "unittest"
if not unittest.testing() then
  return _ENV
end
test_suite = unittest.TestSuite:new()
test_suite:add_test(unittest.table_equal({bestoption(443)}, {"ssl", "tcp"}), "bestoption ssl number")
test_suite:add_test(unittest.table_equal({bestoption(80)}, {"tcp", "ssl"}), "bestoption tcp number")
test_suite:add_test(unittest.table_equal({bestoption({number=8443,protocol="tcp",state="open"})}, {"ssl", "tcp"}), "bestoption ssl table")
test_suite:add_test(unittest.table_equal({bestoption({number=1234,protocol="tcp",state="open"})}, {"tcp", "ssl"}), "bestoption tcp table")

return _ENV;
