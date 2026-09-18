-- Script name: egress-check.nse
-- Author: David Kasabji
-- Description: Tests egress filtering by attempting to establish connections to an external server.
-- License: Same as Nmap (see https://nmap.org/book/man-legal.html)
-- Categories: discovery, external

local nmap = require "nmap"
local socket = require "nmap.socket"
local stdnse = require "stdnse"

description = [[
Tests egress filtering by attempting to establish connections to an external server
across a specified range of ports. Specify the external server's IP and port range
using script arguments.

Usage:
nmap --script egress-check --script-args egress-server=<server-ip>,egress-ports=1-1000
]]

categories = {"discovery", "external"}

author = "David Kasabji"

license = "Same as Nmap"

-- Define script arguments
hostrule = function(host, port)
  return true -- Run this script globally (doesn't depend on local port states)
end

action = function(host)
  local server = stdnse.get_script_args("egress-server")
  local port_range = stdnse.get_script_args("egress-ports")

  if not server then
		  return "Missing argument: egress-server. Use --script-args egress-server=<egress-server-ip>"
  end

  if not port_range then
		  return "Missing argument: egress-ports. Use --script-args egress-ports=<start>-<end>"
  end

  -- Parse port range
  local start_port, end_port = port_range:match("(%d+)%-(%d+)")
  if not start_port or not end_port then
    return "Invalid port range format. Use the format <start>-<end>, e.g., 1-1000."
  end

  start_port, end_port = tonumber(start_port), tonumber(end_port)
  if not start_port or not end_port or start_port > end_port then
    return "Invalid port range. Ensure start < end and both are valid numbers."
  end

  local results = {}
  for test_port = start_port, end_port do
    stdnse.print_debug(1, "Testing egress to %s:%d", server, test_port)
    local sock = nmap.new_socket()
    local connection, err = sock:connect(server, test_port)

    if connection then
      results[#results + 1] = test_port
      stdnse.print_debug(1, "Port %d: Egress allowed.", test_port)
    else
      stdnse.print_debug(2, "Port %d: Egress blocked. Error: %s", test_port, err or "unknown error")
    end

    sock:close()
  end

  -- Compile results
  if #results > 0 then
    return string.format("Egress allowed on ports: %s", table.concat(results, ", "))
  else
    return "No ports with egress capabilities detected in the specified range."
  end
end

