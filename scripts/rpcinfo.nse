id = "rpcinfo"

description = "connects to portmapper and prints a list of all registered programs"
author = "Sven Klemm <sven@c3d2.de>"
license = "See nmaps COPYING for licence"
categories = {"safe","discovery"}

require "shortport"
require "bit"
require "stdnse"

local rpc_numbers = {}

-- Fills rpc_numbers with values read from RPC file - Kris Katterjohn
local fillrpc = function()
	local path = nmap.fetchfile("nmap-rpc")

	if path == nil then
		return false
	end

	local file = io.open(path, "r")

	-- Loops through RPC file line-by-line
	while true do
		local l = file:read()

		if not l then
			break
		end

		l = l:gsub("%s*#.*", "")

		if l:len() ~= 0 then
			local m = l:gsub("^([%a%d_]+)%s+(%d+).*", "%2=%1")

			if m:match("=") then
				local t = stdnse.strsplit("=", m)
				rpc_numbers[tonumber(t[1])] = t[2]
			end
		end
	end

	file:close()

	return true
end

portrule = shortport.port_or_service(111, "rpcbind")

action = function(host, port)
  local try, catch
  local transaction_id = "nmap"
  local socket = nmap.new_socket()
  local result = ""

  if not fillrpc() then
    stdnse.print_debug("rpcinfo: Can't read from RPC file!")
    return
  end

  catch = function() socket:close() end
  try = nmap.new_try( catch )

  local ntohl = function( s )
    return bit.lshift(s:byte(1),24) + bit.lshift(s:byte(2),16) +
           bit.lshift(s:byte(3),8) + s:byte(4)
  end

  local request = string.char(0x80,0,0,40) -- fragment header
  request = request .. transaction_id -- transaction id
  request = request .. "\0\0\0\0\0\0\0\2" -- message type: call (0) and rpc version 2
  request = request .. string.char(0,1,134,160) -- programm portmap (100000)
  request = request .. "\0\0\0\2\0\0\0\4" -- programm version (2) procedure dump(4)
  request = request .. "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"-- Credentials and verifier

  socket:set_timeout(1000)
  try( socket:connect(host.ip, port.number) )
  try( socket:send( request ) )
  local status, answer, answer_part
  status, answer = socket:receive_bytes( 1 )
  while status do
    status, answer_part = socket:receive_bytes( 1 )
    if status then answer = answer .. answer_part end
  end

  local fragment_length = answer:byte(4) + answer:byte(3) * 256 + answer:byte(2) * 65536
  if answer:sub(5,8) == transaction_id and answer:byte(12) == 1 and answer:byte(16) == 0 and answer:byte(28) == 0 then
    -- transaction_id matches, message type reply, reply state accepted and accept state executed successfully
    answer_part = answer
    answer = answer_part:sub( 28 + 1, fragment_length + 4 )
    answer_part = answer_part:sub( fragment_length + 4 + 1 )

    while answer_part:len() > 0 do -- defragment packet
      fragment_length = answer_part:byte(4) + answer_part:byte(3) * 256 + answer_part:byte(2) * 65536
      answer = answer .. answer_part:sub( 5, fragment_length + 4 )
      answer_part = answer_part:sub( fragment_length + 4 + 1 )
    end

    while answer:byte(4) == 1 and answer:len() >= 20 do
      local rpc_prog, rpc_vers, rpc_proto, rpc_port
      if result:len() > 0 then result = result .. '\n' end
      rpc_prog = ntohl( answer:sub(5,8))
      rpc_vers = ntohl( answer:sub(9,12))
      rpc_proto = ntohl( answer:sub(13,16))
      rpc_port = ntohl( answer:sub(17,20))
      answer = answer:sub(21)
      if rpc_proto == 6 then
        rpc_proto = "tcp"
      elseif rpc_proto == 17 then
        rpc_proto = "udp"
      end
      result = result .. string.format("%s(%d) %d/%s",rpc_numbers[rpc_prog] or rpc_prog,rpc_vers,rpc_port,rpc_proto)
    end

  end

  return result
end

