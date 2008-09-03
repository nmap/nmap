---
-- Connects to portmapper and fetches a list of all registered programs
-- 
--@output
-- 111/tcp open  rpcbind
-- |  rpcinfo:  
-- |  100000  2        111/udp  rpcbind   
-- |  100005  1,2,3    705/udp  mountd    
-- |  100003  2,3,4   2049/udp  nfs       
-- |  100024  1      32769/udp  status    
-- |  100021  1,3,4  32769/udp  nlockmgr  
-- |  100000  2        111/tcp  rpcbind   
-- |  100005  1,2,3    706/tcp  mountd    
-- |  100003  2,3,4   2049/tcp  nfs       
-- |  100024  1      50468/tcp  status    
-- |_ 100021  1,3,4  50468/tcp  nlockmgr  


require "shortport"
require "datafiles"
require "bin"
require "bit"
require "tab"

id = "rpcinfo"
description = "connects to portmapper and fetches a list of all registered programs"
author = "Sven Klemm <sven@c3d2.de>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default","safe","discovery"}

portrule = shortport.port_or_service(111, "rpcbind")

--- format a table of version for output
--@param version_table table containing the versions 
--@return string with the formatted versions
local format_version = function( version_table )
  table.sort( version_table )
  return table.concat( version_table, ',' )
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(1000)
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)
  local rpc_numbers = try(datafiles.parse_rpc())

  try(socket:connect(host.ip, port.number))

  -- build rpc dump call packet
  local transaction_id = math.random(0x7FFFFFFF)
  local request = bin.pack('>IIIIIIILL',0x80000028,transaction_id,0,2,100000,2,4,0,0)
  try(socket:send(request))

  local answer = try(socket:receive_bytes(1))

  local _,offset,header,length,tx_id,msg_type,reply_state,accept_state,value,payload,last_fragment
  last_fragment = false; offset = 1; payload = ''

  -- extract payload from answer and try to receive more packets if header with
  -- last_fragment set has not been received
  while not last_fragment do
    if offset > #answer then
      answer = answer .. try(socket:receive_bytes(1))
    end
    offset,header = bin.unpack('>I',answer,offset)
    last_fragment = bit.band( header, 0x80000000 ) ~= 0
    length = bit.band( header, 0x7FFFFFFF )
    payload = payload .. answer:sub( offset, offset + length - 1 )
    offset = offset + length
  end
  socket:close()

  offset,tx_id,msg_type,reply_state,_,_,accept_state = bin.unpack( '>IIIIII', payload )

  -- transaction_id matches, message type reply, reply state accepted and accept state executed successfully
  if tx_id == transaction_id and msg_type == 1 and reply_state == 0 and accept_state == 0 then
    local dir = { udp = {}, tcp = {}}
    local protocols = {[6]='tcp',[17]='udp'}
    local rpc_prog, rpc_vers, rpc_proto, rpc_port
    offset, value = bin.unpack('>I',payload,offset)
    while value == 1 and #payload - offset >= 19 do
      offset,rpc_prog,rpc_vers,rpc_proto,rpc_port,value = bin.unpack('>IIIII',payload,offset)
      rpc_proto = protocols[rpc_proto] or tostring( rpc_proto )
      -- collect data in a table
      dir[rpc_proto] = dir[rpc_proto] or {}
      dir[rpc_proto][rpc_port] = dir[rpc_proto][rpc_port] or {}
      dir[rpc_proto][rpc_port][rpc_prog] = dir[rpc_proto][rpc_port][rpc_prog] or {}
      table.insert( dir[rpc_proto][rpc_port][rpc_prog], rpc_vers )
    end

    -- format output
    local output = tab.new(4)
    for rpc_proto, o in pairs(dir) do
      -- get list of all used ports
      local ports = {}
      for rpc_port, i in pairs(o) do table.insert(ports, rpc_port) end
      table.sort(ports)

      -- iterate over ports to produce output
      for i, rpc_port in ipairs(ports) do
        i = o[rpc_port]
        for rpc_prog, versions in pairs(o[rpc_port]) do
          local name = rpc_numbers[rpc_prog] or ''
          tab.addrow(output,rpc_prog,format_version(versions),('%5d/%s'):format(rpc_port,rpc_proto),name)
        end
      end
    end
    return ' \n' .. tab.dump( output )

  end

end

