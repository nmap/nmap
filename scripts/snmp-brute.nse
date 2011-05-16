description = [[
Attempts to find an SNMP community string by brute force guessing.
]]
-- 2008-07-03

---
-- @args snmpcommunity The SNMP community string to use. If it's supplied, this
-- script will not run.
-- @args snmplist The filename of a list of community strings to try.
--
-- @output
-- PORT    STATE SERVICE
-- 161/udp open  snmp
-- |_snmp-brute: public

author = "Philip Pickering"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "auth"}

require "shortport"
require "snmp"

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

action = function(host, port)

  if nmap.registry.snmpcommunity or nmap.registry.args.snmpcommunity then return end

  -- create the socket used for our connection
  local socket = nmap.new_socket()
  
  -- set a reasonable timeout value
  socket:set_timeout(5000)
  
  -- do some exception handling / cleanup
  local catch = function()
    socket:close()
  end

  local try = nmap.new_try(catch)
	
	-- connect to the potential SNMP system
  try(socket:connect(host, port))

	
  local request = snmp.buildGetRequest({}, "1.3.6.1.2.1.1.3.0")

  local commFile = nmap.registry.args.snmplist and nmap.fetchfile(nmap.registry.args.snmplist)
  local commTable
  
  -- fetch wordlist from file (from unpwdb-lib)
  if commFile then
     local file = io.open(commFile)
     
     if file then
	commTable = {}
	while true do
	   local l = file:read()
	   
	   if not l then
	      break
	   end
					 
	   -- Comments takes up a whole line
	   if not l:match("#!comment:") then
	      table.insert(commTable, l)
	   end
	end
	
	file:close()
     end
  end
  
  -- default wordlist
  if (not commTable) then	commTable = {'public', 'private', 'snmpd', 'snmp', 'mngt', 'cisco', 'admin'} end
  
  -- send all possible words out before waiting for an answer
  for _, commStr in ipairs(commTable) do
     local payload = snmp.encode(snmp.buildPacket(request, 0, commStr))
     try(socket:send(payload))
  end
  
  -- finally wait for a response
  local status
  local response
  
  status, response = socket:receive_bytes(1)
  
  if (not status) then
     return
  end
  
  if (response == "TIMEOUT") then
     return
  end
  nmap.set_port_state(host, port, "open")
  
  local result
  _, result = snmp.decode(response)
  
  -- response contains valid community string
  if type(result) == "table" then
     nmap.registry.snmpcommunity = result[2]
     return result[2]
  end
  
  return
end

