description = [[
Attempts to extract information from Microsoft SQL Server instances.
]]
-- rev 1.0 (2007-06-09)
-- rev 1.1 (2009-12-06 - Added SQL 2008 identification T Sellers)

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "intrusive"}

require('stdnse')
require "shortport"
require("strbuf")

portrule = shortport.portnumber({1433, 1434}, "udp", {"open", "open|filtered"})

action = function(host, port)

	-- create the socket used for our connection
	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	-- do some exception handling / cleanup
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)
	
	-- try to login to MS SQL network service, and obtain the real version information
	-- MS SQL 2000 does not report the correct version in the data sent in response to UDP probe (see below)
	local get_real_version = function(dst, dstPort)
	  
	  local outcome
	  local payload =  strbuf.new()
	  
	  local stat, resp
	  
	  -- build a TDS packet - type 0x12
	  -- copied from packet capture of osql connection
	  payload = payload .. "\018\001\000\047\000\000\001\000\000\000"
	  payload = payload .. "\026\000\006\001\000\032\000\001\002\000"
	  payload = payload .. "\033\000\001\003\000\034\000\004\004\000"
	  payload = payload .. "\038\000\001\255\009\000\011\226\000\000"
	  payload = payload .. "\000\000\120\023\000\000\000"
	  
	  socket = nmap.new_socket()
	  
	  -- connect to the server using the tcpPort captured from the UDP probe
	  try(socket:connect(dst, dstPort, "tcp"))
	  
	  try(socket:send(strbuf.dump(payload)))
	  
	  -- read in any response we might get
	  stat, resp = socket:receive_bytes(1)
	  
	  if string.match(resp, "^\004") then
		
	    -- build a login packet to send to SQL server
	    -- username = sa, blank password
	    -- for information about packet structure, see http://www.freetds.org/tds.html
	    
	    local query = strbuf.new()
	    query = query .. "\016\001\000\128\000\000\001\000" -- TDS packet header
	    query = query .. "\120\000\000\000\002\000\009\114" -- Login packet header = length, version
	    query = query .. "\000\000\000\000\000\000\000\007" -- Login packet header continued = size, client version
	    query = query .. "\140\018\000\000\000\000\000\000" -- Login packet header continued = Client PID, Connection ID
	    query = query .. "\224\003\000\000\104\001\000\000" -- Login packet header continued = Option Flags 1 & 2, status flag, reserved flag, timezone
	    query = query .. "\009\004\000\000\094\000\004\000" -- Login packet (Collation), then start offsets & lengths (client name, client length)
	    query = query .. "\102\000\002\000\000\000\000\000" -- Login packet, offsets & lengths = username offset, username length, password offset, password length
	    query = query .. "\106\000\004\000\114\000\000\000" -- Login packet, offsets & lengths = app name offset, app name length, server name offset, server name length
	    query = query .. "\000\000\000\000\114\000\003\000" -- Login packet, offsets & lengths = unknown offset, unknown length, library name offset, library name length
	    query = query .. "\120\000\000\000\120\000\000\000" -- Login packet, offsets & lengths = locale offset, locale length, database name offset, database name length
	    query = query .. "\000\000\000\000\000\000\000\000" -- Login packet, MAC address + padding
	    query = query .. "\000\000\000\000\000\000\000\000" -- Login packet, padding
	    query = query .. "\000\000\000\000\000\000\078\000" -- Login packet, padding + start of client name (N)
	    query = query .. "\077\000\065\000\080\000\115\000" -- Login packet = rest of client name (MAP) + username (s)
	    query = query .. "\097\000\078\000\077\000\065\000" -- Login packet = username (a), app name (NMA)
	    query = query .. "\080\000\078\000\083\000\069\000" -- Login packet = app name (P), library name (NSE)
	    
	    -- send the packet down the wire
	    try(socket:send(strbuf.dump(query)))
	    
	    -- read in any response we might get
	    stat, resp = socket:receive_bytes(1)
	  
	    -- successful response to login packet should contain the string "SQL Server"
	    -- however, the string is UCS2 encoded, so we have to add the \000 characters
	    if string.match(resp, "S\000Q\000L\000") then
		  outcome = "\n    sa user appears to have blank password"
		  
		  strbuf.clear(query)
		  -- since we have a successful login, send a query that will tell us what version the server is really running
		  query = query .. "\001\001\000\044\000\000\001\000" -- TDS Query packet
		  query = query .. "\083\000\069\000\076\000\069\000" -- SELE
		  query = query .. "\067\000\084\000\032\000\064\000" -- CT @
		  query = query .. "\064\000\086\000\069\000\082\000" -- @VER
		  query = query .. "\083\000\073\000\079\000\078\000" -- SION
		  query = query .. "\013\000\010\000"
		  
		  -- send the packet down the wire
		  try(socket:send(strbuf.dump(query)))
	      
		  -- read in any response we might get
		  stat, resp = socket:receive_bytes(1)
		  
		  -- strip out the embedded \000 characters
		  local banner = string.gsub(resp, "%z", "")
		  outcome = outcome .. "\n     " .. string.match(banner, "(Microsoft.-)\n")
		  outcome = outcome .. "\n" .. string.match(banner, "\n.-\n.-\n(.-Build.-)\n")
	    end
	    
	    try(socket:close())
	    
	  end -- if string.match(response, "^\004")
	  
	  if outcome == nil then
	    outcome = "\n    Could not retrieve actual version information"
	  end
	  
	  return outcome
	end -- get_real_version(dst, dstPort)
	
	-- connect to the potential SQL server
	try(socket:connect(host.ip, port.number, "udp"))
	
	-- send a magic packet
	-- details here:  http://www.codeproject.com/cs/database/locate_sql_servers.asp
	try(socket:send("\002"))
	
	local status
	local response
	
	-- read in any response we might get
	status, response = socket:receive_bytes(1)
	
	try(socket:close())

	if (not status) then
		return
	end

	if (response == "TIMEOUT") then
		return
	end
	
	-- since we got something back, the port is definitely open
	nmap.set_port_state(host, port, "open")
	
	local result
	
	-- create a lua table to hold some information
	local serverInfo = {}
			
	-- do some pattern matching to exract certain key elements from the response
	-- the data comes back as a long semicolon separated list
	
	-- A single server can have multiple instances, which are separated by a double semicolon
	-- cycle through each instance
	local count = 1
	for instance in string.gmatch(response, "(.-;;)") do
	  result = instance
	  serverInfo[count] = {}
	  serverInfo[count].name = string.match(instance, "ServerName;(.-);")
	  serverInfo[count].instanceName = string.match(instance, "InstanceName;(.-);")
	  serverInfo[count].clustered = string.match(instance, "IsClustered;(.-);")
	  serverInfo[count].version = string.match(instance, "Version;(.-);")
	  serverInfo[count].tcpPort = string.match(instance, ";tcp;(.-);")
	  serverInfo[count].namedPipe = string.match(instance, ";np;(.-);")
	  count = count + 1
	end
	
	-- do some heuristics on the version to see if we can match the major releases
	if string.match(serverInfo[1].version, "^6%.0") then
	  result = "Discovered Microsoft SQL Server 6.0"
	elseif string.match(serverInfo[1].version, "^6%.5") then
	  result = "Discovered Microsoft SQL Server 6.5"
	elseif string.match(serverInfo[1].version, "^7%.0") then
	  result = "Discovered Microsoft SQL Server 7.0"
	elseif string.match(serverInfo[1].version, "^8%.0") then
	  result = "Discovered Microsoft SQL Server 2000"
	elseif string.match(serverInfo[1].version, "^9%.0") then
	  -- The Express Edition of MS SQL Server 2005 has a default instance name of SQLEXPRESS
	  for _,instance in ipairs(serverInfo) do
	    if string.match(instance.instanceName, "SQLEXPRESS") then
	      result = "Discovered Microsoft SQL Server 2005 Express Edition"
	    end
	  end
	  if result == nil then
	    result = "Discovered Microsoft SQL Server 2005"
	  end
	elseif string.match(serverInfo[1].version, "^10%.0") then
	  -- The Express Edition of MS SQL Server 2008 has a default instance name of SQLEXPRESS
	  for _,instance in ipairs(serverInfo) do
	    if string.match(instance.instanceName, "SQLEXPRESS") then
	      result = "Discovered Microsoft SQL Server 2008 Express Edition"
	    end
	  end
	  if result == nil then
	    result = "Discovered Microsoft SQL Server 2008"
	  end
	else
	  result = "Discovered Microsoft SQL Server"
	end
	if serverInfo[1].name ~= nil then
	  result = result .. "\n  Server name: " .. serverInfo[1].name
	end
	if serverInfo[1].version ~= nil then
	  result = result .. "\n  Server version: " .. serverInfo[1].version
	  -- Check for some well known release versions of SQL Server 2005
	  --  for more info, see http://support.microsoft.com/kb/321185
	  if string.match(serverInfo[1].version, "9.00.3042") then
	    result = result .. " (SP2)"
	  elseif string.match(serverInfo[1].version, "9.00.3043") then
	    result = result .. " (SP2)"
	  elseif string.match(serverInfo[1].version, "9.00.2047") then
	    result = result .. " (SP1)"
	  elseif string.match(serverInfo[1].version, "9.00.1399") then
	    result = result .. " (RTM)"
	  -- Check for versions of SQL Server 2008
	  elseif string.match(serverInfo[1].version, "10.0.1075") then
	    result = result .. " (CTP)"
	  elseif string.match(serverInfo[1].version, "10.0.1600") then
	    result = result .. " (RTM)"
	  elseif string.match(serverInfo[1].version, "10.0.2531") then
	    result = result .. " (SP1)"		
	  end
	end
	for _,instance in ipairs(serverInfo) do
	  if instance.instanceName ~= nil then
	    result = result .. "\n  Instance name: " .. instance.instanceName
	  end
	  if instance.tcpPort ~= nil then
	    result = result .. "\n  TCP Port: " .. instance.tcpPort
		result = result .. get_real_version(host.ip, instance.tcpPort)
	  end
    end
	
	return result
	
end


