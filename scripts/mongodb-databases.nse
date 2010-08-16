description = [[
Attempts to get a list of tables from a MongoDB database.
]]

---
-- @usage
-- nmap -p 27017 --script mongodb-databases <host>
-- @output
-- PORT      STATE SERVICE REASON
-- 27017/tcp open  unknown syn-ack
-- | mongodb-databases:  
-- |   ok = 1
-- |   databases
-- |     1
-- |       empty = false
-- |       sizeOnDisk = 83886080
-- |       name = test
-- |     0
-- |       empty = false
-- |       sizeOnDisk = 83886080
-- |       name = httpstorage
-- |     3
-- |       empty = true
-- |       sizeOnDisk = 1
-- |       name = local
-- |     2
-- |       empty = true
-- |       sizeOnDisk = 1
-- |       name = admin
-- |_  totalSize = 167772160

-- version 0.1
-- Created 01/12/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>


author = "Martin Holst Swende"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require "mongodb"
require "shortport"

portrule = shortport.port_or_service({27017}, {"mongodb"})
function action(host,port)

	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(10000)
	-- do some exception  / cleanup
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)

	try( socket:connect(host, port) )
	
	local req, result, packet, err, status
	--Build packet
	status, packet = mongodb.listDbQuery()
	if not status then return result end-- Error message
	
	--- Send packet
	status, result = mongodb.query(socket, packet)
	if not status then return result end-- Error message
	
	local output = mongodb.queryResultToTable(result)
	if err ~= nil then 
		stdnse.log_error(err) 
	end
	if result ~= nil then
		return stdnse.format_output(true, output )
	end
end
