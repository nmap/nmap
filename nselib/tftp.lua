--- Library implementing a minimal TFTP server
--
-- Currently only write-operations are supported so that script can trigger
-- TFTP transfers and receive the files and return them as result.
-- 
-- The library contains the following classes
-- * <code>Packet</code>
-- ** The <code>Packet</code> classes contain one class for each TFTP operation.
-- * <code>File</code>
-- ** The <code>File</code> class holds a recieved file including the name and contents
-- * <code>ConnHandler</code>
-- ** The <code>ConnHandler</code> class handles and processes incoming connections.
--
-- The following code snipplet starts the TFTP server and waits for the file incoming.txt
-- to be uploaded for 10 seconds:
-- <code>
--   tftp.start()
--   local status, f = tftp.waitFile("incoming.txt", 10)
--   if ( status ) then return f:getContent() end
-- </code>
--
-- @author Patrik Karlsson <patrik@cqure.net>
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--

-- version 0.2
--
-- 2011-01-22 - re-wrote library to use coroutines instead of new_thread code.

module(... or "tftp", package.seeall)

threads, infiles, running = {}, {}, {}
state = "STOPPED"
srvthread = {}

-- All opcodes supported by TFTP
OpCode = {
	RRQ = 1,
	WRQ = 2,
	DATA = 3,
	ACK = 4,
	ERROR = 5,	
}


--- A minimal packet implementation
--
-- The current code only implements the ACK and ERROR packets
-- As the server is write-only the other packet types are not needed
Packet = {
	
	-- Implements the ACK packet
	ACK = {
		
		new = function( self, block )
			local o = {}
		   	setmetatable(o, self)
	        self.__index = self
			o.block = block
			return o
		end,
		
		__tostring = function( self )
			return bin.pack(">SS", OpCode.ACK, self.block)
		end,
		
	},
	
	-- Implements the error packet
	ERROR = {

		new = function( self, code, msg )
			local o = {}
		   	setmetatable(o, self)
	        self.__index = self
			o.msg = msg
			o.code = code
			return o
		end,
		
		__tostring = function( self )
			return bin.pack(">SSz", OpCode.ERROR, self.code, self.msg)
		end,
	}
	
}

--- The File class holds files received by the TFTP server
File = {
	
	--- Creates a new file object
	--
	-- @param filename string containing the filename
	-- @param content string containing the file content
	-- @return o new class instance
	new = function(self, filename, content, sender)
		local o = {}
	   	setmetatable(o, self)
        self.__index = self
		o.name = filename
		o.content = content
		o.sender = sender
		return o
	end,

	getContent = function(self)	return self.content	end,
	setContent = function(self, content) self.content = content	end,

	getName = function(self) return self.name end,
	setName = function(self, name) self.name = name end,
	
	setSender = function(self, sender) self.sender = sender end,
	getSender = function(self) return self.sender end,
}


-- The thread dispatcher is called by the start function once
local function dispatcher()

	local last = os.time()
	local f_condvar = nmap.condvar(infiles) 
	local s_condvar = nmap.condvar(state)

	while(true) do
	
		-- check if other scripts are active
		local counter = 0
		for t in pairs(running) do
			counter = counter + 1
		end
		if ( counter == 0 ) then 
			state = "STOPPING"
			s_condvar "broadcast"
		end
	
		if #threads == 0 then break end
		for i, thread in ipairs(threads) do
			local status, res = coroutine.resume(thread)
			if ( not(res) ) then    -- thread finished its task?
				table.remove(threads, i)
            	break
          	end
        end
        		
		-- Make sure to process waitFile atleast every 2 seconds
		-- in case no files have arrived
		if ( os.time() - last >= 2 ) then
			last = os.time()
			f_condvar "broadcast"
		end
		
	end
	state = "STOPPED"
	s_condvar "broadcast"
	stdnse.print_debug("Exiting _dispatcher")
end

-- Processes a new incoming file transfer
-- Currently only uploads are supported
--
-- @param host containing the hostname or ip of the initiating host
-- @param port containing the port of the initiating host
-- @param data string containing the initial data passed to the server
local function processConnection( host, port, data )
	local pos, op = bin.unpack(">S", data)
	local socket = nmap.new_socket("udp")

	socket:set_timeout(1000)
	local status, err = socket:connect(host, port)
	if ( not(status) ) then	return status, err end

	socket:set_timeout(10)
	
	-- If we get anything else than a write request, abort the connection
	if ( OpCode.WRQ ~= op ) then
		stdnse.print_debug("Unsupported opcode")
		socket:send( tostring(Packet.ERROR:new(0, "TFTP server has write-only support")))
	end

	local pos, filename, enctype = bin.unpack("zz", data, pos)
	status, err = socket:send( tostring( Packet.ACK:new(0) ) )
	
	local blocks = {}
	local lastread = os.time()
	
	while( true ) do
		local status, pdata = socket:receive()
		if ( not(status) ) then
			-- if we're here and havent succesfully read a packet for 5 seconds, abort
			if ( os.time() - lastread  > 5 ) then
				coroutine.yield(false)
			else
				coroutine.yield(true)
			end
		else
			-- record last time we had a succesful read
			lastread = os.time()
			pos, op = bin.unpack(">S", pdata)
			if ( OpCode.DATA ~= op ) then
				stdnse.print_debug("Expected a data packet, terminating TFTP transfer")
			end
		
			local block, data
			pos, block, data = bin.unpack(">SA" .. #pdata - 4, pdata, pos )
		
			blocks[block] = data
		
			-- First block was not 1
			if ( #blocks == 0 ) then
				socket:send( tostring(Packet.ERROR:new(0, "Did not receive block 1")))
				break
			end
		
			-- for every fith block check that we've received the preceeding four
			if ( ( #blocks % 5 ) == 0 ) then
				for b = #blocks - 4, #blocks do
					if ( not(blocks[b]) ) then
						socket:send( tostring(Packet.ERROR:new(0, "Did not receive block " .. b)))
					end
				end
			end
		
			-- Ack the data block
			status, err = socket:send( tostring(Packet.ACK:new(block)) )

			if ( ( #blocks % 20 ) == 0 ) then
				-- yield every 5th iteration so other threads may work
				coroutine.yield(true)
			end
		
			-- If the data length was less than 512, this was our last block			
			if ( #data < 512 ) then
				socket:close()
				break
			end
		end
	end
	
	local filecontent = ""
	
	-- Make sure we received all the blocks needed to proceed
	for i=1, #blocks do
		if ( not(blocks[i]) ) then
			return false, ("Block #%d was missing in transfer")
		end
		filecontent = filecontent .. blocks[i]
	end
	stdnse.print_debug("Finnished receiving file \"%s\"", filename)
	
	-- Add  anew file to the global infiles table
	table.insert( infiles, File:new(filename, filecontent, host) )
	
	local condvar = nmap.condvar(infiles)
	condvar "broadcast"
end

-- Waits for a connection from a client
local function waitForConnection()
	
	local srvsock = nmap.new_socket("udp")
	local status = srvsock:bind(nil, 69)
	assert(status, "Failed to bind to TFTP server port")
	
	srvsock:set_timeout(0)
	
	while( state == "RUNNING" ) do
		local status, data = srvsock:receive()
		if ( not(status) ) then 
			coroutine.yield(true) 
		else
			local status, _, _, rhost, rport = srvsock:get_info()
			local x = coroutine.create( function() processConnection(rhost, rport, data) end )
			table.insert( threads, x )
			coroutine.yield(true)
		end
	end
end


--- Starts the TFTP server and creates a new thread handing over to the dispatcher
function start()
	local disp = nil
	local mutex = nmap.mutex("srvsocket")

	-- register a running script
	running[coroutine.running()] = true

	mutex "lock"
	if ( state == "STOPPED" ) then
		srvthread = coroutine.running()	
		table.insert( threads, coroutine.create( waitForConnection ) )
		stdnse.new_thread( dispatcher )
		state = "RUNNING"
	end
	mutex "done"
	
end

local function waitLast()
	-- The thread that started the server needs to wait here until the rest
	-- of the scripts finnish running. We know we are done once the state
	-- shifts to STOPPED and we get a singla from the condvar in the
	-- dispatcher
	local s_condvar = nmap.condvar(state)
	while( srvthread == coroutine.running() and state ~= "STOPPED" ) do
		s_condvar "wait"
	end
end

--- Waits for a file with a specific filename for at least the number of
-- seconds specified by the timeout parameter. If this function is called
-- from the thread that's running the server it will wait until all the
-- other threads have finnished executing before returning.
--
-- @param filename string containing the name of the file to receive
-- @param timeout number containing the minimum number of seconds to wait
--        for the file to be received
-- @return status true on success false on failure
-- @return File instance on success, nil on failure
function waitFile( filename, timeout )
	local condvar = nmap.condvar(infiles)
	local t = os.time()
	while(os.time() - t < timeout) do
		for _, f in ipairs(infiles) do
			if (f:getName() == filename) then 
				running[coroutine.running()] = nil
				waitLast()
				return true, f 
			end
		end
		condvar "wait"
	end
	-- de-register a running script
	running[coroutine.running()] = nil
	waitLast()

	return false
end
