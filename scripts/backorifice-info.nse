local bin = require "bin"
local bit = require "bit"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Connects to a BackOrifice service and gathers information about
the host and the BackOrifice service itself.

The extracted host information includes basic system setup, list
of running processes, network resources and shares.

Information about the service includes enabled port redirections,
listening console applications and a list of BackOrifice plugins
installed with the service.
]]

---
-- @usage
-- nmap --script backorifice-info <target> --script-args backorifice-info.password=<password>
--
-- @arg backorifice-info.password Encryption password (defaults to no password).
-- @arg backorifice-info.seed Encryption seed (default derived from password, or 31337 for no password).
--
--@output
--31337/udp open|filtered BackOrifice
--| backorifice-info:
--|   PING REPLY
--|     !PONG!1.20!HAL9000!
--|   SYSTEM INFO
--|     System info for machine 'HAL9000'
--|     Current user: 'Dave'
--|     Processor: I586
--|     Win32 on Windows 95 v4.10 build 2222 -  A
--|     Memory: 63M in use: 30%  Page file: 1984M free: 1970M
--|     C:\ - Fixed Sec/Clust: 64 Byts/Sec: 512,  Bytes free: 2147155968/21471
--|       ...155968
--|     D:\ - CD-ROM
--|   PROCESS LIST
--|       PID  -    Executable
--|     4293872589 C:\WINDOWS\SYSTEM\KERNEL32.DLL
--|     4294937581 C:\WINDOWS\SYSTEM\MSGSRV32.EXE
--|     4294935933 C:\WINDOWS\SYSTEM\MPREXE.EXE
--|     4294843869 C:\WINDOWS\SYSTEM\MSTASK.EXE
--|     4294838549 C:\WINDOWS\SYSTEM\ .EXE
--|     4294864917 C:\WINDOWS\EXPLORER.EXE
--|     4294880413 C:\WINDOWS\TASKMON.EXE
--|     4294878445 C:\WINDOWS\SYSTEM\SYSTRAY.EXE
--|     4294771309 C:\WINDOWS\WINIPCFG.EXE
--|     4294772081 C:\WINDOWS\SYSTEM\WINOA386.MOD
--|   NETWORK RESOURCES - NET VIEW
--|     (null) '(null)' - Microsoft Network - UNKNOWN!  (Network root?):CONTAINER
--|     (null) 'WORKGROUP' - (null) - DOMAIN:CONTAINER
--|     (null) '\\HAL9000' -  - SERVER:CONTAINER
--|     (null) '\\HAL9000\DOCUMENTS' - sample comment 2 - SHARE:DISK
--|     (null) '\\WIN982' -  - SERVER:CONTAINER
--|     (null) '\\WIN982\BO' - tee hee hee comment - SHARE:DISK
--|   SHARELIST
--|     'DOCUMENTS'-C:\WINDOWS\DESKTOP\DOCUMENTS 'sample comment 2' RO:'' RW:'
--|       ...'' Disk PERSISTANT READONLY
--|     'IPC$'-  'Remote Inter Process Communication' RO:'' RW:'' IPC FULL
--|   REDIRECTED PORTS
--|     0 redirs displayed
--|   LISTENING CONSOLE APPLICATIONS
--|     0 apps listed
--|   PLUGIN LIST
--|_    End of plugins
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"backorifice-brute"}


portrule = shortport.port_or_service (31337, "BackOrifice", "udp")


--variables
local g_packet = 0

--"constants"
local MAGICSTRING ="*!*QWTY?"
local TYPE = {
	ERROR = 0x00,
	PARTIAL_PACKET = 0x80,
	CONTINUED_PACKET = 0x40,
	PING = 0x01,
	SYSINFO = 0x06,
	PROCESSLIST = 0x20,
	NETVIEW = 0x39,
	NETEXPORTLIST = 0x12,
	REDIRLIST = 0x0D,
	APPLIST = 0x3F,
	PLUGINLIST = 0x2F
}


--table of commands which have output
local cmds = {
	{cmd_name="PING REPLY",p_code=TYPE.PING,arg1="",arg2="",
	filter = function(data)
		data = string.gsub(data," ","")
		return data
	end},
	{cmd_name="SYSTEM INFO",p_code=TYPE.SYSINFO,arg1="",arg2="",
	filter = function(data)
		if string.match(data,"End of system info") then return nil end
		return data
	end},
	{cmd_name="PROCESS LIST",p_code=TYPE.PROCESSLIST,arg1="",arg2="",
	filter = function(data)
		if string.match(data,"End of processes") then return nil end
		data = string.gsub(data,"pid","PID")
		return data
	end},
	{cmd_name="NETWORK RESOURCES - NET VIEW",p_code=TYPE.NETVIEW,arg1="",arg2="",
	filter = function(data)
		if string.match(data,"Network resources:") then return nil end
		if string.match(data,"End of resource list") then return nil end
		return data
	end},
	{cmd_name="SHARELIST",p_code=TYPE.NETEXPORTLIST,arg1="",arg2="",
	filter = function(data)
	if string.match(data,"Shares as returned by system:") then return nil end
		if string.match(data,"End of shares") then return nil end
		return data
	end},
	{cmd_name="REDIRECTED PORTS",p_code=TYPE.REDIRLIST,arg1="",arg2="",
	filter = function(data)
		if string.match(data,"Redirected ports:%s") then return nil end
		return data
	end},
	{cmd_name="LISTENING CONSOLE APPLICATIONS",p_code=TYPE.APPLIST,arg1="",arg2="",
	filter = function(data)
		if string.match(data,"Active apps:") then return nil end
		return data
	end},
	-- I !think! plugin list MUST be last because it causes problems server-side
	{cmd_name="PLUGIN LIST",p_code=TYPE.PLUGINLIST,arg1="",arg2="",
	filter = function(data)
		if string.match(data,"Plugins:") then return nil end
		return data
	end}
}

local function gen_next_seed(seed)
	seed = seed*214013 + 2531011
	seed = bit.band(seed,0xffffff)
	return seed
end

local function gen_initial_seed(password)
	if password == nil then
		return 31337
	else
		local y = #password
		local z = 0

		for x = 1,y do
			local pchar = string.byte(password,x)
			z = z + pchar
		end

		for x=1,y do
			local pchar = string.byte(password,x)
			if (x-1)%2 == 1 then
				z = z - (pchar * (y-(x-1)+1))
			else
				z = z + (pchar * (y-(x-1)+1))
			end
			z = z % 0x7fffffff
		end
		z = (z*y) % 0x7fffffff
		return z
	end
end

--BOcrypt returns encrypted/decrypted data
local function BOcrypt(data, password, initial_seed )
	local output =""
	if data==nil then return end

	local seed
	if(initial_seed == nil) then
		--calculate initial seed
		seed = gen_initial_seed(password)
	else
		--in case initial seed is set by backorifice brute
		seed = initial_seed
	end

	local data_byte
	local crypto_byte

	for i = 1, #data  do
		data_byte = string.byte(data,i)

		--calculate next seed
		seed = gen_next_seed(seed)
		--calculate encryption key based on seed
		local key = bit.band(bit.arshift(seed,16), 0xff)

		crypto_byte = bit.bxor(data_byte,key)
		output = bin.pack("AC",output,crypto_byte)
		if i == 256 then break end --ARGSIZE limitation
	end
	return output
end

local function BOpack(type_packet, str1, str2)
-- create BO packet
	local data = ""
	local size = #MAGICSTRING + 4*2 + 3 + #str1 + #str2
	data = bin.pack("A<IICACAC",MAGICSTRING,size,g_packet,type_packet,str1,0x00,str2,0x00)
	g_packet = g_packet + 1
	return data
end

local function BOunpack(packet)
	local pos, magic = bin.unpack("A8",packet)

	if magic ~= MAGICSTRING then return nil,TYPE.ERROR end  --received non-BO packet

	local packetsize, packetid, type_packet, data
	pos, packetsize, packetid, type_packet = bin.unpack("<IIC",packet,pos)
	pos, data = bin.unpack("A"..(packetsize-pos-1),packet,pos)

	return data, type_packet
end

local function insert_version_info(host,port,BOversion,BOhostname,initial_seed,password)
	if(port.version==nil) then port.version={} end
	if(port.version.name==nil) then 
		port.version.name ="BackOrifice"
		port.version.name_confidence = 10
	end
	if(port.version.product==nil) then port.version.product ="BackOrifice trojan" end
	if(port.version.version == nil) then port.version.version = BOversion end
	if(port.version.extrainfo == nil) then 
		if password == nil then
			if initial_seed == nil then
				port.version.extrainfo = "no password"
			else
				port.version.extrainfo = "initial encryption seed="..initial_seed
			end
		else
			port.version.extrainfo = "password="..password
		end
	end
	port.version.hostname = BOhostname
	if(port.version.ostype == nil) then port.version.ostype = "Windows" end
	nmap.set_port_version(host, port)
	nmap.set_port_state(host, port, "open")
end

action = function( host, port )
	--initial seed is set by backorifice-brute
	local initial_seed = stdnse.get_script_args( SCRIPT_NAME .. ".seed" )
	local password = stdnse.get_script_args(SCRIPT_NAME .. ".password")
	local socket = nmap.new_socket("udp")
	local try = nmap.new_try(function() socket:close() end)
	socket:set_timeout(5000)

	local output_all={}

	for i=1,#cmds do
		--send command
		local data = BOpack( cmds[i].p_code, cmds[i].arg1, cmds[i].arg2 )
		data = BOcrypt(data, password, initial_seed)
		try(socket:sendto(host.ip, port.number, data))

		--receive info
		local output, response, p_type, multi_flag
		output = {}
		output.name = cmds[i].cmd_name
		multi_flag = false
		while true do
			response = try(socket:receive())
			response = BOcrypt(response,password,initial_seed)
			response, p_type = BOunpack(response)  -- p_type -> error, singular, partial, continued

			if p_type ~= TYPE.ERROR then
				local tmp_str = cmds[i].filter(response)
				if tmp_str ~= nil then
					if cmds[i].p_code==TYPE.PING then 
						--invalid chars for hostname are allowed on old windows boxes
						local BOversion, BOhostname = string.match(tmp_str,"!PONG!(1%.20)!(.*)!")
						if BOversion==nil then 
							--in case of bad PING reply return ""
							return 
						else
							--fill up version information
							insert_version_info(host,port,BOversion,BOhostname,initial_seed,password)
						end
					end
						
					table.insert(output,tmp_str)
				end

				--singular
				if bit.band(p_type,TYPE.PARTIAL_PACKET)==0x00
					and bit.band(p_type,TYPE.CONTINUED_PACKET)==0x00 then break end

				--first
				if bit.band(p_type,TYPE.CONTINUED_PACKET)==0x00 then
					multi_flag = true
				end

				--last
				if bit.band(p_type,TYPE.PARTIAL_PACKET)==0x00 then break end
			end

		end
		--gather all responses in table
		table.insert(output_all,output)
	end

	socket:close()
	return stdnse.format_output(true,output_all)
end
