local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local http = require "http"
local bin = require "bin"

description = [[
Gathers info from the Metasploit rpc service.
It requires a valid login pair. After authentication it 
tries to determine Metasploit version and deduce the OS type.
Then it creates a new console and executes few commands
to get additional info. 
References:
 * http://wiki.msgpack.org/display/MSGPACK/Format+specification 
 *  https://community.rapid7.com/docs/DOC-1516 Metasploit RPC API Guide
]]

---
--@usage
-- nmap <target> --script=metasploit-info --script-args username=root,password=root
--@output
-- 55553/tcp open  metasploit-msgrpc syn-ack
-- | metasploit-info:
-- |   Metasploit version: 4.4.0-dev Ruby version: 1.9.3 i386-mingw32 2012-02-16 API version: 1.0
-- |   Additional info:
-- |   Host Name:                 WIN
-- |   OS Name:                   Microsoft Windows XP Professional
-- |   OS Version:                5.1.2600 Service Pack 3 Build 2600
-- |   OS Manufacturer:           Microsoft Corporation
-- |   OS Configuration:          Standalone Workstation
-- |   OS Build Type:             Uniprocessor Free
-- |  ..... lots of other info ....
-- |   Domain:                    WORKGROUP
-- |_  Logon Server:              \\BLABLA
-- 
-- @args metasploit-info.username  Valid metasploit rpc username (required)
-- @args metasploit-info.password  Valid metasploit rpc password (required)
-- @args metasploit-info.command   Custom command to run on the server (optional)



author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive","safe"}

portrule = shortport.port_or_service(55553,"metasploit-msgrpc")
local arg_username 		= stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password 		= stdnse.get_script_args(SCRIPT_NAME .. ".password")
local arg_command 		= stdnse.get_script_args(SCRIPT_NAME .. ".command")
local os_type

-- returns a "prefix" that msgpack uses for strings 
local get_prefix = function(data)
	if string.len(data) <= 31 then
		return bin.pack("C",0xa0 + string.len(data))
	else 
		return bin.pack("C",0xda)  .. bin.pack("s",string.len(data))
	end	
	
end

-- returns a msgpacked data for console.read
local encode_console_read = function(method,token, console_id)
	return bin.pack("C",0x93) .. get_prefix(method) .. method .. bin.pack("H","da0020") .. token .. get_prefix(console_id) .. console_id
end

-- returns a msgpacked data for console.write
local encode_console_write = function(method, token, console_id, command)
	return bin.pack("C",0x94) .. get_prefix(method) .. method .. bin.pack("H","da0020") .. token .. get_prefix(console_id) .. console_id .. get_prefix(command) .. command
end

-- returns a msgpacked data for auth.login
local encode_auth = function(username, password)
	local method = "auth.login"
	return bin.pack("C",0x93) .. bin.pack("C",0xaa) .. method .. get_prefix(username) .. username .. get_prefix(password) .. password
end

-- returns a msgpacked data for any method without exstra parameters
local encode_noparam = function(token,method)
	-- token is always the same length
	return bin.pack("C",0x92) .. get_prefix(method) .. method .. bin.pack("H","da0020") .. token
end 

-- does the actuall call with specified, pre-packed data
-- and returns the response
local msgrpc_call = function(host, port, msg)
	local data
	local options = {
		header = {
			["Content-Type"] = "binary/message-pack"
		}
	}
	data = http.post(host,port, "/api/",options, nil , msg)
	if data and data.status and tostring( data.status ):match( "200" )  then
		return data.body
	end
	return nil
end

-- auth.login wraper, returns the auth token
local login = function(username, password,host,port)
	
	local data  = msgrpc_call(host, port, encode_auth(username,password))
	
	if data then
		local start = string.find(data,"success")
		if  start > -1 then
			-- get token
			local token = string.sub(string.sub(data,start),17) -- "manualy" unpack token
			return true, token
		else
			return false, nil
		end
	end
	stdnse.print_debug("something is wrong:" .. data )
	return false, nil
end

-- core.version wraper, returns version info, and sets the OS type
-- so we can decide which commands to send later
local get_version = function(host, port, token)
	local msg = encode_noparam(token,"core.version")

	local data = msgrpc_call(host, port, msg)
	-- unpack data 
	if data then
		-- get version, ruby version, api version
		local start = string.find(data,"version")
		local metasploit_version
		local ruby_version 
		local api_version
		if start then 
			metasploit_version = string.sub(string.sub(data,start),9)
			start = string.find(metasploit_version,"ruby")
			start = start - 2
			metasploit_version = string.sub(metasploit_version,1,start)
			start = string.find(data,"ruby")
			ruby_version = string.sub(string.sub(data,start),6)
			start = string.find(ruby_version,"api")
			start = start - 2 			
			ruby_version = string.sub(ruby_version,1,start)
			start = string.find(data,"api")
			api_version = string.sub(string.sub(data,start),5)
			-- put info in a table and parse for OS detection and other info
			port.version.name = "metasploit-msgrpc"
			port.version.product = metasploit_version
			port.version.name_confidence = 100
			nmap.set_port_version(host,port)
			local info = "Metasploit version: " .. metasploit_version .. " Ruby version: " .. ruby_version .. " API version: " .. api_version
			if string.find(ruby_version,"mingw") < 0 then
				os_type = "linux" -- assume linux for now
			else -- mingw compiler means it's a windows build
				os_type = "windows"
			end
			stdnse.print_debug(info)
			return info
		end
	end
	return nil
end

-- console.create wraper, returns console_id 
-- which we can use to interact with metasploit further
local create_console = function(host,port,token)
	local msg = encode_noparam(token,"console.create")
	local data = msgrpc_call(host, port, msg)
	-- unpack data 
	if data then
		--get console id
		local start = string.find(data,"id")
		local console_id 
		if start then
			console_id = string.sub(string.sub(data,start),4)
			local next_token = string.find(console_id,"prompt")
			console_id = string.sub(console_id,1,next_token-2)
			return console_id
		end
	end
	return nil

end

-- console.read wraper
local read_console = function(host,port,token,console_id)
	local msg = encode_console_read("console.read",token,console_id)
	local data = msgrpc_call(host, port, msg)
	-- unpack data 
	if data then
		-- check if busy
		while string.byte(data,string.len(data)) == 0xc3 do
			-- console is busy , let's retry in one second
			stdnse.sleep(1)
			data = msgrpc_call(host, port, msg)
		end
		local start = string.find(data,"data")
		local read_data 
		if start then
			read_data = string.sub(string.sub(data,start),8)
			local next_token = string.find(read_data,"prompt")
			read_data = string.sub(read_data,1,next_token-2)
			return read_data
		end		
	end 
end

-- console.write wraper
local write_console = function(host,port,token,console_id,command)
	local msg = encode_console_write("console.write",token,console_id,command .. "\n")
	local data = msgrpc_call(host, port, msg)
	-- unpack data 
	if data then
		return true
	end
	return false
end

-- console.destroy wraper, just to be nice, we don't want console to hang ...
local destroy_console = function(host,port,token,console_id)
	local msg = encode_console_read("console.destroy",token,console_id)
	local data = msgrpc_call(host, port, msg)
end

-- write command and read result helper
local write_read_console = function(host,port,token, console_id,command)
	if write_console(host,port,token,console_id, command) then 
		local read_data = read_console(host,port,token,console_id)
		if read_data then
			read_data = string.sub(read_data,string.find(read_data,"\n")+1) -- skip command echo
			return read_data
		end
	end
	return nil
end

action = function( host, port )
	if not arg_username or not arg_password then
		stdnse.print_debug("This script requires username and password supplied as arguments")
		return false
	end
	
	-- authenticate
	local status, token = login(arg_username,arg_password,host,port)
	if  status then
		-- get version info
		local info = get_version(host,port,token)
		local console_id = create_console(host,port,token)
		if console_id then
			local read_data = read_console(host,port,token,console_id) -- first read the banner/ascii art
			stdnse.print_debug(2,read_data) -- print the nice looking banner if dbg level high enough :)
			if read_data then
				if os_type == "linux" then
					read_data = write_read_console(host,port,token,console_id, "uname -a")
					if read_data then
						info = info .. "\nAdditional info: " ..  read_data
					end
					read_data = write_read_console(host,port,token,console_id, "id")
					if read_data then
						info = info ..  read_data
					end
				elseif os_type == "windows" then 
					read_data = write_read_console(host,port,token,console_id, "systeminfo")
					if read_data then
						stdnse.print_debug(2,read_data) -- print whole info if dbg level high enough
						local stop = string.find(read_data,"Hotfix") -- trim data down , systeminfo return A LOT
						read_data = string.sub(read_data,1,stop-2)
						info = info .. "\nAdditional info: \n" ..  read_data
					end
				end
				if arg_command then
					read_data = write_read_console(host,port,token,console_id, arg_command)
					if read_data then
						info = info .. "\nCustom command output: " ..  read_data
					end
				end
				if read_data then
					-- let's be nice and close the console
					destroy_console(host,port,token,console_id)
				end
			end
		end 
		if info then
			return stdnse.format_output(true,info)
		end
	end
	return false
end
