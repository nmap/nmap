description = [[
Retrieves or sets the ready message on printers that support the Printer
Job Language. This includes most PostScript printers that listen on port
9100. Without an argument, displays the current ready message. With the
<code>pjl_ready_message</code> script argument, displays the old ready
message and changes it to the message given.
]]

---
-- @arg pjl_ready_message Ready message to display.
-- @output
-- 9100/tcp open  jetdirect
-- |   hprdymsg: "Printer display initially read: "<initial message>"
-- |_ "p0wn3d pr1nt3r" was set as the display for printer at printer.ip.address
-- |_ "Re-polling printer to check that message was successful"
-- |_ "Current printer display message: "p0wn3d pr1nt3r"
-- @usage
-- nmap --script=pjl-ready-message.nse \
--   --script-args='pjl_ready_message="your message here"'

author = "Aaron Leininger <rilian4@hotmail.com>" 

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive"}

require "nmap"
require "shortport"
portrule = shortport.port_or_service(9100, "jetdirect")

local function parse_response(response)
	local msg
	local line
	local found=0
	
	for line in response:gmatch(".-\n") do
		msg = line:match("^DISPLAY=\"(.*)\"")
		if msg then
			found=1
			break
		end
	end
	if found==1 then
		return(msg)
	else
		return("No Response from Printer")
	end
end

action = function(host, port)

	local status		--to be used to grab the existing status of the display screen before changing it. 
	local newstatus		--used to repoll the printer after setting the display to check that the probe worked.
	local statusmsg		--stores the PJL command to get the printer's status
	local response		--stores the response sent over the network from the printer by the PJL status command
	
	statusmsg="@PJL INFO STATUS\n"
	
	local rdymsg=""			--string containing text to send to the printer. 
	local rdymsgarg=""		--will contain the argument from the command line if one exists

	local socket = nmap.new_socket()
	socket:set_timeout(15000)
	try = nmap.new_try(function() socket:close() end)
	try(socket:connect(host.ip, port.number))
	try(socket:send(statusmsg))		--this block gets the current display status
	response,data=socket:receive()  
	if not response then			--send an initial probe. If no response, send nothing further. 
		socket:close()
		return("No response from printer")
	else
	--The following block will check for an argument from the command line and if there isn't one, it will attempt to return the current display and quit out
		if not nmap.registry.args.pjl_ready_message then
			status=parse_response(data)
			return("Current Display: \""..status.."\"")
		else	--There is a command-line arg if you got here. Set up the new display message for injection. 
			rdymsgarg=nmap.registry.args.pjl_ready_message
		end
	end
	
	rdymsg="@PJL RDYMSG DISPLAY = \""..rdymsgarg.."\"\r\n"
	try(socket:send(rdymsg)) 		--actually set the display message here.
	
	try(socket:send(statusmsg))		--this block gets the status again for comparison
	response,data=socket:receive()
	newstatus=parse_response(data)
	
	socket:close()
	
	local outstring
	outstring = "\""..rdymsgarg.."\"".." was set as the display for printer at "..host.ip.."\r\n".."Re-polling printer to check that message was successful...\r\n".."Current printer display message: \""..newstatus.."\""
	return(outstring)
end
