local nmap = require "nmap"
local shortport = require "shortport"

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
-- |_ pjl-ready-message: "READY" changed to "p0wn3d pr1nt3r"
-- @usage
-- nmap --script=pjl-ready-message.nse \
--   --script-args='pjl_ready_message="your message here"'

author = "Aaron Leininger"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive"}

portrule = shortport.port_or_service(9100, "jetdirect")

local function parse_response(response)
  local msg
  local line

  for line in response:gmatch(".-\n") do
    msg = line:match("^DISPLAY=\"(.*)\"")
    if msg then
      return msg
    end
  end
end

action = function(host, port)

  local status  --to be used to grab the existing status of the display screen before changing it.
  local newstatus  --used to repoll the printer after setting the display to check that the probe worked.
  local statusmsg  --stores the PJL command to get the printer's status
  local response  --stores the response sent over the network from the printer by the PJL status command

  statusmsg="@PJL INFO STATUS\n"

  local rdymsg=""  --string containing text to send to the printer.
  local rdymsgarg=""  --will contain the argument from the command line if one exists

  local socket = nmap.new_socket()
  socket:set_timeout(15000)
  local try = nmap.new_try(function() socket:close() end)
  try(socket:connect(host, port))
  try(socket:send(statusmsg))  --this block gets the current display status
  local data
  response,data=socket:receive()
  if not response then  --send an initial probe. If no response, send nothing further.
    socket:close()
    if nmap.verbosity() > 0 then
      return "No response from printer: "..data
    else
      return nil
    end
  end

  status = parse_response(data)
  if not status then
    if nmap.verbosity() > 0 then
      return "Error reading printer response: "..data
    else
      return nil
    end
  end

  rdymsgarg = nmap.registry.args.pjl_ready_message
  if not rdymsgarg then
    if status then
      return "\""..status.."\""
    else
      return nil
    end
  end

  rdymsg="@PJL RDYMSG DISPLAY = \""..rdymsgarg.."\"\r\n"
  try(socket:send(rdymsg))  --actually set the display message here.

  try(socket:send(statusmsg))  --this block gets the status again for comparison
  response,data=socket:receive()
  if not response then
    socket:close()
    return "\""..status.."\""
  end
  newstatus=parse_response(data)
  if not newstatus then
    socket:close()
    return "\""..status.."\""
  end

  socket:close()

  return "\""..status.."\" changed to \""..newstatus.."\""
end
