--- IMAP functions.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "imap", package.seeall)

require 'stdnse'


---
-- Asks an IMAP server for capabilities.
--
-- See RFC 3501.
-- @param host Host to be queried.
-- @param port Port to connect to.
-- @return Table containing capabilities or nil on error.
-- @return nil or String error message.
function capabilities(host, port)
   local socket = nmap.new_socket()
   local capas = {}
   socket:set_timeout(10000)
   local proto = (port.version and port.version.service_tunnel == "ssl" and "ssl") or "tcp"
   if not socket:connect(host.ip, port.number, proto) then return nil, "Could Not Connect" end

   local status, line = socket:receive_lines(1)
   if not string.match(line, "^[%*] OK") then return nil, "No Response" end
   
   socket:send("a001 CAPABILITY\r\n")
   status, line = socket:receive_buf("\r\n", false)
   if not status then 
      capas.CAPABILITY = false
   else 
      while status do
         if string.match(line, "^%*%s+CAPABILITY") then
	    line = string.gsub(line, "^%*%s+CAPABILITY", "")
	    for capability in string.gmatch(line, "[%w%+=-]+") do
	       capas[capability] = true
            end
            break
         end
         status, line = socket:receive_buf("\r\n", false)
      end
   end
   socket:close()
   return capas
end
