description = [[
Detects the TNS Poison vulnerability.

The vulnerability, called TNS Poison (CVE-2012-1675), affects the
component called TNS Listener, which is the responsible of connections
establishment. To exploit the vulnerability no privilege is needed, just
network access to the TNS Listener. The "feature" exploited is enabled by
default in all Oracle versions starting with Oracle 8i and ending with
Oracle 11g.

Reference:
  Oracle Security Alert:
  https://www.oracle.com/technetwork/topics/security/alert-cve-2012-1675-1608180.html

  How this can be exploited:
  http://joxeankoret.com/download/tnspoison.pdf
]]

author      = "Alexandr Savca"
license     = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories  = {"vuln", "safe"}

---
-- @usage
-- nmap <ip> -p 1521-1523 --script oracle-vuln-tns-poison
--
-- @output
-- PORT     STATE SERVICE
-- 1521/tcp open  oracle
-- | oracle-vuln-tns-poison:
-- |   VULNERABLE:
-- |   The vulnerability allows to intercept traffic between the client and the
-- |   Oracle database.
-- |     State: VULNERABLE
-- |     IDs: CVE:CVE-2012-1675
-- |     Description:
-- |       When client sends a TNS packet of type CONNECT to the TNS Listener with
-- |       the following string:
-- |         - Oracle 9i to 11g: (CONNECT_DATA=(COMMAND=SERVICE_REGISTER_NSGR))
-- |         - Oracle 8i: (CONNECT_DATA=(COMMAND=SERVICE_REGISTER))
-- |       The vulnerable server answers with a TNS packet of type ACCEPT. After
-- |       this, client can send a "data packet" to the TNS Listener with a
-- |       following data:
-- |         - Service name to register
-- |         - Instances to register under the specified service name
-- |         - Maximum number of client connections allowed
-- |         - Current number of client connections established
-- |         - Handler's name
-- |         - IP address and port to connect to the database
-- |         - etc
-- |       If the packet is well formed, the server will answer with another
-- |       TNS "data packet" with the instances registered. After this step, the
-- |       instances and service names are registered in the remote TNS Listener
-- |       and any connection attempt to the TNS Listener by using the specified
-- |       SERVICE_NAME or SID (database's instance) will be routed to the
-- |       remote database server.
-- |     Disclosure date: 2012-4-18
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1675
-- |       https://www.oracle.com/technetwork/topics/security/alert-cve-2012-1675-1608180.html
-- |_      http://seclists.org/fulldisclosure/2012/Apr/204

local stdnse    = require "stdnse"
local comm      = require "comm"
local shortport = require "shortport"
local vulns     = require "vulns"
local bin       = require "bin"

portrule = shortport.port_or_service({1521,1522,1523}, "oracle-tns")

local function create_connect_pkt(msg)
  return bin.pack(">SSCCSSSSSSSSSSSICCA",
    msg:len() + 34,     -- Packet Length
    0,                  -- Packet Checksum
    1,                  -- Packet Type (CONNECT)
    0,                  -- Reserved Byte
    0,                  -- Header Checksum
    308,                -- Version
    300,                -- Version (Compatibility)
    0,                  -- Service Options
    2048,               -- Session Data Unit Size
    32767,              -- Maximum Transmission Data Unit Size
    20376,              -- NT Protocol Characteristics
    0,                  -- Line Turnaround Value
    1,                  -- Value of 1 in Hardware
    msg:len(),          -- Length of connect data
    34,                 -- Offset to connect data
    0,                  -- Maximum Receivable Connect Data
    1,                  -- Connect Flags 0
    1,                  -- Connect Flags 1
    msg
    )
end

local function oracle_version(vsnnum)
  local hex = stdnse.tohex(tonumber(vsnnum))
  -- return major version number
  return tonumber(string.unpack("c1", hex), 16)
end

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)
  local report = vulns.Report:new(SCRIPT_NAME, host)
  local vuln   = {
    title = [[
The vulnerability allows to intercept traffic between the client and the
Oracle database.]],
    state = vulns.STATE.NOT_VULN,
    IDS = { CVE = 'CVE-2012-1675' },
    description = [[
When client sends a TNS packet of type CONNECT to the TNS Listener with
the following string:
  - Oracle 9i to 11g: (CONNECT_DATA=(COMMAND=SERVICE_REGISTER_NSGR))
  - Oracle 8i: (CONNECT_DATA=(COMMAND=SERVICE_REGISTER))
The vulnerable server answers with a TNS packet of type ACCEPT. After
this, client can send a "data packet" to the TNS Listener with a
following data:
  - Service name to register
  - Instances to register under the specified service name
  - Maximum number of client connections allowed
  - Current number of client connections established
  - Handler's name
  - IP address and port to connect to the database
  - etc
If the packet is well formed, the server will answer with another
TNS "data packet" with the instances registered. After this step, the
instances and service names are registered in the remote TNS Listener
and any connection attempt to the TNS Listener by using the specified
SERVICE_NAME or SID (database's instance) will be routed to the
remote database server.]],
    references = {
      'https://www.oracle.com/technetwork/topics/security/alert-cve-2012-1675-1608180.html',
      'http://seclists.org/fulldisclosure/2012/Apr/204',
    },
    dates = {disclosure = {year = '2012', month = '4', day = '18'}}
  }

  local status, response

  -- Retrieve Version
  status, response = comm.exchange(host, port,
    create_connect_pkt("(CONNECT_DATA=(COMMAND=version))"))
  if not status then
    return fail("Could not get a response: " .. response)
  end

  local vsnnum, version
  vsnnum  = response and response:match("%(VSNNUM=(%d+)%)")
  version = oracle_version(vsnnum)

  -- Send Poison probe
  local poison
  if version == 8 then
    poison = "(CONNECT_DATA=(COMMAND=SERVICE_REGISTER))"
  elseif version >= 9 and version <= 11 then
    poison = "(CONNECT_DATA=(COMMAND=SERVICE_REGISTER_NSGR))"
  else
    return fail("Version " .. version .. " is not affected")
  end

  status, response = comm.exchange(host, port, create_connect_pkt(poison))
  if not status then
    return fail("Could not get a response: " .. response)
  end

  -- Check response message type
  if response and string.byte(response, 5) == 2 then -- TNS Packet Type: ACCEPT
    vuln.state = vulns.STATE.VULN
  end

  return report:make_output(vuln)
end
