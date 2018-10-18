local nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Tests a list of known ICAP service names and prints information about
any it detects. The Internet Content Adaptation Protocol (ICAP) is
used to extend transparent proxy servers and is generally used for
content filtering and antivirus scanning.
]]

---
-- @usage
-- nmap -p 1344 <ip> --script icap-info
--
-- @output
-- PORT     STATE SERVICE
-- 1344/tcp open  unknown
-- | icap-info:
-- |   /avscan
-- |     Service: C-ICAP/0.1.6 server - Clamav/Antivirus service
-- |     ISTag: CI0001-000-0973-6314940
-- |   /echo
-- |     Service: C-ICAP/0.1.6 server - Echo demo service
-- |     ISTag: CI0001-XXXXXXXXX
-- |   /srv_clamav
-- |     Service: C-ICAP/0.1.6 server - Clamav/Antivirus service
-- |     ISTag: CI0001-000-0973-6314940
-- |   /url_check
-- |     Service: C-ICAP/0.1.6 server - Url_Check demo service
-- |_    ISTag: CI0001-XXXXXXXXX
--
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}


portrule = shortport.port_or_service(1344, "icap")

local function fail(err) return stdnse.format_output(false, err) end

local function parseResponse(resp)
  if ( not(resp) ) then
    return
  end

  local resp_p = { header = {}, rawheader = {} }
  local resp_tbl = stringaux.strsplit("\r?\n", resp)

  if ( not(resp_tbl) or #resp_tbl == 0 ) then
    stdnse.debug2("Received an invalid response from server")
    return
  end

  resp_p.status = tonumber(resp_tbl[1]:match("^ICAP/1%.0 (%d*) .*$"))
  resp_p['status-line'] = resp_tbl[1]

  for i=2, #resp_tbl do
    local key, val = resp_tbl[i]:match("^([^:]*):%s*(.*)$")
    if ( not(key) or not(val) ) then
      stdnse.debug2("Failed to parse header: %s", resp_tbl[i])
    else
      resp_p.header[key:lower()] = val
    end
    table.insert(resp_p.rawheader, resp_tbl[i])
  end
  return resp_p
end

action = function(host, port)

  local services = {"/avscan", "/echo", "/srv_clamav", "/url_check", "/nmap" }
  local headers = {"Service", "ISTag"}
  local probe = {
    "OPTIONS icap://%s%s ICAP/1.0",
    "Host: %s",
    "User-Agent: nmap icap-client/0.01",
    "Encapsulated: null-body=0"
  }
  local hostname = stdnse.get_hostname(host)
  local result = {}

  for _, service in ipairs(services) do
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    if ( not(socket:connect(host, port)) ) then
      return fail("Failed to connect to server")
    end

    local request = (table.concat(probe, "\r\n") .. "\r\n\r\n"):format(hostname, service, hostname)

    if ( not(socket:send(request)) ) then
      socket:close()
      return fail("Failed to send request to server")
    end

    local status, resp = socket:receive_buf(match.pattern_limit("\r\n\r\n", 2048), false)
    if ( not(status) ) then
      return fail("Failed to receive response from server")
    end

    local resp_p = parseResponse(resp)
    if ( resp_p and resp_p.status == 200 ) then
      local result_part = { name = service }
      for _, h in ipairs(headers) do
        if ( resp_p.header[h:lower()] ) then
          table.insert(result_part, ("%s: %s"):format(h, resp_p.header[h:lower()]))
        end
      end
      table.insert(result, result_part)
    end
  end
  return stdnse.format_output(true, result)
end
