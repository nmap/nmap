description = [[
Decodes the VSNNUM version number from an Oracle TNS listener.
]]

local shortport = require "shortport"
local nmap = require "nmap"
local comm = require "comm"
local stdnse = require "stdnse"
local string = require "string"
local U = require "lpeg-utility"

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version", "safe"}

portrule = function (host, port)
  return (
    -- -sV has an actual version for this, no need to send more probes and decode.
    not (port.version and port.version.version and port.version.version ~= "")
    -- Otherwise, normal checking for port numbers etc.
    and shortport.version_port_or_service({1521,1522,1523}, "oracle-tns")(host, port)
    )
end

-- Lifted from nmap-service-probes
-- TODO: Figure out if we can send a better probe than this. We might need to
--       send ADDRESS, CID, etc.
local oracle_tns_probe = "\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x004\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))"

local ERR_CODES = {
  ["1189"] = "unauthorized",
  ["1194"] = "insecure transport",
  ["12154"] = "unknown identifier",
  ["12504"] = "requires service name",
  ["12505"] = "unknown sid",
  ["12514"] = "unknown service name",
}

local function decode_vsnnum (vsnnum)
  vsnnum = tonumber(vsnnum)
  return string.format("%d.%d.%d.%d.%d",
    vsnnum >> 24,
    vsnnum >> 20 & 0xF,
    vsnnum >> 12 & 0xFF,
    vsnnum >>  8 & 0xF,
    vsnnum       & 0xFF
    )
end

do
  local test_data = {
    ["135290880"] = "8.1.6.0.0",
    ["153092352"] = "9.2.0.1.0",
    ["169869568"] = "10.2.0.1.0",
    ["185599488"] = "11.1.0.6.0",
    ["202375680"] = "12.1.0.2.0",
    ["301989888"] = "18.0.0.0.0",
    ["318767104"] = "19.0.0.0.0",
    ["352321536"] = "21.0.0.0.0",
  }
  for n, v in pairs(test_data) do
    local ver = decode_vsnnum(n)
    assert(ver == v, ("%s == %s"):format(ver, v))
  end
end

action = function (host, port)
  local response
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    -- Probes sent, replies received, but no match.
    response = U.get_response(port.version.service_fp, "oracle-tns")
  end

  if not response then
    -- Have to send the probe ourselves
    local status
    status, response = comm.exchange(host, port, oracle_tns_probe)
    if not status then
      stdnse.debug1("Couldn't get a response: %s", response)
      return nil
    end
  end

  local vsnnum = response and response:match("%(VSNNUM=(%d+)%)", 12)
  port.version = port.version or {}
  if vsnnum then
    local version = decode_vsnnum(vsnnum)
    port.version.product = "Oracle TNS listener"
    port.version.version = version
    local cpes = port.version.cpe or {}
    cpes[#cpes+1] = "cpe:/a:oracle:database_server:" .. version
    port.version.cpe = cpes
  end

  local errno = response and response:match("%(ERR=(%d+)%)", 12)
  if errno then
    port.version.extrainfo = ERR_CODES[errno] or ("error: "..errno)
  end

  if vsnnum or errno then
    nmap.set_port_version(host, port, "hardmatched")
  end
end
