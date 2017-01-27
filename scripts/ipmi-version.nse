local ipmi = require "ipmi"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
  Performs IPMI Information Discovery through Channel Auth probes.
]]

---
-- @usage
-- nmap -sU --script ipmi-version -p 623 <host>
--
-- @output
-- PORT     STATE SERVICE  REASON
-- 623/udp  open|filtered  unknown
-- | ipmi-version:
-- |   Version: IPMI-2.0
-- |   UserAuth: password, md5, md2
-- |   PassAuth: null_user
-- |_  Level: 1.2,2.0
--
-- @xmloutput
-- <table>
--   <table key="Version">
--     <elem>IPMI-2.0</elem>
--   </table>
--
--   <table key="UserAuth">
--     <elem>password</elem>
--     <elem>md5</elem>
--     <elem>md2</elem>
--   </table>
--
--   <table key="PassAuth">
--     <elem>kg_default</elem>
--     <elem>null_user</elem>
--   </table>
--
--   <table key="Level">
--     <elem>1.2</elem>
--     <elem>2.0</elem>
--   </table>
-- </table>
--

author = "Claudiu Perta <claudiu.perta@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service(623, "asf-rmcp", "udp", {"open", "open|filtered"})

local comma_separated = {
  __tostring = function(t) return table.concat(t, ", ") end
}

action = function(host, port)

  local request = ipmi.channel_auth_request()
  local socket = nmap.new_socket()

  socket:set_timeout(
    ((host.times and host.times.timeout) or 8) * 1000)
  socket:connect(host, port, "udp")

 -- Send 3 probes
  local tries = 3
  repeat
    socket:send(request)
    tries = tries - 1
  until tries == 0

  local status, reply = socket:receive()
  socket:close()

  if not status then
    stdnse.debug1(string.format("No response (%s)", reply))
    return nil
  end

  nmap.set_port_state(host, port, "open")

  -- Invalid reply
  local info = ipmi.parse_channel_auth_reply(reply)
  if info["ipmi_command"] ~= 56 then
    return "IPMI - Invalid response"
  end

  -- Valid reply
  local Version = {}
  if info["ipmi_compat_20"] then
    table.insert(Version, "IPMI-2.0")
  else
    table.insert(Version, "IPMI-1.5")
  end

  local UserAuth = {}
  setmetatable(UserAuth, comma_separated)

  if info["ipmi_compat_oem_auth"] then
    table.insert(UserAuth, "oem_auth")
  end

  if info["ipmi_compat_password"]  then
    table.insert(UserAuth, "password")
  end

  if info["ipmi_compat_md5"] then
    table.insert(UserAuth, "md5")
  end

  if info["ipmi_compat_md2"] then
    table.insert(UserAuth, "md2")
  end

  if info["ipmi_compat_none"] then
    table.insert(UserAuth, "null")
  end

  local PassAuth = {}
  setmetatable(PassAuth, comma_separated)

  if info["ipmi_compat_20"] and info["ipmi_user_kg"] then
    table.insert(PassAuth, "kg_default")
  end

  if not info["ipmi_user_disable_message_auth"] then
    table.insert(PassAuth, "auth_msg")
  end

  if not info["ipmi_user_disable_user_auth"]  then
    table.insert(PassAuth, "auth_user")
  end

  if info["ipmi_user_non_null"] then
    table.insert(PassAuth, "non_null_user")
  end

  if info["ipmi_user_null"] then
    table.insert(PassAuth, "null_user")
  end

  if info["ipmi_user_anonymous"] then
    table.insert(PassAuth, "anonymous_user")
  end

  local ConnInfo = {}
  setmetatable(ConnInfo, comma_separated)

  if info["ipmi_conn_15"] then
    table.insert(ConnInfo, "1.5")
  end

  if info["ipmi_conn_20"] then
    table.insert(ConnInfo, "2.0")
  end

  local output = stdnse.output_table()
  output["Version"] = Version
  output["UserAuth"] = UserAuth
  output["PassAuth"] = PassAuth
  output["Level"] = ConnInfo
  if info["ipmi_oem_id"] ~= 0 then
    output["OEMID"] =  info["ipmi_oem_id"]
  end

  return output
end
