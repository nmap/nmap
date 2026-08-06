local string = require "string"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local table = require "table"

description = [[
Gathers information (a list of server properties) from an Eclipse Equinoxe OSGi
(Open Service Gateway initiative) console.

References:
    * https://www.eclipse.org/equinox/documents/quickstart-framework.php
]]

---
-- @usage
-- nmap -p <port> <ip> --script osgi-info
--
-- @output
-- PORT   STATE SERVICE REASON
-- 5555/tcp open  telnet  Eclipse Equinoxe OSGi Shell (direct mode)
-- | osgi-info:
-- |   username: root
-- |   OS Version: Linux 4.4.0-38-generic (amd64 little endian)
-- |   Java Runtime: 1.8.0_101-b13 (Java(TM) SE Runtime Environment)
-- |_  Java VM: 25.101-b13 (Java HotSpot(TM) 64-Bit Server VM)
--
-- @xmloutput
-- <elem key="username">root</elem>
-- <elem key="OS Version">Linux 4.4.0-38-generic (amd64 little endian)</elem>
-- <elem key="Java Runtime">1.8.0_101-b13 (Java(TM) SE Runtime Environment)</elem>
-- <elem key="Java VM">25.101-b13 (Java HotSpot(TM) 64-Bit Server VM)</elem>

author = "Quentin Kaiser"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe", "version"}


portrule = shortport.service('telnet')

local telnet_eol = "\r\n"

action = function(host, port)

  local result = stdnse.output_table()

  -- osgi prompt regular expression
  local prompt_regexp = "(osgi>)"
  -- properties parsing regular expression
  local props_regexp = "([^=]+)=([^\r|^\n]*)"

  -- command to get system properties
  local props_cmd = "getprop"
  local disconnect_cmd = "disconnect"
  local confirm_cmd = "y"

  -- socket handler
  local socket = nmap.new_socket()
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)

  -- connect
  try(socket:connect(host, port))
  socket:set_timeout(7500)
  data = try(socket:receive())

  -- if we receive IAC negotiations matching the signature, we negotiate
  if data == string.pack("<B<B<B<B<B<B<B<B<B<B<B<B",
        0xFF, 0xFB, 0x01, 0xFF, 0xFB, 0x03, 0xFF, 0xFD, 0x1F, 0xFF, 0xFD, 0x18) then
    local nego1 = string.pack("<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B",
        0xFF, 0xFD, 0x01, 0xFF, 0xFD, 0x03, 0xFF, 0xFB, 0x1F, 0xFF, 0xFA, 0x1F,
        0x00, 0x3B, 0x00, 0x1D, 0xFF, 0xF0, 0xFF, 0xFB, 0x18)
    local nego2 = string.pack("<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B<B",
        0xFF, 0xFA, 0x18, 0x00, 0x78, 0x74, 0x65, 0x72, 0x6D, 0x2D, 0x32, 0x35,
        0x36, 0x63, 0x6F, 0x6C, 0x6F, 0x72, 0xFF, 0xF0)
    try(socket:send(nego1))
    try(socket:receive())
    try(socket:send(nego2))
    data = try(socket:receive())
  end

  -- we check it's actually an OSGi prompt
  if not string.match(data, prompt_regexp) then
    return stdnse.format_output(false, "Not an OSGi shell.")
  end

  -- request properties
  try(socket:send(props_cmd .. telnet_eol))
  data = try(socket:receive_buf(prompt_regexp, true))

  -- we create an indexed array with key/values from properties dump
  props = {}
  for k, v in string.gmatch(data, props_regexp) do
    props[k:gsub("%s+", "")] = v
  end

  -- we fill our results table
  result["username"] = props["user.name"]
  result["OS Version"] = string.format(
    "%s %s (%s %s endian)", props["os.name"], props["os.version"],
    props["os.arch"], props["sun.cpu.endian"]
  )
  result["Java Runtime"] = string.format(
    "%s (%s)", props["java.runtime.version"], props["java.runtime.name"]
  )
  result["Java VM"] = string.format(
    "%s (%s)", props["java.vm.version"], props["java.vm.name"]
  )

  -- graceful disconnection
  try(socket:send(disconnect_cmd .. telnet_eol))
  try(socket:receive_buf("Disconnect from console?([^\r|^\n]*)", true))
  try(socket:send(confirm_cmd .. telnet_eol))
  try(socket:receive())
  socket:close()
  return result
end
