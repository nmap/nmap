local nbd = require "nbd"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local tableaux = require "tableaux"

description = [[
Displays protocol and block device information from NBD servers.

The Network Block Device protocol is used to publish block devices
over TCP. This script connects to an NBD server and attempts to pull
down a list of exported block devices and their details

For additional information:
* https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
]]

---
-- @usage nmap -p 10809 --script nbd-info <target>
--
-- @output
-- PORT      STATE SERVICE REASON
-- 10809/tcp open  nbd     syn-ack
-- | nbd-info:
-- |   Protocol:
-- |     Negotiation: fixed newstyle
-- |     SSL/TLS Wrapped: false
-- |   Exported Block Devices:
-- |     foo:
-- |       Size: 1048576 bytes
-- |       Transmission Flags:
-- |         SEND_FLUSH
-- |         READ_ONLY
-- |         SEND_FUA
-- |     bar:
-- |       Size: 1048576 bytes
-- |       Transmission Flags:
-- |         READ_ONLY
-- |_        ROTATIONAL
--
-- @args nbd-info.export_names Either a single name, or a table of
-- names to about which to request information from the server.

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.version_port_or_service(10809, "nbd", "tcp")

local enumerate_options = function(comm)
  -- Run the LIST command and store the responses.
  local req = comm:build_opt_req("LIST")
  if not req then
    return
  end

  local status, err = comm:send(req)
  if not status then
    stdnse.debug1("Failed to send option request: %s", err)
    return nil
  end

  while true do
    local rep = comm:receive_opt_rep()
    if not rep or rep.rtype_name ~= "SERVER" then
      break
    end

    comm.exports[rep.export_name] = {}
  end
end

local newstyle_connection = function(comm, args)
  local names = {}

  for _, name in ipairs(args.export_name) do
    table.insert(names, name)
  end

  for name, _ in pairs(comm.exports) do
    table.insert(names, name)
  end

  for i, name in ipairs(names) do
    if i ~= 1 then
      local status = comm:reconnect()
      if not status then
        return
      end
    end

    comm:attach(name)
  end
end

local function parse_args()
  local args = {}

  local arg = stdnse.get_script_args(SCRIPT_NAME .. ".export-names")
  if not arg then
    -- An empty string for an export name indicates to the server that
    -- we wish to attach to the default export.
    arg = {}
  elseif type(arg) ~= 'table' then
    arg = {arg}
  end
  args.export_name = arg

  return args
end

action = function(host, port)
  local args = parse_args()

  local comm = nbd.Comm:new(host, port)

  local status = comm:connect(args)
  if not status then
     return nil
  end

  -- If the service supports an unrecognized negotiation, or the
  -- oldstyle negotiation, there's no more information to be had.
  if comm.protocol.negotiation == "unrecognized" or comm.protocol.negotiation == "oldstyle" then
    -- Nothing to do.
    comm:close()

  -- If the service supports the (non-fixed) newstyle negotiation,
  -- which should be very rare, we can only send a single option. That
  -- option is the name of the export to which we'd like to attach.
  elseif comm.protocol.negotiation == "newstyle" then
    newstyle_connection(comm, args)

  -- If the service supports the fixed newstyle negotiation, then we
  -- can perform option haggling to wring additional information from
  -- it.
  elseif comm.protocol.negotiation == "fixed newstyle" then
    enumerate_options(comm)
    newstyle_connection(comm, args)

  -- Otherwise, we've got a mismatch between the library and this script.
  else
    assert(false, "NBD library supports more negotiation styles than this script.")
  end

  -- Master output table.
  local output = stdnse.output_table()

  -- Format protocol information.
  local protocol = stdnse.output_table()
  if comm.protocol.negotiation == "oldstyle" and comm.exports["(default)"] then
    if comm.exports["(default)"].hflags & nbd.NBD.handshake_flags.FIXED_NEWSTYLE then
      protocol["Fixed Newstyle Negotiation"] = "Supported by service, but not on this port."
    end
  end
  protocol["Negotiation"] = comm.protocol.negotiation
  protocol["SSL/TLS Wrapped"] = comm.protocol.ssl_tls

  output["Protocol"] = protocol

  -- Format exported block device information.
  local exports = stdnse.output_table()
  local no_shares = true
  local names = tableaux.keys(comm.exports)
  -- keep exports in stable order
  table.sort(names)
  for _, name in ipairs(names) do
    local info = comm.exports[name]
    local exp = {}
    if type(info.size) == "number" then
      exp["Size"] = info.size .. " bytes"
    end

    if type(info.tflags) == "table" then
      local keys = {}
      for k, _ in pairs(info.tflags) do
        if k ~= "HAS_FLAGS" then
          table.insert(keys, k)
        end
      end
      -- sort by bitfield flag value
      table.sort(keys, function(a, b)
          return nbd.NBD.transmission_flags[a] < nbd.NBD.transmission_flags[b]
        end)
      exp["Transmission Flags"] = keys
    end

    no_shares = false
    exports[name] = exp
  end

  if not no_shares then
    output["Exported Block Devices"] = exports
  end

  return output
end
