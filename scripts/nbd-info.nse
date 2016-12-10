local nbd = require "nbd"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
]]

---
-- @usage nmap -p 10809 --script nbd-info <target>
--

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

portrule = shortport.version_port_or_service(10001, "nbd", "tcp")

fixed_newstyle_connection = function(comm, args)
end

newstyle_connection = function(comm, args)
  if type(args.export_name) == "string" then
    comm:attach(args.export_name)
    return
  end

  for i, name in ipairs(args.export_name) do
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

  local arg = stdnse.get_script_args(SCRIPT_NAME .. ".export-name")
  if not arg then
    -- An empty string for an export name indicates to the server that
    -- we wish to attach to the default export.
    arg = ""
  end
  args.export_name = arg

  return args
end

action = function(host, port)
  local args = parse_args()

  local comm = nbd.Comm:new(host, port)

  local status = comm:connect(args)
  if not status then
     return false
  end

  -- If the service supports an unrecognized negotiation, or the
  -- oldstyle negotiation, there's no more information to be had.
  if comm.protocol.negotiation == "unrecognized" or comm.protocol.negotiation == "oldstyle" then
    -- Nothing to do.
    conn:close()

  -- If the service supports the (non-fixed) newstyle negotiation,
  -- which should be very rare, we can only send a single option. That
  -- option is the name of the export to which we'd like to attach.
  elseif comm.protocol.negotiation == "newstyle" then
    newstyle_connection(comm, args)

  -- If the service supports the fixed newstyle negotiation, then we
  -- can perform option haggling to wring additional information from
  -- it.
  elseif comm.protocol.negotiation == "fixed newstyle" then
    --fixed_newstyle_connection(comm)
    newstyle_connection(comm, args)

  -- Otherwise, we've got a mismatch between the library and this script.
  else
    assert(false, "NBD library supports more negotiation styles than this script.")
  end

  -- Master output table.
  local output = stdnse.output_table()

  -- Format protocol information.
  local tbl = {}
  table.insert(tbl, ("Negotiation: %s"):format(comm.protocol.negotiation))
  table.insert(tbl, ("SSL/TLS Wrapped: %s"):format(comm.protocol.ssl_tls))
  output["Protocol"] = tbl

  -- Format exported block device information.
  local tbl = {}
  local exports = comm.exports or {}
  for name, info in pairs(exports) do
    local exp = {}
    table.insert(exp, ("Size: %d bytes"):format(info.size))

    local keys = {}
    for k, _ in pairs(info.flags) do
      if k ~= "HAS_FLAGS" then
	table.insert(keys, k)
      end
    end
    exp["Flags"] = keys

    tbl[name] = exp
  end

  if comm.exports then
    output["Exported Block Devices"] = tbl
  end

  return output, stdnse.format_output(true, output)
end
