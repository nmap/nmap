local io = require "io"
local nmap = require "nmap"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Loads addresses from an Nmap XML output file for scanning.

Address type (IPv4 or IPv6) is determined according to whether -6 is specified to nmap.
]]

---
--@args targets-xml.iX Filename of an Nmap XML file to import
--@args targets-xml.state Only hosts with this status will have their addresses
--                        input. Default: "up"
--
--@usage
-- nmap --script targets-xml --script-args newtargets,iX=oldscan.xml
--
--@output
--Pre-scan script results:
--|_targets-xml: Added 16 ipv4 addresses
--
--@xmloutput
--16

-- TODO: more filtering options: port status, string search, etc.

author = "Daniel Miller"
categories = {"safe"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local filename = stdnse.get_script_args(SCRIPT_NAME .. ".iX")

prerule = function ()
  if not filename then
    stdnse.verbose1("Need to supply a file name with the %s.iX argument", SCRIPT_NAME);
    return false
  end
  return true
end

local startElement = {
  host = function (state)
    state.addresses = {}
    state.up = nil
  end,
  status = function (state)
    state.parser._call.attribute = function (name, attribute)
      if name == "state" then
        state.up = attribute == state.status
      end
    end
  end,
  address = function (state)
    state.parser._call.attribute = function (name, attribute)
      if name == "addrtype" then
        state.valid = attribute == state.addrtype
      elseif name == "addr" then
        state.address = attribute
      end
    end
  end,
}

local closeElement = {
  host = function (state)
    if state.up then
      state.added = state.added + #state.addresses
      if target.ALLOW_NEW_TARGETS then
        target.add(table.unpack(state.addresses))
      end
    end
    state.up = nil
  end,
  status = function (state)
    state.parser._call.attribute = nil
  end,
  address = function (state)
    if state.valid and state.address then
      table.insert(state.addresses, state.address)
    end
    state.parser._call.attribute = nil
    state.address = nil
    state.valid = false
  end,
}

action = function ()
  local status = stdnse.get_script_args(SCRIPT_NAME .. ".state") or "up"
  local input, err = io.open(filename, "r")
  if not input then
    stdnse.debug1("Couldn't open %s: %s", filename, err)
    return nil
  end

  local state = {
    status = status,
    addrtype = "ipv4",
    added = 0,
  }
  if nmap.address_family() == "inet6" then
    state.addrtype = "ipv6"
  end

  state.parser = slaxml.parser:new({
      startElement = function (name)
        return startElement[name] and startElement[name](state) or nil
      end,
      closeElement = function (name)
        return startElement[name] and closeElement[name](state) or nil
      end,
    })

  local buf = ""
  local function next_chunk()
    local read, starts, ends
    repeat
      read = input:read(8192)
      if not read then
        return buf, true
      end
      starts, ends = string.find(read, ">.-$")
      if not starts then
        buf = buf .. read
      end
    until starts
    local ret = buf .. string.sub(read, 1, starts)
    buf = string.sub(read, starts+1)
    return ret, false
  end
  local chunk
  local eof = false
  while not eof do
    chunk, eof = next_chunk()
    state.parser:parseSAX(chunk)
  end
  return state.added, ("Found %s %s addresses"):format(state.added, state.addrtype)
end
