local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local match = require "match"
local table = require "table"

description = [[
Queries OpenFlow controllers for information. Newer versions of the OpenFlow
protocol (1.3 and greater) will return a list of all protocol versions supported
by the controller. Versions prior to 1.3 only return their own version number.

For additional information:
* https://www.opennetworking.org/images/stories/downloads/sdn-resources/onf-specifications/openflow/openflow-switch-v1.5.0.noipr.pdf
]]

---
-- @usage nmap -p 6633,6653 --script openflow-info <target>
-- @output
-- PORT     STATE SERVICE REASON
-- 6653/tcp open  openflow
-- | openflow-info:
-- |   OpenFlow Running Version: 1.5.X
-- |   OpenFlow Versions Supported:
-- |     1.0
-- |     1.1
-- |     1.2
-- |     1.3.X
-- |     1.4.X
-- |_    1.5.X

author = "Jay Smith"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

-- OpenFlow versions released:
-- 0x01 = 1.0
-- 0x02 = 1.1
-- 0x03 = 1.2
-- 0x04 = 1.3.X
-- 0x05 = 1.4.X
-- 0x06 = 1.5.X
-- The bits in the version bitmap are indexed by the ofp version number of the
-- protocol. If the bit identified by the number of left bitshift equal
-- to a ofp version number is set, this OpenFlow version is supported.
local openflow_versions = {
  [0x02] = "1.0",
  [0x04] = "1.1",
  [0x08] = "1.2",
  [0x10] = "1.3.X",
  [0x20] = "1.4.X",
  [0x40] = "1.5.X"
}

local OPENFLOW_HEADER_SIZE = 8
local OFPT_HELLO = 0
local OFPHET_VERSIONBITMAP = 1
local HELLO_MESSAGE = "\x01\x00\x00\x08\xff\xff\xff\xff"

portrule = shortport.version_port_or_service({6633, 6653}, "openflow", "tcp")

receive_message = function(host, port)

  -- Handshake Info:
  -- Versions 1.3.1 and later say hello with a bitmap of versions supported
  -- Earlier versions either say hello without the bitmap.
  -- Some implementations are shy and don't make the first move, so we'll say
  -- hello first. We'll pretend to be a switch using version 1.0 of the protocol
  local socket, message = comm.tryssl(host, port, HELLO_MESSAGE, { recv_first = false, bytes = OPENFLOW_HEADER_SIZE } )

  -- third and fourth bytes contain the length of the message, including the header
  local message_length = string.unpack(">I2", message, 3)
  if message_length > OPENFLOW_HEADER_SIZE then
    local status, body = socket:receive_buf(match.numbytes(message_length - OPENFLOW_HEADER_SIZE), true)
    if not status then
      return false, body
    end
    message = message .. body
  end
  socket:close()
  return true, message
end

retrieve_version_bitmap = function(message)
  -- HELLO message structure:
  -- /* OFPT_HELLO. This message includes zero or more hello elements having
  -- * variable size. Unknown elements types must be ignored/skipped, to allow
  -- * for future extensions. */
  -- struct ofp_hello {
  -- struct ofp_header header;
  -- /* Hello element list */
  -- struct ofp_hello_elem_header elements[0]; /* List of elements - 0 or more */
  -- };
  -- The HELLO message may contain zero or more hello elements. One of these
  -- hello elements may be of the type OFPHET_VERSIONBITMAP. We must search
  -- through elements until we find OFPHET_VERSIONBITMAP.
  -- Note: As of version 1.5, OFPHET_VERSIONBITMAP is the only standard hello element type.
  -- However, we can not assume that this will be the case for long.
  local index = OPENFLOW_HEADER_SIZE + 1
  while index < #message do
    local element_type = string.unpack(">I2", message, index)
    local element_length = string.unpack(">I2", message, index + 2)

    if element_type == OFPHET_VERSIONBITMAP then
      stdnse.debug(1, "Version Index: %i", index + 4)
      return string.unpack(">I4", message, index + 4)
    end

    index = index + element_length
  end
  return nil
end

action = function(host, port)
  local supported_versions = {}
  local results = {}

  local status, message = receive_message(host, port)
  if not status then
    return false, message
  end
  local current_version = string.unpack(">I1", message, 1)
  results["OpenFlow Running Version"] = openflow_versions[2^current_version]

  local message_type = string.unpack(">I1", message, 2)
  if message_type == OFPT_HELLO then
    local version_bitmap = retrieve_version_bitmap(message)
    if version_bitmap ~= nil then
      for mask, version in pairs(openflow_versions) do
        if mask & version_bitmap then
          table.insert(supported_versions, version)
        end
      end
      table.sort(supported_versions)
      results["OpenFlow Versions Supported"] = supported_versions
    end
  end

  return results
end
