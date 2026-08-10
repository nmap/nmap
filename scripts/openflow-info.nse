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

author = {"Jay Smith", "Mak Kolybabi <mak@kolybabi.com>"}
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

portrule = shortport.version_port_or_service({6633, 6653}, "openflow", "tcp")

receive_message = function(host, port)
  local hello = string.pack(
    ">I1 I1 I2 I4",
    0x04,
    OFPT_HELLO,
    OPENFLOW_HEADER_SIZE,
    0xFFFFFFFF
  )

  -- Handshake Info:
  -- Versions 1.3.1 and later say hello with a bitmap of versions supported
  -- Earlier versions either say hello without the bitmap.
  -- Some implementations are shy and don't make the first move, so we'll say
  -- hello first. We'll pretend to be a switch using version 1.0 of the protocol
  local socket, response = comm.tryssl(host, port, hello, {bytes = OPENFLOW_HEADER_SIZE})
  if not socket then
    stdnse.debug1("Failed to connect to service: %s", response)
    return
  end

  if #response < OPENFLOW_HEADER_SIZE then
    socket:close()
    stdnse.debug1("Initial packet received was %d bytes, need >= %d bytes.", #response, OPENFLOW_HEADER_SIZE)
    return
  end

  -- The first byte is the protocol version number being used. So long as that
  -- number is less than the currently-published versions, then we can be
  -- confident in our parsing of the packet.
  local pos = 1
  local message = {}
  local message_version, pos = string.unpack(">I1", response, 1)
  if message_version > 0x06 then
    socket:close()
    stdnse.debug1("Initial packet received had unrecognized version %d.", message_version)
    return
  end
  message.version = message_version

  -- The second byte is the packet type.
  local message_type, pos = string.unpack(">I1", response, pos)
  message.type = message_type

  -- The fourth and fifth bytes are the length of the entire message, including
  -- the header and length itself.
  local message_length, pos = string.unpack(">I2", response, pos)
  if message_length < OPENFLOW_HEADER_SIZE then
    socket:close()
    stdnse.debug1("Response declares length as %d bytes, need >= %d bytes.", message_length, OPENFLOW_HEADER_SIZE)
    return
  end
  message.length = message_length

  -- The remainder of the header contains the ID.
  local message_id, pos = string.unpack(">I4", response, pos)
  message.id = message_id

  -- All remaining data from the response, up until the message length, is the body.
  assert(pos == OPENFLOW_HEADER_SIZE + 1)
  message.body = response:sub(pos, message_length)

  -- If we have the whole packet, pass it up the call stack.
  if message_length <= #response then
    socket:close()
    return message
  end

  -- If message length is larger than the data we already have, receive the
  -- remainder of the packet.
  local missing_bytes = message_length - #response
  local status, body = socket:receive_buf(match.numbytes(missing_bytes), true)
  if not status then
    socket:close()
    stdnse.debug1("Failed to receive missing %d bytes of response: %s", missing_bytes, body)
    return
  end
  message.body = (response .. body):sub(pos, message_length)

  return message
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
  local pos = 1
  local body = message.body
  while pos + 4 < #body - 1 do
    local element_length, element_type
    element_type, element_length, pos = string.unpack(">I2 I2", body, pos)
    if pos + element_length < #body then
      stdnse.debug1("Ran out of data parsing element type %d at position %d.", element_type, pos)
      return
    end

    if element_type == OFPHET_VERSIONBITMAP then
      return string.unpack(">I4", body, pos)
    end

    pos = pos + element_length - 4
  end

  return
end

action = function(host, port)
  local output = stdnse.output_table()

  local message = receive_message(host, port)
  if not message then
    return
  end

  output["OpenFlow Version Running"] = openflow_versions[2 ^ message.version]
  if message.type ~= OFPT_HELLO then
    return output
  end

  local version_bitmap = retrieve_version_bitmap(message)
  if not version_bitmap then
    return output
  end

  local supported_versions = {}
  for mask, version in pairs(openflow_versions) do
    if mask & version_bitmap then
      table.insert(supported_versions, version)
    end
  end
  table.sort(supported_versions)
  output["OpenFlow Versions Supported"] = supported_versions

  return output
end
