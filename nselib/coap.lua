local bin = require "bin"
local bit = require "bit"
local comm = require "comm"
local json = require "json"
local lpeg = require "lpeg"
local match = require "match"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unittest = require "unittest"

_ENV = stdnse.module("coap", stdnse.seeall)

---
-- An implementation of CoAP
-- https://tools.ietf.org/html/rfc7252
--
-- This library does not currently implement the entire CoAP protocol,
-- only those behaviours which are necessary for existing scripts are
-- included. Extending to accomodate additional control packets should
-- not be difficult.
--
-- @author "Mak Kolybabi <mak@kolybabi.com>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

COAP = {}

COAP.build = nil
COAP.parse = nil

COAP.header = {}
COAP.header.build = nil
COAP.header.parse = nil

COAP.header.codes = {}
COAP.header.codes.build = nil
COAP.header.codes.parse = nil

COAP.header.options = {}
COAP.header.options.build = nil
COAP.header.options.parse = nil

COAP.header.options.delta_length = {}
COAP.header.options.delta_length.build = nil
COAP.header.options.delta_length.parse = nil

COAP.header.options.accept = {}
COAP.header.options.accept.build = nil
COAP.header.options.accept.parse = nil

COAP.header.options.block1 = {}
COAP.header.options.block1.build = nil
COAP.header.options.block1.parse = nil

COAP.header.options.block2 = {}
COAP.header.options.block2.build = nil
COAP.header.options.block2.parse = nil

COAP.header.options.content_format = {}
COAP.header.options.content_format.build = nil
COAP.header.options.content_format.parse = nil

COAP.header.options.etag = {}
COAP.header.options.etag.build = nil
COAP.header.options.etag.parse = nil

COAP.header.options.if_match = {}
COAP.header.options.if_match.build = nil
COAP.header.options.if_match.parse = nil

COAP.header.options.if_none_match = {}
COAP.header.options.if_none_match.build = nil
COAP.header.options.if_none_match.parse = nil

COAP.header.options.location_path = {}
COAP.header.options.location_path.build = nil
COAP.header.options.location_path.parse = nil

COAP.header.options.location_query = {}
COAP.header.options.location_query.build = nil
COAP.header.options.location_query.parse = nil

COAP.header.options.max_age = {}
COAP.header.options.max_age.build = nil
COAP.header.options.max_age.parse = nil

COAP.header.options.proxy_scheme = {}
COAP.header.options.proxy_scheme.build = nil
COAP.header.options.proxy_scheme.parse = nil

COAP.header.options.proxy_uri = {}
COAP.header.options.proxy_uri.build = nil
COAP.header.options.proxy_uri.parse = nil

COAP.header.options.size1 = {}
COAP.header.options.size1.build = nil
COAP.header.options.size1.parse = nil

COAP.header.options.uri_host = {}
COAP.header.options.uri_host.build = nil
COAP.header.options.uri_host.parse = nil

COAP.header.options.uri_path = {}
COAP.header.options.uri_path.build = nil
COAP.header.options.uri_path.parse = nil

COAP.header.options.uri_port = {}
COAP.header.options.uri_port.build = nil
COAP.header.options.uri_port.parse = nil

COAP.header.options.uri_query = {}
COAP.header.options.uri_query.build = nil
COAP.header.options.uri_query.parse = nil

COAP.header.options.value = {}

COAP.header.options.value.block = {}
COAP.header.options.value.block.build = nil
COAP.header.options.value.block.parse = nil

COAP.header.options.value.empty = {}
COAP.header.options.value.empty.build = nil
COAP.header.options.value.empty.parse = nil

COAP.header.options.value.opaque = {}
COAP.header.options.value.opaque.build = nil
COAP.header.options.value.opaque.parse = nil

COAP.header.options.value.uint = {}
COAP.header.options.value.uint.build = nil
COAP.header.options.value.uint.parse = nil

COAP.header.options.value.string = {}
COAP.header.options.value.string.build = nil
COAP.header.options.value.string.parse = nil

COAP.header.find_option = nil
COAP.header.find_options = nil

COAP.payload = {}
COAP.payload.parse = nil

COAP.payload.text_plain = {}
COAP.payload.text_plain.build = nil
COAP.payload.text_plain.parse = nil

COAP.payload.application_link_format = {}
COAP.payload.application_link_format.build = nil
COAP.payload.application_link_format.parse = nil

COAP.payload.application_xml = {}
COAP.payload.application_xml.build = nil
COAP.payload.application_xml.parse = nil

COAP.payload.application_octet_stream = {}
COAP.payload.application_octet_stream.build = nil
COAP.payload.application_octet_stream.parse = nil

COAP.payload.application_exi = {}
COAP.payload.application_exi.build = nil
COAP.payload.application_exi.parse = nil

COAP.payload.application_json = {}
COAP.payload.application_json.build = nil
COAP.payload.application_json.parse = nil

--- Builds a CoAP message.
--
-- @name COAP.build
--
-- @param options Table of options accepted by the desired message
--                build function.
-- @param payload String representing the message payload.
--
-- @return status true on success, false on failure.
-- @return response String representing a raw message on success, or
--         containing the error message on failure.
COAP.build = function(options, payload)
  -- Sanity check the payload.
  if not payload then
    payload = ""
  end
  assert(type(payload) == "string")

  assert(type(options) == "table")

  -- Build the header.
  local pkt = COAP.header.build(options)

  -- Build the payload.
  if payload ~= "" then
    pkt = pkt .. string.char(0xFF)
  end
  pkt = pkt .. COAP.payload.build(options, payload)

  return pkt
end

--- Parses a CoAP message.
--
-- @name COAP.parse
--
-- @param buf String from which to parse the message.
-- @param pos Position from which to start parsing.
--
-- @return pos String index on success, false on failure.
-- @return response Table representing a message on success, string
--         containing the error message on failure.
COAP.parse = function(buf, pos)
  assert(type(buf) == "string")

  if not pos or pos == 0 then
    pos = 1
  end
  assert(type(pos) == "number")
  assert(pos <= #buf)

  -- Parse the fixed header.
  local pos, hdr = COAP.header.parse(buf, pos)
  if not pos then
    return false, hdr
  end

  -- If we've reached the end of the packet, there's no payload and we
  -- can return immediately.
  if pos > #buf then
    return pos, hdr
  end

  -- If we're not at the end of the buffer, but the next byte after
  -- the header and options is not the payload marker, return
  -- immediately. We've got no idea what we're looking at.
  if buf:byte(pos) ~= 0xFF then
    stdnse.debug3("Parsed to byte %d of %d of packet, remaining bytes not understood.", pos - 1, #buf)
    return pos, hdr
  end
  pos = pos + 1

  -- If there's nothing past the payload marker, which is how some
  -- implementations format their packets.
  if pos > #buf then
    return pos, hdr
  end

  -- By this point, we have the payload and it's prefixed by the
  -- payload marker. We know this is a payload, so extract it.
  local payload = buf:sub(pos)
  pos = #buf + 1

  -- If the header contains a block options, then we can't parse the
  -- payload since it spans multiple packets, so we return it raw.
  local b1opt = COAP.header.find_option(hdr, "block1")
  local b2opt = COAP.header.find_option(hdr, "block2")
  if b1opt or b2opt then
    hdr.payload = payload
    return pos, hdr
  end

  -- In the absence of block options, we should be able to parse the
  -- payload.
  local status, payload = COAP.payload.parse(hdr, payload)
  if not status then
    return false, payload
  end
  hdr.payload = payload

  return pos, hdr
end

COAP.header.types = {
  ["confirmable"]     = 0,
  ["non-confirmable"] = 1,
  ["acknowledgement"] = 2,
  ["reset"]           = 3,
}

--- Builds a CoAP message header.
--
-- @name COAP.header.build
--
-- See section "3. Message Format" of the standard.
--
-- @param options Table of options accepted by the desired message
--                build function.
--
-- @return status true on success, false on failure.
-- @return response String representing a raw message header on
--         success, or containing the error message on failure.
COAP.header.build = function(options)
  assert(type(options) == "table")

  -- Fields which can be left as default.
  local ver = options.version
  if not ver then
    ver = 1
  end
  assert(type(ver) == "number")
  assert(ver >= 0)
  assert(ver <= 3)

  local token = options.token
  if not token then
    token = ""
  end
  assert(type(token) == "string")

  local tkl = #token
  assert(type(tkl) == "number")
  assert(tkl >= 0)
  assert(tkl <= 8)

  local id = options.id
  if not id then
    id = math.random(65535)
  end
  assert(type(id) == "number")
  assert(id >= 0)
  assert(id <= 65535)

  -- Fields which need to be explicitly set.
  local mtype = options.type
  assert(type(mtype) == "string")
  mtype = COAP.header.types[mtype]
  assert(mtype)

  local code = options.code
  assert(code)
  assert(type(code) == "string")
  code = COAP.header.codes.build(code)

  -- Build the fixed portion of the header.
  local pkt = ""

  ver = bit.lshift(ver, 6)
  mtype = bit.lshift(mtype, 4)

  pkt = pkt .. bin.pack("C", bit.bor(bit.bor(ver, mtype), tkl))
  pkt = pkt .. code
  pkt = pkt .. bin.pack(">S", id)
  pkt = pkt .. token

  -- Include optional portions of the header.
  if options["options"] then
    pkt = pkt .. COAP.header.options.build(options.options)
  end

  return pkt
end

--- Parses a CoAP message header.
--
-- @name COAP.header.parse
--
-- See section "3. Message Format" of the standard.
--
-- @param buf String from which to parse the header.
-- @param pos Position from which to start parsing.
--
-- @return pos String index on success, false on failure.
-- @return response Table representing a message header on success,
--         string containing the error message on failure.
COAP.header.parse = function(buf, pos)
  assert(type(buf) == "string")
  if #buf < 4 then
    return false, "Cannot parse a string of less than four bytes."
  end

  if not pos or pos == 0 then
    pos = 1
  end
  assert(type(pos) == "number")
  assert(pos <= #buf)

  if pos + 4 - 1 > #buf then
    return false, "Fixed header extends past end of buffer."
  end

  local pos, ver_type_tkl, code, id = bin.unpack("CA>S", buf, pos)
  if not pos then
    return false, "Failed to parse fixed header."
  end

  -- Parse the fixed header.
  local hdr = {}

  local ver = bit.rshift(ver_type_tkl, 6)
  hdr.version = ver

  local mtype = bit.rshift(ver_type_tkl, 4)
  mtype = bit.band(mtype, 0x3)

  hdr.type = ("(unrecognized: %d)"):format(mtype)
  for key, val in pairs(COAP.header.types) do
    if val == mtype then
      hdr.type = key
      break
    end
  end

  local tkl = bit.band(ver_type_tkl, 0xF)
  if tkl < 0 or tkl > 8 then
    return false, ("Token length was %d, but must be 0 through 8."):format(tkl)
  end
  hdr.token_length = tkl

  local status, code = COAP.header.codes.parse(code)
  if not status then
    return false, code
  end
  hdr.code = code

  hdr.id = id

  -- The token can be between 0 and 8 bytes.
  if hdr.token_length > 0 then
    hdr.token = buf:sub(pos, pos + hdr.token_length - 1)
    pos = pos + hdr.token_length
  end

  -- If we've reached the end of the packet, there's no options or
  -- payload and we can return immediately after we put in an empty
  -- options table.
  if pos > #buf then
    hdr.options = {}
    return pos, hdr
  end

  -- Parse the options.
  local pos, opt = COAP.header.options.parse(buf, pos)
  if not pos then
    return false, opt
  end
  hdr.options = opt

  return pos, hdr
end

COAP.header.codes.ids = {
  -- Requests
  ["get"]                        = {0,  1},
  ["post"]                       = {0,  2},
  ["put"]                        = {0,  3},
  ["delete"]                     = {0,  4},

  -- Responses
  ["created"]                    = {2,  1},
  ["deleted"]                    = {2,  2},
  ["valid"]                      = {2,  3},
  ["changed"]                    = {2,  4},
  ["content"]                    = {2,  5},
  ["bad_request"]                = {4,  0},
  ["unauthorized"]               = {4,  1},
  ["bad_option"]                 = {4,  2},
  ["forbidden"]                  = {4,  3},
  ["not_found"]                  = {4,  4},
  ["method_not_allowed"]         = {4,  5},
  ["not_acceptable"]             = {4,  6},
  ["precondition_failed"]        = {4, 12},
  ["request_entity_too_large"]   = {4, 13},
  ["unsupported_content-format"] = {4, 15},
  ["internal_server_error"]      = {5,  0},
  ["not_implemented"]            = {5,  1},
  ["bad_gateway"]                = {5,  2},
  ["service_unavailable"]        = {5,  3},
  ["gateway_timeout"]            = {5,  4},
  ["proxying_not_supported"]     = {5,  5},
}

--- Builds a CoAP message request or response code.
--
-- @name COAP.header.codes.build
--
-- @param name String naming the desired code.
--
-- @return status true on success, false on failure.
-- @return response String representing a code on success, or
--         containing the error message on failure.
COAP.header.codes.build = function(name)
  assert(type(name) == "string")

  local id = COAP.header.codes.ids[name]
  assert(id, ("Code '%s' not recognized."):format(name))

  local class = id[1]
  local detail = id[2]

  class = bit.lshift(class, 5)

  return bin.pack("C", bit.bor(class, detail))
end

--- Parses a CoAP request or response code.
--
-- @name COAP.header.codes.parse
--
-- @param buf String from which to parse the code.
-- @param pos Position from which to start parsing.
--
-- @return pos String index on success, false on failure.
-- @return response Table representing the code on success, string
--         containing the error message on failure.
COAP.header.codes.parse = function(buf, pos)
  assert(type(buf) == "string")
  if #buf < 1 then
    return false, "Cannot parse a string of less than one byte."
  end

  if not pos or pos == 0 then
    pos = 1
  end
  assert(type(pos) == "number")
  assert(pos <= #buf)

  local pos, id = bin.unpack("C", buf, pos)
  if not pos then
    return false, id
  end

  local class = bit.rshift(id, 5)
  local detail = bit.band(id, 0x1F)

  for key, val in pairs(COAP.header.codes.ids) do
    if val[1] == class and val[2] == detail then
      return pos, key
    end
  end

  return false, ("Code '%d.%02d' not recognized."):format(class, detail)
end

COAP.header.options.ids = {
  ["if_match"]       = 1,
  ["uri_host"]       = 3,
  ["etag"]           = 4,
  ["if_none_match"]  = 5,
  ["uri_port"]       = 7,
  ["location_path"]  = 8,
  ["uri_path"]       = 11,
  ["content_format"] = 12,
  ["max_age"]        = 14,
  ["uri_query"]      = 15,
  ["accept"]         = 17,
  ["location_query"] = 20,
  ["block2"]         = 23,
  ["block1"]         = 27,
  ["proxy_uri"]      = 35,
  ["proxy_scheme"]   = 39,
  ["size1"]          = 60,
}

--- Build CoAP message header options.
--
-- @name COAP.header.options.build
--
-- See section "3.1. Option Format" of the standard.
--
-- Due to the ordering of options and using delta representation of
-- their identifiers, we process all options at once.
--
-- The sorting method used is in this function is terrible, but using
-- Lua's sort with a function gave seemingly inconsistent results. We
-- have rolled-our-own stable sort which functions properly. Replacing
-- it is welcome.
--
-- @param options Table of options and their values.
--
-- @return response String representing a raw set of options, properly
--         sorted.
COAP.header.options.build = function(options)
  -- Sanity check the option table.
  assert(type(options) == "table")
  if #options == 0 then
    return ""
  end

  -- Each option needs to have an ID, since that's used for ordering
  -- and the delta value.
  local ids = {}
  for _, opt in pairs(options) do
    local id = COAP.header.options.ids[opt.name]
    assert(id)
    opt.id = id
    ids[id] = true
  end

  -- Options are encoded in order of their corresponding IDs, and
  -- contain a delta value indicating the offset of the option's ID
  -- from the previous option, which allows gaps.
  --
  -- We start by ordering the array of options, using stable sorting
  -- so that duplicate options retain their relative ordering. The
  -- range of IDs is large enough to warrant sorting instead of
  -- iterating through all possibilities.
  local unique_ids = {}
  for key, val in pairs(ids) do
    table.insert(unique_ids, key)
  end

  table.sort(unique_ids)

  local sorted_options = {}
  for _, id in ipairs(unique_ids) do
    for _, opt in pairs(options) do
      if opt.id == id then
        table.insert(sorted_options, opt)
      end
    end
  end

  -- The first option, and duplicate instances of an option, can be
  -- encoded using a delta of zero.
  local prev = 0

  local pkt = ""
  for _, opt in ipairs(sorted_options) do
    -- Build the option's value.
    local val = COAP.header.options[opt.name].build(opt.value)

    -- Calculate delta of this option's ID versus the previous
    -- option's ID.
    local delta = opt.id - prev
    assert(delta >= 0)
    prev = opt.id

    -- We must delete the ID key from the option to prevent it from
    -- persisting on the shared object that was passed in, which can
    -- bungle our tests.
    opt.id = nil

    -- Due to the complex nature of the delta and length fields, they
    -- are handled together.
    local delta_and_length = COAP.header.options.delta_length.build(delta, #val)

    pkt = pkt .. delta_and_length .. val
  end

  return pkt
end

--- Parses a CoAP message's header options.
--
-- @name COAP.header.options.parse
--
-- See section "3.1. Option Format" of the standard.
--
-- @param buf String from which to parse the options.
-- @param pos Position from which to start parsing.
--
-- @return pos String index on success, false on failure.
-- @return response Table representing options on success, string
--         containing the error message on failure.
COAP.header.options.parse = function(buf, pos)
  assert(type(buf) == "string")
  if #buf < 1 then
    return false, nil, nil, "Cannot parse a string of less than one byte."
  end

  if not pos or pos == 0 then
    pos = 1
  end
  assert(type(pos) == "number")
  assert(pos <= #buf, ("pos<%d> <= #buf<%d>"):format(pos, #buf))

  local prev = 0
  local options = {}
  while pos <= #buf do
    -- Check for the Packet Marker which terminates the options list.
    if buf:byte(pos) == 0xFF then
      break
    end

    -- Parse the first one to five bytes of the option.
    local delta, err, length
    pos, delta, length, err = COAP.header.options.delta_length.parse(buf, pos)
    if not pos then
      return false, err
    end

    -- Reconstruct the ID and name of the option.
    local id = prev + delta
    prev = id
    local name = nil
    for key, val in pairs(COAP.header.options.ids) do
      if val == id then
        name = key
        break
      end
    end

    -- XXX-MAK: Technically, we should determine whether the option is
    -- critical and only fail if it is. However, this works well
    -- enough.
    if not name then
      return false, ("Failed to find name for option with ID %d."):format(id)
    end

    -- Extract the value bytes from the buffer, since the option value
    -- parsers cannot determine the value length on their own.
    local end_pos = pos + length
    if end_pos - 1 > #buf then
      return false, "Option value extends past end of buffer."
    end
    local body = buf:sub(pos, end_pos - 1)
    pos = end_pos

    -- Parse the value of the option.
    local val = COAP.header.options[name].parse(body)

    -- Create the option definition and add it to our list.
    table.insert(options, {["name"] = name, ["value"] = val})
  end

  return pos, options
end

--- Builds a CoAP message header Accept option.
--
-- @name COAP.header.options.accept.build
--
-- 5.10.4. Accept
--
-- @param val Number representing an acceptable content type.
--
-- @return str String representing the option's value.
COAP.header.options.accept.build = function(val)
  assert(val >= 0)
  assert(val <= 65535)
  return COAP.header.options.value.uint.build(val)
end

--- Parses a CoAP message header Accept option.
--
-- @name COAP.header.options.accept.parse
--
-- 5.10.4. Accept
--
-- @param buf String from which to parse the option.
--
-- @return val Number representing the option's value.
COAP.header.options.accept.parse = function(buf)
  return COAP.header.options.value.uint.parse(buf)
end

--- Builds a CoAP message header Block1 option.
--
-- @name COAP.header.options.block1.build
--
-- https://tools.ietf.org/html/draft-ietf-core-block-19
--
-- @see COAP.header.options.block.build
--
-- @param val Table representing the option's parameters.
--
-- @return str String representing the option's value.
COAP.header.options.block1.build = function(val)
  return COAP.header.options.value.block.build(val)
end

--- Parses a CoAP message header Block1 option.
--
-- @name COAP.header.options.block1.parse
--
-- https://tools.ietf.org/html/draft-ietf-core-block-19
--
-- @see COAP.header.options.block.parse
--
-- @param buf String from which to parse the option.
--
-- @return response Table representing the option's value.
COAP.header.options.block1.parse = function(buf)
  return COAP.header.options.value.block.parse(buf)
end

--- Builds a CoAP message header Block2 option.
--
-- @name COAP.header.options.block2.build
--
-- https://tools.ietf.org/html/draft-ietf-core-block-19
--
-- @see COAP.header.options.block.build
--
-- @param val Table representing the option's parameters.
--
-- @return str String representing the option.
COAP.header.options.block2.build = function(val)
  return COAP.header.options.value.block.build(val)
end

--- Parses a CoAP message header Block2 option.
--
-- @name COAP.header.options.block2.parse
--
-- https://tools.ietf.org/html/draft-ietf-core-block-19
--
-- @see COAP.header.options.block.parse
--
-- @param buf String from which to parse the option.
--
-- @return response Table representing the option's value.
COAP.header.options.block2.parse = function(buf)
  return COAP.header.options.value.block.parse(buf)
end

-- The default content format, "charset=utf-8", is represented by the
-- absence of this option.
COAP.header.options.content_format.values = {
  ["text/plain"]               = 0,
  ["application/link-format"]  = 40,
  ["application/xml"]          = 41,
  ["application/octet-stream"] = 42,
  ["application/exi"]          = 47,
  ["application/json"]         = 50,
}

--- Builds a CoAP message header Content-Format option.
--
-- @name COAP.header.options.content_format.build
--
-- 5.10.3. Content-Format
--
-- @param val Number representing the payload content format.
--
-- @return str String representing the option's value.
COAP.header.options.content_format.build = function(val)
  -- Translate string to number if necessary.
  if type(val) == "string" then
    val = COAP.headers.options.content_format.values[val]
  end
  assert(val)

  return COAP.header.options.value.uint.build(val)
end

--- Parses a CoAP message header Content-Format option.
--
-- @name COAP.header.options.content_format.parse
--
-- 5.10.3. Content-Format
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.content_format.parse = function(buf)
  local val = COAP.header.options.value.uint.parse(buf)

  -- Translate number to string if possible.
  for name, num in pairs(COAP.header.options.content_format.values) do
    if num == val then
      return name
    end
  end

  return val
end

--- Builds a CoAP message header ETag option.
--
-- @name COAP.header.options.etag.build
--
-- 5.10.6. ETag
-- 5.10.6.1. ETag as a Response Option
-- 5.10.6.2. ETag as a Request Option
--
-- @param val String representing the ETag's value.
--
-- @return str String representing the option's value.
COAP.header.options.etag.build = function(val)
  assert(#val >= 1)
  assert(#val <= 8)
  return COAP.header.options.value.opaque.build(val)
end

--- Parses a CoAP message header ETag option.
--
-- @name COAP.header.options.etag.parse
--
-- 5.10.6. ETag
-- 5.10.6.1. ETag as a Response Option
-- 5.10.6.2. ETag as a Request Option
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.etag.parse = function(buf)
  return COAP.header.options.value.opaque.parse(buf)
end

--- Builds a CoAP message header If-Match option.
--
-- @name COAP.header.options.if_match.build
--
-- 5.10.8. Conditional Request Options
-- 5.10.8.1. If-Match
--
-- @param val String representing the condition.
--
-- @return str String representing the option's value.
COAP.header.options.if_match.build = function(val)
  assert(#val >= 0)
  assert(#val <= 8)
  return COAP.header.options.value.opaque.build(val)
end

--- Parses a CoAP message header If-Match option.
--
-- @name COAP.header.options.if_match.parse
--
-- 5.10.8. Conditional Request Options
-- 5.10.8.1. If-Match
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.if_match.parse = function(buf)
  return COAP.header.options.value.opaque.parse(buf)
end

--- Builds a CoAP message header If-None-Match option.
--
-- @name COAP.header.options.if_none_match.build
--
-- 5.10.8. Conditional Request Options
-- 5.10.8.2. If-None-Match
--
-- @param val Parameter is ignored, existing only to keep API
--            consistent.
--
-- @return str Empty string to keep API consistent.
COAP.header.options.if_none_match.build = function(val)
  return COAP.header.options.value.empty.build(val)
end

--- Parses a CoAP message header If-None-Match option.
--
-- @name COAP.header.options.if_none_match.parse
--
-- 5.10.8. Conditional Request Options
-- 5.10.8.2. If-None-Match
--
-- @param buf Parameter is ignored, existing only to keep API
--            consistent.
--
-- @return val Nil due to the option being empty.
COAP.header.options.if_none_match.parse = function(buf)
  return COAP.header.options.value.empty.parse(buf)
end

--- Builds a CoAP message header Location-Path option.
--
-- @name COAP.header.options.location_path.build
--
-- 5.10.7. Location-Path and Location-Query
--
-- @param val String representing a path.
--
-- @return str String representing the option's value.
COAP.header.options.location_path.build = function(val)
  assert(#val >= 0)
  assert(#val <= 255)
  return COAP.header.options.value.string.build(val)
end

--- Parses a CoAP message header Location-Path option.
--
-- @name COAP.header.options.location_path.parse
--
-- 5.10.7. Location-Path and Location-Query
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.location_path.parse = function(buf)
  return COAP.header.options.value.string.parse(buf)
end

--- Builds a CoAP message header Location-Query option.
--
-- @name COAP.header.options.location_query.build
--
-- 5.10.7. Location-Path and Location-Query
--
-- @param val String representing the query.
--
-- @return str String representing the option's value.
COAP.header.options.location_query.build = function(val)
  assert(#val >= 0)
  assert(#val <= 255)
  return COAP.header.options.value.string.build(val)
end

--- Parses a CoAP message header Location-Query option.
--
-- @name COAP.header.options.location_query.parse
--
-- 5.10.7. Location-Path and Location-Query
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.location_query.parse = function(buf)
  return COAP.header.options.value.string.parse(buf)
end

--- Builds a CoAP message header Max-Age option.
--
-- @name COAP.header.options.max_age.build
--
-- 5.10.5. Max-Age
--
-- @param val Number representing the maximum age.
--
-- @return str String representing the option's value
COAP.header.options.max_age.build = function(val)
  return COAP.header.options.value.uint.build(val)
end

--- Parses a CoAP message header Max-Age option.
--
-- @name COAP.header.options.max_age.parse
--
-- 5.10.5. Max-Age
--
-- @param buf String from which to parse the option.
--
-- @return val Number representing the option's value.
COAP.header.options.max_age.parse = function(buf)
  return COAP.header.options.value.uint.parse(buf)
end

--- Builds a CoAP message header Proxy-Scheme option.
--
-- @name COAP.header.options.proxy_scheme.build
--
-- 5.10.2. Proxy-Uri and Proxy-Scheme
--
-- @param val String representing the proxy scheme.
--
-- @return str String representing the option's value.
COAP.header.options.proxy_scheme.build = function(val)
  assert(#val >= 1)
  assert(#val <= 255)
  return COAP.header.options.value.string.build(val)
end

--- Parses a CoAP message header Proxy-Scheme option.
--
-- @name COAP.header.options.proxy_scheme.parse
--
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.proxy_scheme.parse = function(buf)
  return COAP.header.options.value.string.parse(buf)
end

--- Builds a CoAP message header Proxy-Uri option.
--
-- @name COAP.header.options.proxy_uri.build
--
-- 5.10.2. Proxy-Uri and Proxy-Scheme
--
-- @param val String representing the proxy URI.
--
-- @return str String representing the option's value.
COAP.header.options.proxy_uri.build = function(val)
  return COAP.header.options.value.string.build(val)
end

--- Parses a CoAP message header Proxy-Uri option.
--
-- @name COAP.header.options.proxy_uri.parse
--
-- 5.10.2. Proxy-Uri and Proxy-Scheme
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.proxy_uri.parse = function(buf)
  return COAP.header.options.value.string.parse(buf)
end

--- Builds a CoAP message header Size1 option.
--
-- @name COAP.header.options.Size1.build
--
-- 5.10.9. Size1 Option
--
-- @param val Number representing a size.
--
-- @return str String representing the option's value.
COAP.header.options.size1.build = function(val)
  return COAP.header.options.value.uint.build(val)
end

--- Parses a CoAP message header Size1 option.
--
-- @name COAP.header.options.size1.parse
--
-- 5.10.9. Size1 Option
--
-- @param buf String from which to parse the option.
--
-- @return val Number representing the option's value.
COAP.header.options.size1.parse = function(buf)
  return COAP.header.options.value.uint.parse(buf)
end

--- Builds a CoAP message header Uri-Host option.
--
-- @name COAP.header.options.uri_host.build
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param val String representing the host of the URI.
--
-- @return str String representing the option's value.
COAP.header.options.uri_host.build = function(val)
  assert(#val >= 1)
  assert(#val <= 255)
  return COAP.header.options.value.string.build(val)
end

--- Parses a CoAP message header Uri-Host option.
--
-- @name COAP.header.options.uri_host.parse
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.uri_host.parse = function(buf)
  return COAP.header.options.value.string.parse(buf)
end

--- Builds a CoAP message header Uri-Path option.
--
-- @name COAP.header.options.uri_path.build
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param val String representing a path in the URI.
--
-- @return str String representing the option's value.
COAP.header.options.uri_path.build = function(val)
  assert(#val >= 0)
  assert(#val <= 255)
  return COAP.header.options.value.string.build(val)
end

--- Parses a CoAP message header Uri-Path option.
--
-- @name COAP.header.options.uri_path.parse
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.uri_path.parse = function(buf)
  return COAP.header.options.value.string.parse(buf)
end

--- Builds a CoAP message header Uri-Port option.
--
-- @name COAP.header.options.uri_port.build
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param val Number representing an endpoint's port number.
--
-- @return str String representing the option's value.
COAP.header.options.uri_port.build = function(val)
  assert(val >= 0)
  assert(val <= 65535)
  return COAP.header.options.value.uint.build(val)
end

--- Parses a CoAP message header Uri-Port option.
--
-- @name COAP.header.options.uri_port.parse
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param buf String from which to parse the option.
--
-- @return val Number representing the option's value.
COAP.header.options.uri_port.parse = function(buf)
  return COAP.header.options.value.uint.parse(buf)
end

--- Builds a CoAP message header Uri-Query option.
--
-- @name COAP.header.options.uri_query.build
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param val String representing a query string in the URI.
--
-- @return str String representing the option's value.
COAP.header.options.uri_query.build = function(val)
  return COAP.header.options.value.string.build(val)
end

--- Parses a CoAP message header Uri-Query option.
--
-- @name COAP.header.options.uri_query.parse
--
-- 5.10.1. Uri-Host, Uri-Port, Uri-Path, and Uri-Query
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.uri_query.parse = function(buf)
  return COAP.header.options.value.string.parse(buf)
end

--- Builds a CoAP message header Block option.
--
-- @name COAP.header.options.block.build
--
-- For large payloads that would be too large for the underlying
-- transport, block transfers exist. This allows endpoints to transfer
-- payloads in small chunks. This is very common, and is frequently
-- used when transferring the <code>/.well-known/core</code> resource
-- due to its size.
--
-- As of the writing of this function, the block transfer definition
-- is a draft undergoing active revision.
--
-- https://tools.ietf.org/html/draft-ietf-core-block-19
--
-- @see COAP.header.options.block1.build
-- @see COAP.header.options.block2.build
--
-- @param val Table representing the block's parameters.
--
-- @return str String representing the option's value.
COAP.header.options.value.block.build = function(val)
  assert(type(val) == "table")

  -- Let the uint parser do the initial encoding, since it can handle
  -- 1-3 byte uints, even though the block number field can only be 4,
  -- 12, or 20 bits. The encoding guarantees that the 4 LSBs can be
  -- used for the remaining two fields.
  --
  -- Note that we have to handle zero as a special case since the uint
  -- will be represented by the absence of any bytes, but we need a
  -- single byte to encode the remaining two fields.
  local num = val.number
  assert(type(num) == "number")
  assert(val.number >= 0)
  assert(val.number <= 1048575)

  num = bit.lshift(num, 1)

  local mf = val.more
  assert(type(mf) == "boolean")
  if mf then
    num = bit.bor(num, 0x1)
  end

  num = bit.lshift(num, 3)

  local length = val.length
  assert(type(length) == "number")
  assert(val.length >= 16)
  assert(val.length <= 1024)

  local map = {[16]=0, [32]=1, [64]=2, [128]=3, [256]=4, [512]=5, [1024]=6}
  local szx = map[length]
  assert(szx)

  num = bit.bor(num, szx)

  -- The final number that results from combining all the fields
  -- should fit within 3 bytes when built.
  assert(num >= 0)
  assert(num <= 16777215)

  -- Let the uint builder do the initial encoding, since it can handle
  -- 1-3 byte uints.
  --
  -- There is a special case that if all fields are zero/false, then
  -- no bytes should be contained in the value of the block option.
  -- This is due to the number zero being represented as the absence
  -- of any bytes.
  local str = COAP.header.options.value.uint.build(num)

  -- Finally, we want to check that we haven't over-shifted, which is
  -- characterized by the result being longer than expected based on
  -- the original number.
  if val.number == 0 and val.more == false and val.length == 16 then
    assert(#str == 0)
  elseif val.number <= 15 then
    assert(#str == 1)
  elseif val.number <= 4095 then
    assert(#str == 2)
  else
    assert(#str == 3)
  end

  return str
end

--- Parses a CoAP message header Block option.
--
-- @name COAP.header.options.block.parse
--
-- https://tools.ietf.org/html/draft-ietf-core-block-19
--
-- @see COAP.header.options.block1.parse
-- @see COAP.header.options.block2.parse
--
-- @param buf String from which to parse the option.
--
-- @return val Table representing the option.
COAP.header.options.value.block.parse = function(buf)
  assert(#buf >= 0)
  assert(#buf <= 3)

  -- Let the uint parser do the initial decoding, since it can handle
  -- 1-3 byte uints.
  local num = COAP.header.options.value.uint.parse(buf)
  assert(num >= 0)
  assert(num <= 16777215)

  -- Extract size exponent which represents 2 to the power of 4 + szx.
  --
  -- Note that this field could have a value as high as 7, it is only
  -- allowed to go up to 6. This prevents the option's value from
  -- being misinterpreted as the payload marker.
  local szx = bit.band(num, 0x7)
  if szx == 7 then
    szx = 6
  end

  local length = 2 ^ (4 + szx)
  assert(length >= 16)
  assert(length <= 1024)

  num = bit.rshift(num, 3)

  -- Extract more flag which indicates whether this is the last block.
  local mf = (bit.band(num, 0x1) == 0x1)
  assert(type(mf) == "boolean")

  num = bit.rshift(num, 1)

  -- The remainder of the number is the block number in sequence.
  assert(num >= 0)
  assert(num <= 1048575)

  return {
    ["number"] = num,
    ["more"]   = mf,
    ["length"] = length,
  }
end

--- Builds a CoAP message's Empty header option value.
--
-- @name COAP.header.options.value.empty.parse
--
-- 3.2. Option Value Formats
--
-- @param val Parameter is ignored, existing only to keep API
--            consistent.
--
-- @return str Empty string.
COAP.header.options.value.empty.build = function(val)
  assert(type(val) == "nil")
  return ""
end

--- Parses a CoAP message Empty header option value.
--
-- @name COAP.header.options.value.empty.parse
--
-- 3.2. Option Value Formats
--
-- @param buf Parameter is ignored, existing only to keep API
--            consistent.
--
-- @return val Nil due to the option being empty.
COAP.header.options.value.empty.parse = function(buf)
  assert(type(buf) == "string", ("Expected 'string', got '%s'."):format(type(buf)))
  return nil
end

--- Builds a CoAP message Opaque header option value.
--
-- @name COAP.header.options.value.opaque.build
--
-- 3.2. Option Value Formats
--
-- @param str String representing an opaque option value.
--
-- @return str String representing the option's value.
COAP.header.options.value.opaque.build = function(str)
  assert(type(str) == "string", ("Expected 'string', got '%s'."):format(type(str)))
  return str
end

--- Parses a CoAP message Opaque header option value.
--
-- @name COAP.header.options.value.opaque.parse
--
-- 3.2. Option Value Formats
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.value.opaque.parse = function(buf)
  assert(type(buf) == "string", ("Expected 'string', got '%s'."):format(type(buf)))
  return buf
end

--- Builds a CoAP message String header option value.
--
-- @name COAP.header.options.value.string.build
--
-- 3.2. Option Value Formats
--
-- @param str String representing a string option value.
--
-- @return str String representing the option's value.
COAP.header.options.value.string.build = function(str)
  assert(type(str) == "string", ("Expected 'string', got '%s'."):format(type(str)))
  return str
end

--- Parses a CoAP message String header option value.
--
-- @name COAP.header.options.value.string.parse
--
-- 3.2. Option Value Formats
--
-- @param buf String from which to parse the option.
--
-- @return val String representing the option's value.
COAP.header.options.value.string.parse = function(buf)
  assert(type(buf) == "string", ("Expected 'string', got '%s'."):format(type(buf)))
  return buf
end

--- Builds a CoAP message Uint header option value.
--
-- @name COAP.header.options.value.uint.build
--
-- 3.2. Option Value Formats
--
-- @param val Number representing a Uint option value.
--
-- @return str String representing the option's value.
COAP.header.options.value.uint.build = function(val)
  assert(type(val) == "number")
  assert(val >= 0)
  assert(val <= 4294967295)

  if val == 0 then
    return ""
  end

  if val <= 255 then
    return bin.pack("C", val)
  end

  if val <= 65535 then
    return bin.pack(">S", val)
  end

  if val <= 16777215 then
    return bin.pack(">I", val):sub(2, 5)
  end

  return bin.pack(">I", val)
end

--- Parses a CoAP message Uint header option value.
--
-- @name COAP.header.options.value.uint.parse
--
-- 3.2. Option Value Formats
--
-- @param buf String from which to parse the option.
--
-- @return val Number representing the option's value.
COAP.header.options.value.uint.parse = function(buf)
  assert(type(buf) == "string")
  assert(#buf >= 0)
  assert(#buf <= 4)

  if #buf == 0 then
    return 0
  end

  local val, pos
  if #buf == 1 then
    pos, val = bin.unpack("C", buf)
  elseif #buf == 2 then
    pos, val = bin.unpack(">S", buf)
  elseif #buf == 3 then
    pos, val = bin.unpack(">I", string.char(0x00) .. buf)
  else
    pos, val = bin.unpack(">I", buf)
  end

  -- There should be no way for this to fail.
  assert(pos)
  assert(val)
  assert(type(val) == "number")

  return val
end

--- Build the variable-length option delta and length field.
--
-- @name COAP.header.options.delta_length.build
--
-- Due to the interleaving of these two fields they are handled
-- together, since they can appear in nine forms, with the first byte
-- holding a nibble for each:
--   1) D|L
--   2) D|L D
--   3) D|L L
--   4) D|L D D
--   5) D|L D L
--   6) D|L L L
--   7) D|L D D L
--   8) D|L D L L
--   9) D|L D D L L
--
-- The 4 bits reserved in the header for the delta and length are
-- not enough to represent the large numbers required by the
-- options. For this reason there is a 1 or 2-byte field
-- conditionally added to the option's header to extend the range
-- the deltas and lengths can represent.
--
-- The delta field can represent:
--   Low : 0     as 0000
--   High: 12    as 1100
--
-- With one extra delta byte, it can represent:
--   Low : 13    as 1101 00000000 (13 + 0)
--   High: 268   as 1101 11111111 (13 + 255)
--
-- With two extra delta bytes, it can represent:
--   Low : 269   as 1110 00000000 00000000 (269 + 0)
--   High: 65804 as 1110 11111111 11111111 (269 + 65535)
--
-- 3.1. Option Format
--
-- @param delta Number representing the option ID's delta.
-- @param length Number representing the length of the option's value.
--
-- @return str String representing the delta and length fields.
COAP.header.options.delta_length.build = function(delta, length)
  local build = function(num)
    assert(type(num) == "number")
    assert(num >= 0)
    assert(num <= 65804)

    if num <= 12 then
      return num, ""
    end

    if num <= 268 then
      return 13, bin.pack("C", num - 13)
    end

    return 14, bin.pack(">S", num - 269)
  end

  local d1, d2 = build(delta)
  local l1, l2 = build(length)

  d1 = bit.lshift(d1, 4)
  bin.pack("C", bit.bor(d1, l1))

  return bin.pack("C", bit.bor(d1, l1)) .. d2 .. l2
end

--- Parse the variable-length option delta and length field.
--
-- @name COAP.header.options.delta_length.parse
--
-- Due to the interleaving of these two fields they are handled
-- together. See <ref>COAP.header.options.delta_length_build</ref> for details.
--
-- 3.1. Option Format
--
-- @param buf String from which to parse the fields.
-- @param pos Position from which to start parsing.
--
-- @return pos Position at which parsing stopped on success, or false
--         on failure.
-- @return delta Delta value of the option's ID on success, or nil on
--         failure.
-- @return length Length of the option's value on success, or nil on
--         failure.
-- @return err nil on success, or an error message on failure.
COAP.header.options.delta_length.parse = function(buf, pos)
  assert(type(buf) == "string")
  if #buf < 1 then
    return false, nil, nil, "Cannot parse a string of less than one byte."
  end

  if not pos or pos == 0 then
    pos = 1
  end
  assert(type(pos) == "number")
  assert(pos <= #buf)

  local pos, delta_and_length = bin.unpack("C", buf, pos)
  if not pos then
    return false, nil, nil, delta_and_length
  end
  local delta = bit.rshift(delta_and_length, 4)
  local length = bit.band(delta_and_length, 0x0F)

  -- Sanity check the first byte's value.
  if delta == 15 then
    return false, nil, nil, "Delta was 0xF, but a Packet Marker was not expected."
  end

  if length == 15 then
    return false, nil, nil, "Length was 0xF, but a Packet Marker was not expected."
  end

  -- Sanity check the length required to parse the remainder of the fields.
  local required_bytes = 0
  local dspec = nil
  local lspec = nil

  if delta == 13 then
    required_bytes = required_bytes + 1
    dspec = "C"
  elseif delta == 14 then
    required_bytes = required_bytes + 2
    delta = 269
    dspec = ">S"
  end

  if length == 13 then
    required_bytes = required_bytes + 1
    lspec = "C"
  elseif length == 14 then
    required_bytes = required_bytes + 2
    length = 269
    lspec = ">S"
  end

  if pos + required_bytes - 1 > #buf then
    return false, nil, nil, "Option delta and length fields extend past end of buffer."
  end

  -- Extract the remaining bytes of each field.
  if dspec then
    local num
    pos, num = bin.unpack(dspec, buf, pos)
    if not pos then
      return false, nil, nil, num
    end
    delta = delta + num
  end

  if lspec then
    local num
    pos, num = bin.unpack(lspec, buf, pos)
    if not pos then
      return false, nil, nil, num
    end
    length = length + num
  end

  return pos, delta, length, nil
end

--- Finds the first instance of an option type in a header.
--
-- @name COAP.header.find_option
--
-- @see COAP.header.find_options
--
-- @param hdr Table representing a message header.
-- @param name String naming an option type.
--
-- @return opt Table representing option on success, or nil if one was
--             not found.
COAP.header.find_option = function(hdr, name)
  assert(type(hdr) == "table")
  assert(type(name) == "string")

  local opts = COAP.header.find_options(hdr, name, 1)
  if next(opts) == nil then
    return nil
  end

  return opts[1]
end

--- Finds all instances of an option type in a header.
--
-- @name COAP.header.find_options
--
-- @param hdr Table representing a message header.
-- @param name String naming an option type.
-- @param max Maximum number of options to return.
--
-- @return opts Table containing option all options found, may be
--              empty.
COAP.header.find_options = function(hdr, name, max)
  assert(type(hdr) == "table")
  assert(type(name) == "string")
  assert(not max or type(max) == "number")

  local opts = {}

  local count = 1
  for _, opt in ipairs(hdr.options) do
    if opt.name == name then
      table.insert(opts, opt.value)
      if max and count >= max then
        break
      end
      count = count + 1
    end
  end

  return opts
end

COAP.payload.content_formats = {
  ["text/plain"]               = "text_plain",
  ["application/link-format"]  = "application_link_format",
  ["application/xml"]          = "application_xml",
  ["application/octet-stream"] = "application_octet_stream",
  ["application/exi"]          = "application_exi",
  ["application/json"]         = "application_json",
}

--- Parse the payload of a CoAP message.
--
-- @name COAP.payload.parse
--
-- 5.5. Payloads and Representations
--
-- Never use this function directly on a payload that has a Block
-- option, as there will only be a partial payload in such a message.
-- The top-level <ref>COAP.parse</ref> is smart enough not to
-- auto-parse messages with partial payloads.
--
-- @param hdr Table representing a message header.
-- @param buf String from which to parse the payload.
--
-- @return status True on success, false on failure.
-- @return val Object containing parsed payload on success, string
--         containing the error message on failure.
COAP.payload.parse = function(hdr, buf)
  assert(type(hdr) == "table")
  assert(type(buf) == "string", type(buf))

  -- Find the content format option which defines the manner in which
  -- the payload should be interpreted.
  local cf = COAP.header.find_option(hdr, "content_format")

  -- 5.5.2. Diagnostic Payload
  --
  -- If there's no content-format option, then the payload represents
  -- a human-readable string in UTF-8, for which we already have a
  -- parser.
  if not cf then
    return true, COAP.header.options.value.string.parse(buf)
  end

  -- If the content format wasn't recognized, it'll come back as a
  -- number and we'll just log that and return the raw payload.
  if type(cf) == "number" then
    stdnse.debug1("Content format ID %d not recognized for payload.", cf)
    return false, buf
  end

  -- Find the parser associated with the content format.
  local fn_name = COAP.payload.content_formats[cf]
  if not fn_name then
    stdnse.debug1("Content format %s not implemented for payload.", cf)
    return false, buf
  end

  -- Run the parser associated with the content format.
  local fn = COAP.payload[fn_name].parse
  assert(fn)

  return fn(hdr, buf)
end

--- Parse the Plain Text payload of a CoAP message.
--
-- @name COAP.payload.text_plain.parse
--
-- https://tools.ietf.org/html/rfc2046
-- https://tools.ietf.org/html/rfc3676
--
-- This function will return its input, since plain text is assumed to
-- have no additional structure.
--
-- @param hdr Table representing a message header.
-- @param buf String from which to parse the payload.
--
-- @return status True on success, false on failure.
-- @return val String containing parsed payload on success, string
--         containing the error message on failure.
COAP.payload.text_plain.parse = function(hdr, buf)
  assert(type(hdr) == "table")
  assert(type(buf) == "string")

  return true, buf
end

--- Parse the Link Format payload of a CoAP message.
--
-- @name COAP.payload.link_format.parse
--
-- https://tools.ietf.org/html/rfc6690
--
-- This format is complicated enough that parsing it accurately is
-- unlikely to be worth the effort. As a result, we have chosen the
-- following simplifications.
--   1) URIs can contain any character except '>'.
--   2) Parameters can have two forms:
--      a) ;name=value-with-semicolons-and-commas-forbidden
--      b) ;name="value-with-semicolons-and-commas-permitted"
-- If there is a need for full parsing, it can be addressed later.
--
-- @param hdr Table representing a message header.
-- @param buf String from which to parse the payload.
--
-- @return status True on success, false on failure.
-- @return val Table containing parsed payload on success, string
--         containing the error message on failure.
COAP.payload.application_link_format.parse = function(hdr, buf)
  assert(type(hdr) == "table")
  assert(type(buf) == "string")

  local P  = lpeg.P
  local S  = lpeg.S
  local Cg = lpeg.Cg
  local Cs = lpeg.Cs
  local Ct = lpeg.Ct

  local param_value_quoted = P'"' * Cs((P(1) - P'"')^0) * P'"'
  local param_value_bare = Cs((P(1) - S';,')^0)
  local param_value = param_value_quoted + param_value_bare
  local param_name = Cs((P(1) - P'=')^1)
  local param = Ct(P';' * Cg(param_name, 'name') * P'=' * Cg(param_value, 'value'))
  local uri = P'<' * Cs((P(1) - P'>')^1) * P'>'
  local link = Ct(Cg(uri, 'name') * Cg(Ct(param^0), 'parameters'))
  local patt = Ct(link * (P',' * link)^0)

  local matches = lpeg.match(patt, buf)
  if not matches then
    return false, ("Failed to format payload.")
  end

  return true, matches
end

--- Parse the XML payload of a CoAP message.
--
-- @name COAP.payload.application_xml.parse
--
-- https://tools.ietf.org/html/rfc3023
--
-- This function is unimplemented.
--
-- @param hdr Table representing a message header.
-- @param buf String from which to parse the payload.
--
-- @return status True on success, false on failure.
-- @return response Object containing parsed payload on success,
--         string containing the error message on failure.
COAP.payload.application_xml.parse = function(hdr, buf)
  assert(type(hdr) == "table")
  assert(type(buf) == "string")

  return false, "Unimplemented"
end

--- Parse the Octet Stream payload of a CoAP message.
--
-- @name COAP.payload.application_octet_stream.parse
--
-- https://tools.ietf.org/html/rfc2045
-- https://tools.ietf.org/html/rfc2046
--
-- This function will return its input, since it is assumed to have no
-- additional structure.
--
-- @param hdr Table representing a message header.
-- @param buf String from which to parse the payload.
--
-- @return status True on success, false on failure.
-- @return val String containing parsed payload on success, string
--         containing the error message on failure.
COAP.payload.application_octet_stream.parse = function(hdr, buf)
  assert(type(hdr) == "table")
  assert(type(buf) == "string")

  return true, buf
end

--- Parse the EXI payload of a CoAP message.
--
-- @name COAP.payload.exi.parse
--
-- https://www.w3.org/TR/2014/REC-exi-20140211/
--
-- This function is unimplemented.
--
-- @param hdr Table representing a message header.
-- @param buf String from which to parse the payload.
--
-- @return status True on success, false on failure.
-- @return response Object containing parsed payload on success,
--         string containing the error message on failure.
COAP.payload.application_exi.parse = function(hdr, buf)
  assert(type(hdr) == "table")
  assert(type(buf) == "string")

  return false, "Unimplemented"
end

--- Parse the JSON payload of a CoAP message.
--
-- @name COAP.payload.json.parse
--
-- https://tools.ietf.org/html/rfc7159
--
-- @param hdr Table representing a message header.
-- @param buf String from which to parse the payload.
--
-- @return status True on success, false on failure.
-- @return response Object containing parsed payload on success,
--         string containing the error message on failure.
COAP.payload.application_json.parse = function(hdr, buf)
  assert(type(hdr) == "table")
  assert(type(buf) == "string")

  return json.parse(buf)
end

Comm = {
  --- Creates a new Client instance.
  --
  -- @name Comm.new
  --
  -- @param host String as received by the action method.
  -- @param port Number as received by the action method.
  -- @param options Table as received by the action method.
  -- @return o Instance of Client.
  new = function(self, host, port, options)
    local o = {host = host, port = port, options = options or {}}
    -- Choose something random, while still giving lots of the 16-bit range
    -- available to grow into.
    o["message_id"] = math.random(16384)
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to the CoAP endpoint.
  --
  -- @name Comm.connect
  --
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  connect = function(self, options)
    local pkt = self:build(options)
    local sd, response, _, _ = comm.tryssl(self.host, self.port, pkt, {["proto"] = "udp"})
    if not sd then
      return false, response
    end

    -- The socket connected successfully over whichever protocol.
    self.socket = sd

    -- We now have some data that came back from the connection.
    return self:parse(response)
  end,

  --- Sends a CoAP message.
  --
  -- @name Comm.send
  --
  -- @param pkt String representing a raw message.
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  send = function(self, pkt)
    assert(type(pkt) == "string")
    return self.socket:send(pkt)
  end,

  --- Receives an MQTT control packet.
  --
  -- @name Comm.receive
  --
  -- @return status True on success, false on failure.
  -- @return response String representing a raw message on success,
  --         string containing the error message on failure.
  receive = function(self)
    local status, pkt = self.socket:receive()
    if not status then
      return false, "Failed to receive a response from the server."
    end

    return true, pkt
  end,

  --- Builds a CoAP message.
  --
  -- @name Comm.build
  --
  -- @param options Table of options accepted by the requested type of
  --        message.
  -- @return status true on success, false on failure.
  -- @return response String representing a raw message on success, or
  --         containing the error message on failure.
  build = function(self, options, payload)
    assert(type(options) == "table")

    -- Augment with a message ID we control.
    if not options.id then
      self.message_id = self.message_id + 1
      options.id = self.message_id
    end

    return COAP.header.build(options, payload)
  end,

  --- Parses a CoAP message.
  --
  -- @name Comm.parse
  --
  -- @param buf String from which to parse the message.
  -- @param pos Position from which to start parsing.
  -- @return pos String index on success, false on failure.
  -- @return response Table representing a CoAP message on success,
  --         string containing the error message on failure.
  parse = function(self, buf, pos)
    assert(type(buf) == "string")

    if not pos then
      pos = 0
    end
    assert(type(pos) == "number")
    assert(pos < #buf)

    local pos, hdr = COAP.parse(buf, pos)
    if not pos then
      return false, hdr
    end

    return pos, hdr
  end,

  --- Disconnects from the CoAP endpoint.
  --
  -- @name Comm.close
  close = function(self)
    return self.socket:close()
  end,
}

Helper = {
  --- Creates a new Helper instance.
  --
  -- @name Helper.create
  --
  -- @param host String as received by the action method.
  -- @param port Number as received by the action method.
  -- @param options Table as received by the action method.
  -- @return o instance of Client
  new = function(self, host, port, opt)
    local o = { host = host, port = port, opt = opt or {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to the CoAP endpoint.
  --
  -- @name Helper.connect
  --
  -- @param options Table of options for the initial message.
  -- @return status True on success, false on failure.
  -- @return response Table representing the response on success,
  --         string containing the error message on failure.
  connect = function(self, options)
    if not options.code then
      options.code = "get"
    end

    if not options.type then
      options.type = "confirmable"
    end

    if not options.options then
      options.options = {}
    end

    assert(options.uri)
    local components = stdnse.strsplit("/", options.uri)
    for _, component in ipairs(components) do
      if component ~= "" then
        table.insert(options.options, {["name"] = "uri_path", ["value"] = component})
      end
    end

    self.comm = Comm:new(self.host, self.port, self.opt)

    local status, response = self.comm:connect(options)
    if not status then
      return false, response
    end

    -- If the response's ID is not what we expect, then we're going to assume
    -- that we're not talking to a CoAP service.
    if response.id ~= self.comm.message_id then
      return false, "Message ID in response does not match request."
    end

    return status, response
  end,

  --- Sends a request to the CoAP endpoint.
  --
  -- @name Helper.send
  --
  -- @param options Table of options for the message.
  -- @param payload Payload of message.
  -- @return status True on success, false on failure.
  -- @return err String containing the error message on failure.
  send = function(self, options, payload)
    assert(type(options) == "table")

    local pkt = self.comm:build(options, payload)

    return self.comm:send(pkt)
  end,

  --- Sends a request to the CoAP, and receive a response.
  --
  -- @name Helper.request
  --
  -- @param options Table of options for the message.
  -- @param payload String containing the message body.
  -- @return status True on success, false on failure.
  -- @return response Table representing a message with the
  --         corresponding message ID on success, string containing
  --         the error message on failure.
  request = function(self, options, payload)
    assert(type(options) == "table")

    local status, err = self:send(options, payload)
    if not status then
       return false, err
    end

    local id
    if options.id then
      id = options.id
    else
      id = self.comm.o["message_id"]
    end

    return self:receive({id})
  end,

  --- Listens for a response matching a list of types.
  --
  -- @name Helper.receive
  --
  -- @param ids Table of message IDs to wait for.
  -- @param timeout Number of seconds to listen for matching response,
  --                defaults to 5s.
  -- @return status True on success, false on failure.
  -- @return response Table representing any message on success,
  --         string containing the error message on failure.
  receive = function(self, ids, timeout)
    assert(type(ids) == "table")

    if not timeout then
      timeout = 5
    end
    assert(type(timeout) == "number")

    local end_time = nmap.clock_ms() + timeout * 1000
    while true do
      -- Get the raw packet from the socket.
      local status, pkt = self.comm:receive()
      if not status then
        return false, pkt
      end

      -- Parse the raw packet into a table.
      local status, hdr = self.comm:parse(pkt)
      if not status then
        return false, hdr
      end

      -- Check for messages matching our message IDs.
      for _, id in pairs(ids) do
        if hdr.id == id then
          return true, hdr
        end
      end

      -- Check timeout, but only if we care about it.
      if timeout > 0 then
        if nmap.clock_ms() >= end_time then
          break
        end
      end
    end

    return false, ("No messages received in %d seconds matching desired message IDs."):format(timeout)
  end,

  -- Closes the socket with the endpoint.
  --
  -- @name Helper.close
  close = function(self)
  end,
}

-- Skip unit tests unless we're explicitly testing.
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

for test_name, test_code in pairs(COAP.header.codes.ids) do
  local test_cls = test_code[1]
  local test_dtl = test_code[2]

  -- Build the packet.
  local str = COAP.header.codes.build(test_name)

  -- Parse, implicitly from the first character.
  local pos, name = COAP.header.codes.parse(str)
  test_suite:add_test(unittest.equal(name, test_name))
  test_suite:add_test(unittest.equal(pos, #str + 1))

  -- Parse, explicitly from the zero-indexed first character.
  local pos, name = COAP.header.codes.parse(str, 0)
  test_suite:add_test(unittest.equal(name, test_name))
  test_suite:add_test(unittest.equal(pos, #str + 1))

  -- Parse, explicitly from the one-indexed first character.
  local pos, name = COAP.header.codes.parse(str, 1)
  test_suite:add_test(unittest.equal(name, test_name))
  test_suite:add_test(unittest.equal(pos, #str + 1))

  -- Parse, explicitly from the one-indexed second character.
  local pos, name = COAP.header.codes.parse("!" .. str, 2)
  test_suite:add_test(unittest.equal(name, test_name))
  test_suite:add_test(unittest.equal(pos, #str + 2))
end

local tests = {
  {         0, string.char(                      )},
  {         1, string.char(0x01                  )},
  {         2, string.char(0x02                  )},
  {       254, string.char(0xFE                  )},
  {       255, string.char(0xFF                  )},
  {       256, string.char(0x01, 0x00            )},
  {       257, string.char(0x01, 0x01            )},
  {     65534, string.char(0xFF, 0xFE            )},
  {     65535, string.char(0xFF, 0xFF            )},
  {     65536, string.char(0x01, 0x00, 0x00      )},
  {     65537, string.char(0x01, 0x00, 0x01      )},
  {  16777214, string.char(0xFF, 0xFF, 0xFE      )},
  {  16777215, string.char(0xFF, 0xFF, 0xFF      )},
  {  16777216, string.char(0x01, 0x00, 0x00, 0x00)},
  {  16777217, string.char(0x01, 0x00, 0x00, 0x01)},
  {4294967293, string.char(0xFF, 0xFF, 0xFF, 0xFD)},
  {4294967294, string.char(0xFF, 0xFF, 0xFF, 0xFE)},
  {4294967295, string.char(0xFF, 0xFF, 0xFF, 0xFF)},
}

for _, test in ipairs(tests) do
  local test_num = test[1]
  local test_str = test[2]

  -- Build the field.
  local str = COAP.header.options.value.uint.build(test_num)
  test_suite:add_test(unittest.equal(str, test_str))

  -- Parse the field.
  local num = COAP.header.options.value.uint.parse(test_str)
  test_suite:add_test(unittest.equal(num, test_num))
end

-- 3.1.  Option Format
-- There are five different values at which to test the options
-- delta and length fields:
--   1) Start
--   2) Start + 1
--   3) Middle
--   4) End - 1
--   5) End
-- This should be done for each of the three possible field lengths,
-- and at a variety of locations in the buffer.
local tests = {
  {    0,     0, string.char(0x00                        )},
  {    1,     0, string.char(0x10                        )},
  {    0,     1, string.char(0x01                        )},
  {    1,     1, string.char(0x11                        )},
  {    2,     1, string.char(0x21                        )},
  {    1,     2, string.char(0x12                        )},
  {    2,     2, string.char(0x22                        )},
  {   11,    11, string.char(0xBB                        )},
  {   12,    11, string.char(0xCB                        )},
  {   11,    12, string.char(0xBC                        )},
  {   12,    12, string.char(0xCC                        )},
  {   13,    12, string.char(0xDC, 0x00                  )},
  {   12,    13, string.char(0xCD, 0x00                  )},
  {   13,    13, string.char(0xDD, 0x00, 0x00            )},
  {   14,    13, string.char(0xDD, 0x01, 0x00            )},
  {   13,    14, string.char(0xDD, 0x00, 0x01            )},
  {   14,    14, string.char(0xDD, 0x01, 0x01            )},
  {  267,   267, string.char(0xDD, 0xFE, 0xFE            )},
  {  268,   267, string.char(0xDD, 0xFF, 0xFE            )},
  {  267,   268, string.char(0xDD, 0xFE, 0xFF            )},
  {  268,   268, string.char(0xDD, 0xFF, 0xFF            )},
  {  269,   268, string.char(0xED, 0x00, 0x00, 0xFF      )},
  {  268,   269, string.char(0xDE, 0xFF, 0x00, 0x00      )},
  {  269,   269, string.char(0xEE, 0x00, 0x00, 0x00, 0x00)},
  {  270,   269, string.char(0xEE, 0x00, 0x01, 0x00, 0x00)},
  {  269,   270, string.char(0xEE, 0x00, 0x00, 0x00, 0x01)},
  {  270,   270, string.char(0xEE, 0x00, 0x01, 0x00, 0x01)},
  {65802, 65802, string.char(0xEE, 0xFF, 0xFD, 0xFF, 0xFD)},
  {65803, 65802, string.char(0xEE, 0xFF, 0xFE, 0xFF, 0xFD)},
  {65802, 65803, string.char(0xEE, 0xFF, 0xFD, 0xFF, 0xFE)},
  {65803, 65803, string.char(0xEE, 0xFF, 0xFE, 0xFF, 0xFE)},
  {65804, 65803, string.char(0xEE, 0xFF, 0xFF, 0xFF, 0xFE)},
  {65803, 65804, string.char(0xEE, 0xFF, 0xFE, 0xFF, 0xFF)},
  {65804, 65804, string.char(0xEE, 0xFF, 0xFF, 0xFF, 0xFF)},
}

for _, test in ipairs(tests) do
  local test_del = test[1]
  local test_len = test[2]
  local test_str = test[3]

  -- Build the field.
  local str = COAP.header.options.delta_length.build(test_del, test_len)
  test_suite:add_test(unittest.equal(str, test_str))

  -- Parse, implicitly from the first character.
  local pos, del, len, err = COAP.header.options.delta_length.parse(test_str)
  test_suite:add_test(unittest.equal(pos, #test_str + 1))
  test_suite:add_test(unittest.equal(del, test_del))
  test_suite:add_test(unittest.equal(len, test_len))
  test_suite:add_test(unittest.is_nil(err))

  -- -- Parse, explicitly from the zero-indexed first character.
  local pos, del, len, err = COAP.header.options.delta_length.parse(test_str, 0)
  test_suite:add_test(unittest.equal(pos, #test_str + 1))
  test_suite:add_test(unittest.equal(del, test_del))
  test_suite:add_test(unittest.equal(len, test_len))
  test_suite:add_test(unittest.is_nil(err))

  -- Parse, explicitly from the one-indexed first character.
  local pos, del, len, err = COAP.header.options.delta_length.parse(test_str, 1)
  test_suite:add_test(unittest.equal(pos, #test_str + 1))
  test_suite:add_test(unittest.equal(del, test_del))
  test_suite:add_test(unittest.equal(len, test_len))
  test_suite:add_test(unittest.is_nil(err))

  -- -- Parse, explicitly from the one-indexed second character.
  local pos, del, len, err = COAP.header.options.delta_length.parse("!" .. test_str, 2)
  test_suite:add_test(unittest.equal(pos, #test_str + 2))
  test_suite:add_test(unittest.equal(del, test_del))
  test_suite:add_test(unittest.equal(len, test_len))
  test_suite:add_test(unittest.is_nil(err))

  -- Truncate string and attempt to parse, expecting error.
  local short_str = test_str:sub(1, #test_str - 1)
  test_suite:add_test(unittest.equal(#short_str, #test_str - 1))
  local pos, del, len, err = COAP.header.options.delta_length.parse(short_str)
  test_suite:add_test(unittest.is_false(pos))
  test_suite:add_test(unittest.is_nil(del))
  test_suite:add_test(unittest.is_nil(len))
  test_suite:add_test(unittest.not_nil(err))
end

-- See section "3.1. Option Format" of the standard.
local tests = {
  {
    -- Before
    {
      {["name"] = "if_none_match"},
    },
    -- After
    {
      {["name"] = "if_none_match"},
    },
    string.char(0x50)
  },
  {
    -- Before
    {
      {["name"] = "etag", ["value"] = "ETAGETAG"},
    },
    -- After
    {
      {["name"] = "etag", ["value"] = "ETAGETAG"},
    },
    bin.pack("CA", 0x48, "ETAGETAG")
  },
  {
    -- Before
    {
      {["name"] = "max_age", ["value"] = 0},
    },
    -- After
    {
      {["name"] = "max_age", ["value"] = 0},
    },
    string.char(0xD0, 0x01)
  },
  {
    -- Before
    {
      {["name"] = "max_age", ["value"] = 0},
      {["name"] = "uri_path", ["value"] = "foo"},
    },
    -- After
    {
      {["name"] = "uri_path", ["value"] = "foo"},
      {["name"] = "max_age", ["value"] = 0},
    },
    bin.pack("CAC", 0xB3, "foo", 0x30)
  },
  {
    -- Before
    {
      {["name"] = "uri_path", ["value"] = ".well-known"},
      {["name"] = "uri_path", ["value"] = "core"},
    },
    -- After
    {
      {["name"] = "uri_path", ["value"] = ".well-known"},
      {["name"] = "uri_path", ["value"] = "core"},
    },
    bin.pack("CACA", 0xBB, ".well-known", 0x04, "core")
  },
  {
    -- Before
    {
      {["name"] = "uri_path", ["value"] = ".well-known"},
      {["name"] = "if_none_match"},
      {["name"] = "max_age", ["value"] = 0},
      {["name"] = "etag", ["value"] = "ETAGETAG"},
      {["name"] = "uri_path", ["value"] = "core"},
    },
    -- After
    {
      {["name"] = "etag", ["value"] = "ETAGETAG"},
      {["name"] = "if_none_match"},
      {["name"] = "uri_path", ["value"] = ".well-known"},
      {["name"] = "uri_path", ["value"] = "core"},
      {["name"] = "max_age", ["value"] = 0},
    },
    bin.pack(
      "CACCACAC",
      0x48, "ETAGETAG",    -- ID:  4, Delta: 4
      0x10,                -- ID:  5, Delta: 1
      0x6B, ".well-known", -- ID: 11, Delta: 6
      0x04, "core",        -- ID: 11, Delta: 0
      0x30                 -- ID: 14, Delta: 3
    )
  },
}

for _, test in ipairs(tests) do
  local test_opt1 = test[1]
  local test_opt2 = test[2]
  local test_str = test[3]

  -- Build the packet.
  local str = COAP.header.options.build(test_opt1)
  test_suite:add_test(unittest.equal(str, test_str))

  -- Parse, implicitly from the first character.
  local pos, opt = COAP.header.options.parse(test_str)
  test_suite:add_test(unittest.identical(opt, test_opt2))
  test_suite:add_test(unittest.equal(pos, #test_str + 1))

  -- Parse, explicitly from the zero-indexed first character.
  local pos, opt = COAP.header.options.parse(test_str, 0)
  test_suite:add_test(unittest.identical(opt, test_opt2))
  test_suite:add_test(unittest.equal(pos, #test_str + 1))

  -- Parse, explicitly from the one-indexed first character.
  local pos, opt = COAP.header.options.parse(test_str, 1)
  test_suite:add_test(unittest.identical(opt, test_opt2))
  test_suite:add_test(unittest.equal(pos, #test_str + 1))

  -- Parse, explicitly from the one-indexed second character.
  local pos, opt = COAP.header.options.parse("!" .. test_str, 2)
  test_suite:add_test(unittest.identical(opt, test_opt2))
  test_suite:add_test(unittest.equal(pos, #test_str + 2))
end

local tests = {
  {
    {
      ["version"] = 1,
      ["code"] = "get",
      ["id"] = 0x1234,
      ["type"] = "confirmable",
      ["token"] = "nmapcoap",
      ["token_length"] = 8,
      ["options"] = {
        {["name"] = "uri_path", ["value"] = ".well-known"},
        {["name"] = "uri_path", ["value"] = "core"},
      },
    },
    bin.pack(
      "CC>SACACA",
      0x48,
      0x01,
      0x1234,
      "nmapcoap",
      0xBB, ".well-known",
      0x04, "core"
    )
  },
}

for _, test in ipairs(tests) do
  local test_hdr = test[1]
  local test_str = test[2]

  -- Build the packet.
  local str = COAP.header.build(test_hdr)
  test_suite:add_test(unittest.equal(str, test_str))

  -- Parse, implicitly from the first character.
  local pos, hdr = COAP.header.parse(test_str)
  test_suite:add_test(unittest.identical(hdr, test_hdr))
  test_suite:add_test(unittest.equal(pos, #test_str + 1))

  -- Parse, explicitly from the zero-indexed first character.
  local pos, hdr = COAP.header.parse(test_str, 0)
  test_suite:add_test(unittest.identical(hdr, test_hdr))
  test_suite:add_test(unittest.equal(pos, #test_str + 1))

  -- Parse, explicitly from the one-indexed first character.
  local pos, hdr = COAP.header.parse(test_str, 1)
  test_suite:add_test(unittest.identical(hdr, test_hdr))
  test_suite:add_test(unittest.equal(pos, #test_str + 1))

  -- Parse, explicitly from the one-indexed second character.
  local pos, hdr = COAP.header.parse("!" .. test_str, 2)
  test_suite:add_test(unittest.identical(hdr, test_hdr))
  test_suite:add_test(unittest.equal(pos, #test_str + 2))
end

local tests = {
  {
    "application/link-format",
    "",
    "Failed to format payload."
  },
  {
    "application/link-format",
    "<>",
    "Failed to format payload."
  },
  {
    "application/link-format",
    "<>>",
    "Failed to format payload."
  },
  {
    "application/link-format",
    "<<>",
    {{["name"] = "<", ["parameters"] = {}}}
  },
  {
    "application/link-format",
    "<a>,<b>",
    {
      {["name"] = "a", ["parameters"] = {}},
      {["name"] = "b", ["parameters"] = {}},
    }
  },
  {
    "application/link-format",
    "<a>,<b>;param1=B1",
    {
      {["name"] = "a", ["parameters"] = {}},
      {
        ["name"] = "b",
        ["parameters"] = {
          {["name"] = "param1", ["value"] = 'B1'}
        }
      },
    }
  },
  {
    "application/link-format",
    "<a>,<b>;param1=B1,<c>;param2=C1;param3=C2",
    {
      {["name"] = "a", ["parameters"] = {}},
      {
        ["name"] = "b",
        ["parameters"] = {
          {["name"] = "param1", ["value"] = 'B1'}
        }
      },
      {
        ["name"] = "c",
        ["parameters"] = {
          {["name"] = "param2", ["value"] = 'C1'},
          {["name"] = "param3", ["value"] = 'C2'}
        }
      },
    }
  },
  {
    "application/link-format",
    '<a>,<b>;param1=B1,<c>;param2=C1;param3=C2,<d>;param4=";";param5=",";param6= ",<e>',
    {
      {["name"] = "a", ["parameters"] = {}},
      {
        ["name"] = "b",
        ["parameters"] = {
          {["name"] = "param1", ["value"] = 'B1'}
        }
      },
      {
        ["name"] = "c",
        ["parameters"] = {
          {["name"] = "param2", ["value"] = 'C1'},
          {["name"] = "param3", ["value"] = 'C2'}
        }
      },
      {
        ["name"] = "d",
        ["parameters"] = {
          {["name"] = "param4", ["value"] = ';'},
          {["name"] = "param5", ["value"] = ','},
          {["name"] = "param6", ["value"] = ' "'},
        }
      },
      {["name"] = "e", ["parameters"] = {}},
    }
  },
  {
    "application/json",
    '{}',
    {}
  },
  {
    "application/json",
    '{"a": false}',
    {["a"] = false}
  },
  {
    "application/json",
    '{"a": {"b": true}}',
    {["a"] = {["b"] = true}}
  },
  {
    "text/plain",
    "nmap",
    "nmap"
  },
  {
    "application/octet-stream",
    string.char(0x01, 0x23, 0x45, 0x56, 0x89, 0xAB, 0xCD, 0xEF),
    string.char(0x01, 0x23, 0x45, 0x56, 0x89, 0xAB, 0xCD, 0xEF),
  },
}

for _, test in ipairs(tests) do
  local test_fmt = test[1]
  local test_str = test[2]
  local test_res = test[3]

  local hdr = {
    ["options"] = {
      {
        ["name"] = "content_format",
        ["value"] = test_fmt
      }
    }
  }

  -- Parse, implicitly from the first character.
  local status, res = COAP.payload.parse(hdr, test_str)
  test_suite:add_test(unittest.identical(res, test_res))
end

return _ENV;
