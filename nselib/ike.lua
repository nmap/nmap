---
--A very basic IKE library.
--
--The current functionality includes:
--
--  1. Generating a Main or Aggressive Mode IKE request packet with a variable amount of transforms and a vpn group.
--  2. Sending a packet
--  3. Receiving the response
--  4. Parsing the response for VIDs
--  5. Searching for the VIDs in 'ike-fingerprints.lua'
--  6. returning a parsed info table
--
--This library is meant for extension, which could include:
--
--  1. complete parsing of the response packet (might allow for better fingerprinting)
--  2. adding more options to the request packet
--     vendor field (might give better fingerprinting of services, e.g. Checkpoint)
--  3. backoff pattern analyses
--
--An a implementation resembling 'ike-scan' could be built.
--
--@author Jesper Kueckelhahn
--@license Same as Nmap--See https://nmap.org/book/man-legal.html

local _G = require "_G"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local rand = require "rand"
_ENV = stdnse.module("ike", stdnse.seeall)

local ENC_METHODS = {
  ["des"]     = 0x80010001,
  ["3des"]    = 0x80010005,
  ["cast"]    = 0x80010006,
  ["aes/128"] = { 0x80010007, 0x800E0080 },
  ["aes/192"] = { 0x80010007, 0x800E00C0 },
  ["aes/256"] = { 0x80010007, 0x800E0100 },
}

local AUTH_TYPES = {
  ["psk"]    = 0x80030001,
  ["rsa"]    = 0x80030003,
  ["ECDSA"]  = 0x80030008,
  ["Hybrid"] = 0x8003FADD,
  ["XAUTH"]  = 0x8003FDE9,
}

local HASH_ALGORITHM = {
  ["md5"]      = 0x80020001,
  ["sha1"]     = 0x80020002,
  ["sha2-256"] = 0x80020004,
  ["sha2-384"] = 0x80020005,
  ["sha2-512"] = 0x80020006,
}

local GROUP_DESCRIPTION = {
  ["768"]  = 0x80040001,
  ["1024"] = 0x80040002,
  ["1536"] = 0x80040005,
  ["2048"] = 0x8004000E,
}

local EXCHANGE_MODE = {
  ["Main"]       = 0x02,
  ["Aggressive"] = 0x04,
}

local PROTOCOL_IDS = {
  ["tcp"] = 0x06,
  ["udp"] = 0x11,
}

-- Response packet types
local EXCHANGE_TYPE = {
  [0x02] = "Main",
  [0x04] = "Aggressive",
  [0x05] = "Informational",
}

-- Payload names
local PAYLOADS = {
  [0x00] = "None",
  [0x01] = "SA",
  [0x03] = "Transform",
  [0x04] = "Key Exchange",
  [0x05] = "ID",
  [0x08] = "Hash",
  [0x0A] = "Nonce",
  [0x0D] = "VID",
}


-- Load the fingerprint file
-- (located in: nselib/data/ike-fingerprints.lua)
--
local function load_fingerprints()
  local file, filename_full, fingerprints

  -- Check if fingerprints are cached
  if(nmap.registry.ike_fingerprints ~= nil) then
    stdnse.debug1("ike: Loading cached fingerprints")
    return nmap.registry.ike_fingerprints
  end

  -- Try and find the file
  -- If it isn't in Nmap's directories, take it as a direct path
  filename_full = nmap.fetchfile('nselib/data/ike-fingerprints.lua')

  -- Load the file
  stdnse.debug1("ike: Loading fingerprints: %s", filename_full)
  local env = setmetatable({fingerprints = {}}, {__index = _G});
  file = loadfile(filename_full, "t", env)
  if( not(file) ) then
    stdnse.debug1("ike: Couldn't load the file: %s", filename_full)
    return false, "Couldn't load fingerprint file: " .. filename_full
  end
  file()
  fingerprints = env.fingerprints

  -- Check there are fingerprints to use
  if(#fingerprints == 0 ) then
    return false, "No fingerprints were loaded after processing ".. filename_full
  end

  return true, fingerprints
end


-- Extract Payloads
local function extract_payloads(packet)

  -- packet only contains HDR
  if #packet < 29 then return {} end

  local np = packet:byte(17) -- next payload
  local np_txt = PAYLOADS[np]
  local index = 29 -- starting point for search
  local ike_headers = {} -- ike headers

  -- loop over packet
  while np_txt and np_txt ~= "None" and index <= #packet do
    local payload_length, payload
    np, payload_length, index = string.unpack(">B x I2", packet, index)
    payload, index = string.unpack("c" .. (payload_length - 4), packet, index)
    payload = stdnse.tohex(payload)

    -- debug
    if np_txt == 'VID' then
      stdnse.debug2('IKE: Found IKE Header: %s - %s', np_txt, payload)
    else
      stdnse.debug2('IKE: Found IKE Header: %s', np_txt)
    end

    -- Store payload
    if ike_headers[np_txt] == nil then
      ike_headers[np_txt] = {payload}
    else
      table.insert(ike_headers[np_txt], payload)
    end

    np_txt = PAYLOADS[np]
  end
  return ike_headers

end




-- Search the fingerprint database for matches
-- This is a (currently) divided into two parts
--    1) version detection based on single fingerprints
--    2) version detection based on the order of all vendor ids
--
--  NOTE: the second step currently only has support for CISCO devices
--
-- Input is a table of collected vendor-ids, output is a table
-- with fields:
--  vendor, version, name, attributes (table), guess (table), os
local function lookup(vendor_ids)
  if vendor_ids == {} or vendor_ids == nil then return {} end

  -- concat all vids to one string
  local all_vids = ''
  for _,vid in pairs(vendor_ids) do all_vids = all_vids .. vid end

  -- the results
  local info = {
    vendor = nil,
    attribs = {},
  }
  local unmatched = {}

  local status, fingerprints
  status, fingerprints = load_fingerprints()

  if status then

    -- loop over the vendor_ids returned in ike request
    for _,vendor_id in pairs(vendor_ids) do

      -- loop over the fingerprints found in database
      for _,row in pairs(fingerprints) do

        if vendor_id:find(row.fingerprint) then

          -- if a match is found, check if it's a version detection or attribute
          if row.category == 'vendor' then
            local debug_string = ''
            if row.vendor  ~= nil then debug_string = debug_string .. row.vendor .. ' ' end
            if row.version ~= nil then debug_string = debug_string .. row.version       end
            stdnse.debug2("IKE: Fingerprint: %s matches %s", vendor_id,  debug_string)

            -- Only store the first match
            if info.vendor == nil then
              -- the fingerprint contains information about the VID
              info.vendor = row
            end

          elseif row.category == 'attribute' then
            info.attribs[ #info.attribs + 1] = row
            stdnse.debug2("IKE: Attribute: %s matches %s", vendor_id, row.text)
            break
          end
        else
          unmatched[#unmatched+1] = vendor_id
        end
      end
    end
  end
  if next(unmatched) then
    info.unknown_ids = unmatched
  end


  ---------------------------------------------------
  -- Search for the order of the vids
  -- Uses category 'vid_ordering'
  ---

  -- search in the 'vid_ordering' category
  local debug_string = ''
  for _,row in pairs(fingerprints) do

    if row.category == 'vid_ordering' and all_vids:find(row.fingerprint) then

      -- Use ordering information if there where no vendor matches from previous step
      if info.vendor == nil then
        info.vendor = row

        -- Debugging info
        debug_string = ''
        if info.vendor.vendor  ~= nil then debug_string = debug_string .. info.vendor.vendor  .. ' ' end
        if info.vendor.version ~= nil then debug_string = debug_string .. info.vendor.version .. ' ' end
        if info.vendor.ostype  ~= nil then debug_string = debug_string .. info.vendor.ostype         end
        stdnse.debug2('IKE: No vendor match, but ordering match found: %s', debug_string)

        return info

      -- Update OS based on ordering
      elseif info.vendor.vendor == row.vendor then
        info.vendor.ostype = row.ostype

        -- Debugging info
        debug_string = ''
        if info.vendor.vendor ~= nil then debug_string = debug_string .. info.vendor.vendor  .. ' to ' end
        if row.ostype ~= nil then debug_string = debug_string .. row.ostype end
        stdnse.debug2('IKE: Vendor and ordering match. OS updated: %s', debug_string)

        return info

      -- Only print debugging information if conflicting information is detected
      else
        -- Debugging info
        debug_string = ''
        if info.vendor.vendor ~= nil then debug_string = debug_string .. info.vendor.vendor  .. ' vs ' end
        if row.vendor ~= nil then debug_string = debug_string .. row.vendor end
        stdnse.debug2('IKE: Found an ordering match, but vendors do not match. %s', debug_string)

      end
    end
  end

  return info
end


---
-- Handle a response packet
--
-- A very limited response parser.
-- Currently only the VIDs are extracted.
-- This could be made more advanced to
-- allow for fingerprinting via the order
-- of the returned headers
-- @param packet A received IKE packet
-- @return A table of parsed response values
function response(packet)
  local resp = { ["mode"] = "", ["info"] = nil, ['vids']={}, ['success'] = false }

  if #packet > 19 then

    -- extract the return type
    local resp_type = EXCHANGE_TYPE[packet:byte(19)]
    local ike_headers = {}

    -- simple check that the type is something other than 'Informational'
    -- as this type does not include VIDs
    if resp_type ~= "Informational" then
      resp["mode"] = resp_type

      ike_headers = extract_payloads(packet)

      -- Extract the VIDs
      resp['vids'] = ike_headers['VID']

      -- search for fingerprints
      resp["info"] = lookup(resp['vids'])

      -- indicate that a packet 'useful' packet was returned
      resp['success'] = true
    end
  end

  return resp
end


--- Send a request and parse the response
--
-- Sends an IKE request such as generated by <code>ike.request()</code>,
-- binding to the same source port as the destination port.
-- @param host Destination host
-- @param port Destination port (table)
-- @return Parsed IKE response (output of <code>ike.response()</code>)
function send_request( host, port, packet )

  local socket = nmap.new_socket()

  -- lock resource (port 500/udp)
  local mutex = nmap.mutex("ike_port_500");
  mutex "lock";

  -- send the request packet
  socket:set_timeout(1000)
  socket:bind(nil, port.number)
  socket:connect(host, port, "udp")
  local s_status = socket:send(packet)

  -- receive answer
  if s_status then
    local r_status, data = socket:receive_bytes(1)

    if r_status then
      socket:close()

      -- release mutex
      mutex "done";
      return response(data)
    else
      socket:close()
    end
  else
    socket:close()
  end

  -- release mutex
  mutex "done";

  return {}
end

-- Create the aggressive part of a packet
--  Aggressive mode includes the user-id, so the
--  length of this has to be taken into account
--
local function generate_aggressive(port, protocol, id, diffie)
  -- get length of key data based on diffie
  local key_length
  if diffie == 1 then
    key_length = 96
  elseif diffie == 2 then
    key_length = 128
  elseif diffie == 5 then
    key_length = 192
  end

  return (
    -- Key Exchange
    string.pack(">Bx I2",
      0x0a, -- Next payload (Nonce)
      key_length + 4) -- Length
    .. rand.random_string(key_length) -- Random key data

    -- Nonce
    .. string.pack(">Bx I2",
      0x05, -- Next payload (Identification)
      20 + 4) -- Length
    ..rand.random_string(20) -- Nonce data

    -- Identification
    .. string.pack(">Bx I2 BBI2",
      0x00, -- Next Payload (None)
      #id + 4 + 4, -- Payload length
      0x03, -- ID Type (USER_FQDN)
      PROTOCOL_IDS[protocol], -- Protocol ID (UDP)
      port) -- Port (500)
    .. id
    )
end


-- Create the transform
-- AES encryption needs an extra value to define the key length
-- Currently only DES, 3DES and AES encryption is supported
--
local function generate_transform(auth, encryption, hash, group, number, total)
  local key_length, trans_length, aes_enc, sep, enc
  local next_payload, payload_number

  -- handle special case of aes
  if encryption:sub(1,3) == "aes" then
    trans_length = 0x0028
    enc = ENC_METHODS[encryption][1]
    key_length = ENC_METHODS[encryption][2]
  else
    trans_length = 0x0024
    enc = ENC_METHODS[encryption]
    key_length = nil
  end

  -- check if there are more transforms
  if number == total then
    next_payload = 0x00 -- none
  else
    next_payload = 0x03 -- transform
  end

  -- set the payload number

  local trans = string.pack(">Bx I2 BB xx I4I4I4I4",
  next_payload, -- Next payload
  trans_length, -- Transform length
  number, -- Transform number
  0x01, -- Transform ID (IKE)
  enc, -- Encryption algorithm
  HASH_ALGORITHM[hash], -- Hash algorithm
  AUTH_TYPES[auth], -- Authentication method
  GROUP_DESCRIPTION[group]  -- Group Description
  )

  if key_length ~= nil then
    trans = trans .. string.pack(">I4", key_length) -- only set for aes
  end

  trans = trans .. string.pack(">I4I8",
  0x800b0001, -- Life type (seconds)
  0x000c000400007080 -- Life duration (28800)
  )

  return trans
end


-- Generate multiple transforms
-- Input must be a table of complete transforms
--
local function generate_transforms(transform_table)
  local transforms = ''

  for i,t in pairs(transform_table) do
    transforms = transforms .. generate_transform(t.auth, t.encryption, t.hash, t.group, i, #transform_table)
  end

  return transforms
end


--- Create a request packet
--
-- Support for multiple transforms, which minimizes the
-- the amount of traffic/packets needed to be sent
-- @param port Associated port number
-- @param proto Associated protocol
-- @param mode "Aggressive" or "Main"
-- @param transforms Table of IKE transforms
-- @param diffie DH group number
-- @param id Identification data
-- @return IKE request datagram
function request(port, proto, mode, transforms, diffie, id)
  local payload_after_sa, str_aggressive, l, l_sa, l_pro

  local transform_string = generate_transforms(transforms)

  -- check for aggressive vs Main mode
  if mode == "Aggressive" then
    str_aggressive = generate_aggressive(port, proto, id, diffie)
    payload_after_sa = 0x04
  else
    str_aggressive = ""
    payload_after_sa = 0x00
  end


  -- calculate lengths
  l = 48 + transform_string:len() + str_aggressive:len()
  l_sa = 20 + transform_string:len()
  l_pro = 8 + transform_string:len()

  -- Build the packet
  local packet =
    rand.random_string(8) -- Initiator cookie
    .. ("\0"):rep(8) -- Responder cookie
  .. string.pack(">BBBBI4I4 BxI2I4I4 BxI2BBBB",
    0x01, -- Next payload (SA)
    0x10, -- Version
    EXCHANGE_MODE[mode], -- Exchange type
    0x00, -- Flags
    0x00000000, -- Message id
    l, -- packet length


    -- Security Association
    payload_after_sa, -- Next payload (Key exchange, if aggressive mode)
    l_sa, -- Length
    0x00000001, -- IPSEC
    0x00000001, -- Situation

    --## Proposal
    0x00, -- Next payload (None)
    l_pro, -- Payload length
    0x01, -- Proposal number
    0x01, -- Protocol ID (ISAKMP)
    0x00, -- SPI Size
    #transforms -- Proposal transforms
  )

  packet = packet .. transform_string -- transform

  if mode == 'Aggressive' then
    packet = packet .. str_aggressive
  end

  return packet
end


return _ENV
