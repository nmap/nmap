local math = require "math"
local unicode = require "unicode"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
_ENV = stdnse.module("codesys3", stdnse.seeall);

CodesysV3 = {
  ServiceIDs = {
    AddressServiceRequest = 0x01,
    AddressServiceResponse = 0x02,
    NameServiceRequest = 0x03,
    NameServiceResponse = 0x04,
    ChannelService = 0x40,
  },

  NameServicePackageTypes = {
    ResolveName = 0xc201,
    ResolveAddr = 0xc202,
    ResolveGateway = 0xc203,
    Identification = 0xc280,
  },

  -- The NameServiceRequest class contains functions to build a Codesys v3 Name Service Request as a broadcast
  NameServiceRequest = {

    -- Creates a new NameServiceRequest instance
    --
    -- @param portindex The codesys UDP port index
    -- @param interface The interface this broadcast will be sent on - needed for codesys address calculation
    -- @return o instance of request
    new = function(self, portindex, address, netmask_cidr)
      local o = {
        --- data needed for dynamic calculations of fields
        portindex = portindex,
        address = address,
        netmask_cidr = netmask_cidr,

        --- static header
        magic = 0xc5,
        hop_count = 0x0f,
        header_length = 0x4,  -- in 16 bit words

        priority = 0x01,
        signal = 0,
        address_type = 0, -- ABSOLUTE address for a broadcast
        data_length = 0,

        service_id = CodesysV3.ServiceIDs.NameServiceRequest,
        message_id = 0x00,
        broadcast_id = math.random(0xffff),
        
        --- payload
        package_type = CodesysV3.NameServicePackageTypes.ResolveAddr,
        version = 0x0400,
        request_id = math.random(math.pow(2, 32) - 1),
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the whole request to a string
    __tostring = function(self)
      -- Build the address information - this is specific to the UDP broadcast packets in the Codesys V3 protocol

      -- N bits for the address in our subnet, 2 bits for the port index, rounded up to a multiple of 16 bits
      local local_bits = 32 - self.netmask_cidr
      local port_bits = 2
      local codesys_net_addr_words = ((local_bits + port_bits) + 15) // 16

      -- We are broadcasting, so we don't have a receiver address, only our sender address
      -- From here on all the lengths for the address fields are handled in 16 bit words
      local sender_address_length = codesys_net_addr_words
      local receiver_address_length = 0

      -- Sanity check the address length fields - they need to be even (because they are in multiples of 16 bits) and need to fit in a 4 bit field
      assert(sender_address_length <= 0xF, "Sender address length too big to fit in the field")
      assert(receiver_address_length <= 0xF, "Receiver address length too big to fit in the field")

      local address_lengths = ((sender_address_length & 0xF) << 4) | (receiver_address_length & 0xF)

      -- mask off the local part of the address and add the port index in the front
      local my_address = ipOps.todword(self.address)
      local sender_address =  ((self.portindex & 3) << local_bits) | (my_address & ((1 << local_bits) - 1))

      -- Build a more or less static header for the packet including the length field for the sender and receiver address
      local packet_header = string.pack(">BBBBBBH",
        self.magic,
        ((self.hop_count & 0x1F) << 3) | (self.header_length & 7),
        ((self.priority & 3) << 6) | ((self.signal & 1) << 5) | ((self.address_type & 1) << 4) | (self.data_length & 0xF),
        self.service_id,
        self.message_id,
        address_lengths,
        self.broadcast_id
      )

      -- add the sender address to the packet
      for i=0, sender_address_length-1 do
        local j = sender_address_length - 1 - i;
        packet_header = packet_header .. string.pack(">H", (sender_address >> (16 * j)) & 0xFFFF)
      end

      -- pad the packet if necessary
      if ( #packet_header % 4 ~= 0 ) then
        packet_header = packet_header .. string.rep("\x00", #packet_header % 4)
      end

      stdnse.debug1("Sending codesys v3 name service broadcast packet with header: %s", stdnse.tohex(packet_header))

      -- append the name service request packet payload
      local packet_payload = string.pack("<HHI",
        0xc202,     -- Packet type - 0xC202 = Resolve Address
        0x0400,     -- Version - 0x0400 = Version 4.0
        0x04206969  -- "Randome" Request ID
      )

      stdnse.debug1("Payload of name service broadcast: %s", stdnse.tohex(packet_payload))

      return packet_header .. packet_payload
    end,

  },

  -- The NameServiceResponse class contains functions to parse a Codesys v3 Name Service Response
  NameServiceResponse = {
    -- Creates a new Response instance based on raw socket data
    --
    -- @param data string containing the raw socket response
    -- @return o Response instance
    new = function(self, data)
      local o = { data = data }

      if ( not(data) or #data < 6 ) then
        return false, "Response isn't long enough the be a Name Service Response"
      end

      local hopinfo, packetinfo, address_lengths, pos
      o.magic, hopinfo, packetinfo, o.service_id, o.message_id, address_lengths, pos = string.unpack(">BBBBBB", data)

      -- parse hopinfo field
      o.hop_count = hopinfo >> 3
      o.header_length = hopinfo & 7

      -- parse packetinfo field
      o.priority = packetinfo >> 6
      o.signal = (packetinfo >> 5) & 1
      o.address_type = (packetinfo >> 4) & 1
      o.data_length = packetinfo & 0xf

      -- sanity check a few fields to determine if this is a name service broadcast response
      if o.magic ~= 0xc5 or o.service_id ~= CodesysV3.ServiceIDs.NameServiceResponse then
        return false, "Response has the wring magic value or isn't a Name Service Response"
      end

      -- skip ahead to the address fields by skipping the length of the header
      pos = o.header_length * 2

      -- skip over the address fields using the address length fields in the header
      pos = pos + (address_lengths & 0xf) * 2
      pos = pos + (address_lengths >> 4) * 2

      -- skip the padding bytes if necessary
      if pos % 4 ~= 0 then
        pos = pos + (pos % 4)
      end

      -- lua strings are 1-indexed, so adjust the position pointer...
      pos = pos + 1
      
      -- at this point we are at the packet payload

      -- parse the payload header
      o.package_type, o.version, o.request_id, pos = string.unpack("<HHI", data, pos)

      
      -- check the package type we are expecting
      if o.package_type ~= CodesysV3.NameServicePackageTypes.Identification then
        return false, "The payload in the response isn't a Name Service Identification"
      end

      -- TODO: we should handle other versions than v4.00 as well
      if o.version ~= 0x0400 then
        return false, "The response contained a different version than v4.00 which we don't support right now"
      end

      stdnse.debug1("Received Codesys V3 Name Service Identification Response packet we can parse")

      -- FIMXE: Intel vs Motorola Byte Order - means: Little vs Big endian. Does endianness of fields in the
      --        packet later on have different endianness as well? Don't have a Big Endian device to test at hand

      -- Start parsing the PLC identification payload
      local parentAddrSize, nodeNameLength, deviceNameLength, vendorNameLength,
            serialNumberLength, oemDataLength

      o.maxChannels, o.intelByteOrder, o.addrDifference, parentAddrSize, pos = string.unpack("<I2 I1 I1 I2", data, pos)
      nodeNameLength, deviceNameLength, vendorNameLength, pos = string.unpack("<I2 I2 I2", data, pos)
      o.targetType, o.targetId, o.targetVersion, o.flags, pos = string.unpack("<I4 I4 I4 I4", data, pos)
      serialNumberLength, oemDataLength, o.blkDrvType, pos = string.unpack("<I1 I1 I1 x xxxx xxxx", data, pos)

      stdnse.debug1("Max Channels: %x - Intel Byte Order: %x - Parent Addr. Difference: %x - Parent Addr. Size: %x", o.maxChannels, o.intelByteOrder, o.addrDifference, parentAddrSize)
      stdnse.debug1("Node Name Length: %x - Device Name Length: %x - Vendor Name Length: %x", nodeNameLength, deviceNameLength, vendorNameLength)
      stdnse.debug1("Target Type: %x - Target ID: %x - Target Version: %x - Flags: %x", o.targetType, o.targetId, o.targetVersion, o.flags)
      stdnse.debug1("Serial Number Length: %x - OEM Data Length: %x - Block Driver Type: %x", serialNumberLength, oemDataLength, o.blkDrvType)

      -- following the structured data, comes variable length data with the sizes we just parsed
      -- following order should work: parent address, node name, device name, vendor name, serial number, OEM specific data

      o.addrParent = string.sub(data, pos, pos + parentAddrSize)
      pos = pos + parentAddrSize
      stdnse.debug1("Parent Address: %s", stdnse.tohex(o.addrParent))

      o.nodeName = string.sub(data, pos, pos + nodeNameLength*2 - 1)
      o.nodeName = unicode.utf16to8(o.nodeName)
      stdnse.debug1("Node Name: %s", o.nodeName)
      pos = pos + nodeNameLength*2 + 2

      o.deviceName = string.sub(data, pos, pos + deviceNameLength*2 - 1)
      o.deviceName = unicode.utf16to8(o.deviceName)
      stdnse.debug1("Device Name: %s", stdnse.tohex(o.deviceName))
      pos = pos + deviceNameLength*2 +2

      o.vendorName = string.sub(data, pos, pos + vendorNameLength*2 - 1)
      o.vendorName = unicode.utf16to8(o.vendorName)
      stdnse.debug1("Vendor Name: %s", stdnse.tohex(o.vendorName))
      pos = pos + vendorNameLength*2 + 2

      o.serialNumber = string.sub(data, pos, pos + serialNumberLength - 1)
      stdnse.debug1("Serial Number: %s", o.serialNumber)
      pos = pos + serialNumberLength + 1

      o.oemData = string.sub(data, pos, pos + oemDataLength)
      pos = pos + oemDataLength
      stdnse.debug1("OEM data: %s", stdnse.tohex(o.oemData))

      setmetatable(o, self)
      self.__index = self
      return true, o
    end,

  }
}

version_to_str = ipOps.fromdword

return _ENV
