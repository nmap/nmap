---Implements decoders and encoders for IEC-61850-8-1 MMS queries
--
-- References:
-- * https://en.wikipedia.org/wiki/IEC_61850
-- * https://datatracker.ietf.org/doc/html/rfc1006
--
-- @author Dennis Rösch
-- @author Max Helbig
-- @license Same as Nmap--See https://nmap.org/book/man-legal.html
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local asn1 = require "asn1"
local math = require "math"

_ENV = stdnse.module("iec61850mms", stdnse.seeall)

local function stringToHex(str)
  return "\\x" .. stdnse.tohex(str, {separator = "\\x"})
end

MMSDecoder = {

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  unpackmmsFromTPKT = function(self, tpktStr)
    -- unpack TPKT and COTP
    local TPKT_pos = 1
    local COTP_pos = 5
    local COTP_last = false
    local TPKT_ver, TPKT_res, TPKT_len
    local COTP_len, COTP_type, COTP_tpdu
    local OSI_Session = {}

    while not COTP_last do
      TPKT_ver, TPKT_res, TPKT_len = string.unpack("i1c1>i2", tpktStr, TPKT_pos)
      COTP_len, COTP_type, COTP_tpdu = string.unpack("i1c1c1", tpktStr, COTP_pos)
      COTP_last = COTP_tpdu == "\x80"

      OSI_Session[#OSI_Session+1] = string.sub(tpktStr, TPKT_pos + 7, TPKT_pos + TPKT_len - 1)


      if not COTP_last then
        TPKT_pos = TPKT_pos + TPKT_len
        COTP_pos = TPKT_pos + 4
      end
    end
    OSI_Session = table.concat(OSI_Session)


    local newpos = 5 -- start of ISO 8823
    local type, len, dummy

    -- ISO 8823 OSI
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\x61" then
      stdnse.debug(1,"not ISO 8823 OSI type is %s: ", stringToHex(type))
      return nil
    end
    len, newpos = self.decodeLength(OSI_Session, newpos)

    -- presentation-context-identifier
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\x30" then
      stdnse.debug(1,"not presentation-context-identifier type is %s: ", stringToHex(type))
      return nil
    end
    len, newpos = self.decodeLength(OSI_Session, newpos)

    -- fully-encoded-data
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\x02" then
      stdnse.debug(1,"not fully-encoded-data type is %s: ", stringToHex(type))
      return nil
    end
    len, newpos = self.decodeLength(OSI_Session, newpos)
    dummy, newpos = self.decodeInt(OSI_Session, len, newpos)

    -- single-ASN1-type
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\xa0" then
      stdnse.debug(1,"not single-ASN1-type type is %s: ", stringToHex(type))
      return nil
    end
    len, newpos = self.decodeLength(OSI_Session, newpos)



    return string.sub(OSI_Session, newpos)
  end,

  unpackAndDecode = function(self, tpktStr)
    local mmsStr = self.unpackmmsFromTPKT(self, tpktStr)
    if not mmsStr then
      stdnse.debug(1, "mmsString is nil")
      return nil
    end
    return(self.mmsPDU(self, mmsStr))
  end,

  mmsPDU = function(self, mmsStr)
    local CHOICE = {
      ["\xa0"] = "confirmed_RequestPDU",
      ["\xa1"] = "confirmed_ResponsePDU",
      ["\xa8"] = "initiate_RequestPDU",
    }

    local PDUType, PDUlen
    local newpos = 1

    PDUType, newpos = string.unpack("c1", mmsStr, newpos)
    PDUlen, newpos = self.decodeLength(mmsStr, newpos)

    local retval
    if CHOICE[PDUType] then
      retval =  self[CHOICE[PDUType]](self, mmsStr, PDUlen, newpos)
    else
      stdnse.debug(1,"mmsPDU: no option for type %s", stringToHex(PDUType))
      retval, newpos = self.unknown(self, mmsStr, PDUlen, newpos)
      return retval
    end

    return {[CHOICE[PDUType]] = retval}
  end,

  confirmed_RequestPDU = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- invokeID
    if type ~= "\x02" then
      stdnse.debug(1,"no invokeID in RequestPDU")
      return nil
    end

    local invokeID
    invokeID, newpos = self.decodeInt(str, len, newpos)

    -- service
    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {
      ["\xa4"] = "Read_Request"
    }

    local confirmedServiceRequest
    if CHOICE[type] then
      confirmedServiceRequest =  self[CHOICE[type]](self, str, len, newpos)
    else
      stdnse.debug(1,"unknown confirmedServiceRequest")
      confirmedServiceRequest = nil
    end

    -- bulid return value
    local tab = {
      ["invokeID"] = invokeID,
      [CHOICE[type]] = confirmedServiceRequest,
    }

    local retpos = pos + elen
    return tab, retpos
  end,

  confirmed_ResponsePDU = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- invokeID
    if type ~= "\x02" then
      stdnse.debug(1,"no invokeID")
      return nil
    end

    local invokeID
    invokeID, newpos = self.decodeInt(str, len, newpos)

    -- service
    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {
      ["\xa1"] = "getNameList",
      ["\xa2"] = "identify",
      ["\xa4"] = "Read_Response",
    }

    local confirmedServiceResponse
    if CHOICE[type] then
      confirmedServiceResponse =  self[CHOICE[type]](self, str, len, newpos)
    else
      stdnse.debug(1,"unknown confirmedServiceResponse")
      confirmedServiceResponse = nil
    end

    -- bulid return value
    local tab = {
      ["invokeID"] = invokeID,
      [CHOICE[type]] = confirmedServiceResponse,
    }

    local retpos = pos + elen
    return tab, pos + elen
  end,

  identify = function(self, str, elen, pos)
    local CHOICE = {
      ["\x80"] = "vendorName",
      ["\x81"] = "modelName",
      ["\x82"] = "revision",
    }

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      local type, len
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.decodeStr( str, len, newpos)
      sNum = sNum + 1
      seq[CHOICE[type]] = sValue
    end

    return seq, pos + elen
  end,

  getNameList = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- listofidentifier
    if type ~= "\xa0" then
      stdnse.debug(1,"no list of identifier")
      return nil
    end

    local idvlist
    idvlist, newpos = self.listOfIdentifier(self, str, len, newpos)
    local tab = {
      ["listOfIdentifier"] = idvlist
    }

    if pos+elen-newpos == 3 then
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      local morefollows
      morefollows, newpos = self.decodeBool(str, len, newpos)
      tab["moreFollows"] = morefollows
    else
      tab["moreFollows"] = true
    end

    return tab, pos + elen
  end,

  listOfIdentifier = function(self, str, elen, pos)
    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      local type, len
      type, newpos = string.unpack("c1", str, newpos)
      if type ~= "\x1a" then
        stdnse.debug(1,"no identifier type")
      end

      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.decodeStr( str, len, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)

    end

    return seq, pos + elen
  end,

  initiate_RequestPDU = function(self, str, elen, pos)
    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos
    local CHOICE = {} -- Submitted with no values.

    while (newpos < pos + elen) do
      local type, len
      type, newpos = string.unpack("c1", str, newpos)
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for %s", stringToHex(type))
      end
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self[CHOICE[type]](self, str, len, newpos)
      sNum = sNum + 1
      seq[CHOICE[type]] = sValue
    end

    return seq, pos + elen
  end,

  localDetailCalling = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  proposedMaxServOutstandingCalling = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  proposedMaxServOutstandingCalled = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  proposedDataStructureNestingLevel = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  initRequestDetail = function(self, str, elen, pos)
    local CHOICE = {
      ["\x80"] = "proposedVersionNumber",
      ["\x81"] = "parameterSupportOptions",
      ["\x82"] = "servicesSupportedCalling",
    }

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      local type, len
      type, newpos = string.unpack("c1", str, newpos)
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for %s", stringToHex(type))
      end
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self[CHOICE[type]](self, str, len, newpos)
      sNum = sNum + 1
      seq[CHOICE[type]] = sValue
    end

    return seq, pos + elen
  end,

  parameterSupportOptions = function(self, str, elen, pos)
    local NAMES = {
      "array support",
      "structure support",
      "named variable support",
      "structure support",
      "alternate access support",
      "unnamed variable support",
      "scattered access support",
      "third party operations support",
      "named variable list support",
      "condition event support"
    }

    return self.bit_string(self, str, elen, pos, NAMES)
  end,

  proposedVersionNumber = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  Read_Response = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- listOfAccessResult
    local listOfAccessResult
    if type ~= "\xa1" then
      stdnse.debug(1,"no listOfAccessResult")
      return nil, pos + elen
    end

    listOfAccessResult, newpos = self.listOfAccessResult(self, str, len, newpos)

    -- bulid return value
    local tab = {
      ["listOfAccessResult"] = listOfAccessResult
    }
    return tab, pos + elen
  end,

  Read_Request = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local specificationWithResult
    if type ~= "\x80" then
      stdnse.debug(1,"no specificationWithResult")
      specificationWithResult = nil
    end
    specificationWithResult, newpos = self.decodeBool(str, len, newpos)

    -- variableAccessSpecification
    local variableAccessSpecification
    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)
    if type ~= "\xa1" then
      stdnse.debug(1,"no variableAccessSpecification")
      return nil, pos + elen
    end

    variableAccessSpecification, newpos = self.variableAccessSpecification(self, str, len, newpos)

    -- bulid return value
    local tab = {
      ["specificationWithResult"] = specificationWithResult,
      ["variableAccessSpecification"] = variableAccessSpecification,
    }

    local retpos = pos + elen
    return tab, retpos
  end,

  listOfAccessResult = function(self, str, elen, pos)
    local newpos = pos

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue

    while (newpos < pos + elen) do
      local type, len
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.accessResult(self, str, len, newpos, type)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  accessResult = function(self, str, elen, pos, type)
    local CHOICE = {
      ["\xa2"] = "structure",
      ["\x80"] = "dataAccessError",
      ["\x83"] = "bool",
      ["\x84"] = "bit_string",
      ["\x85"] = "integer",
      ["\x86"] = "unsigned",
      ["\x89"] = "octet_string",
      ["\x8a"] = "string",
      ["\x8c"] = "binaryTime",
      ["\x91"] = "utc_Time",
    }

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    if elen == 0 and CHOICE[type] == "string" then
      table.insert(seq, "")
    end

    while (newpos < pos + elen) do
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for", stringToHex(type))
      end
      sValue, newpos = self[CHOICE[type]](self, str, elen, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  dataAccessError = function(self, str, elen, pos)
    local CHOICE = {
      ["\x00"] = "object-invalidated",
      ["\x01"] = "hardware-fault",
      ["\x02"] = "temporarily-unavalible",
      ["\x03"] = "object-access-denied",
      ["\x04"] = "object-undefined",
      ["\x05"] = "invalid-address",
      ["\x06"] = "type-unsupported",
      ["\x07"] = "type-inconsistent",
      ["\x08"] = "object-attribute-inconsistent",
      ["\x09"] = "object-access-unsupported",
      ["\x0a"] = "object-non-existent",
      ["\x0b"] = "object-value-invalid",
    }

    local num, newpos = string.unpack("c" .. elen, str, pos)
    local retval = "DataAccessError: " .. CHOICE[num]
    return retval, pos + elen
  end,

  structure = function(self, str, elen, pos)
    local CHOICE = {
      ["\xa2"] = "structure",
      ["\x83"] = "bool",
      ["\x84"] = "bit_string",
      ["\x85"] = "integer",
      ["\x86"] = "unsigned",
      ["\x89"] = "octet_string",
      ["\x8a"] = "string",
      ["\x8c"] = "binaryTime",
      ["\x91"] = "utc_Time",
    }

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      local type, len
      type, newpos = string.unpack("c1", str, newpos)
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for", stringToHex(type))
      end
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self[CHOICE[type]](self, str, len, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  bool = function(self, str, elen, pos)
    return "TODO: bool", pos + elen
  end,

  bit_string = function(self, str, elen, pos, names)
    local padding, newpos = self.decodeInt(str, 1, pos)

    return "TODO: bit_string", pos + elen
  end,

  integer = function(self, str, elen, pos)
    return self.decodeInt(str, elen, pos)
  end,

  unsigned = function(self, str, elen, pos)
    return "TODO: unsigned", pos + elen
  end,

  octet_string = function(self, str, elen, pos)
    return "TODO: string", pos + elen
  end,

  string = function(self, str, elen, pos)
    return string.unpack("c" .. elen, str, pos)
  end,

  binaryTime = function(self, str, elen, pos)
    return "TODO: string", pos + elen
  end,

  utc_Time= function(self, str, elen, pos)
    return "TODO: utc_Time", pos + elen
  end,

  unknown = function(self, str, elen, pos)
    local hex = stringToHex(str)
    stdnse.debug(1,"Decoder: got an unknown Type")
    stdnse.debug(1,"embedded String in hex:\n", hex)
    stdnse.debug(1,"length of string given to coder: ", #str)
    stdnse.debug(1,"Current position of coder: ", pos)

    return str
  end,

  variableAccessSpecification = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local listOfVariable
    if type ~= "\xa0" then
      stdnse.debug(1,"no listOfVariable")
      listOfVariable = nil
    end
    listOfVariable, newpos = self.listOfVariable(self, str, len, newpos)

    local tab = {
      ["listOfVariable"] = listOfVariable
    }

    return tab, pos + elen
  end,

  listOfVariable = function(self, str, elen, pos)
    local newpos = pos

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue

    while (newpos < pos + elen) do
      local type, len
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.variableSpecification(self, str, len, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  variableSpecification = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {
      ["\xa0"] = "objectName"
    }


    local retval
    if CHOICE[type] then
      retval =  self[CHOICE[type]](self, str, len, newpos)
    else
      retval = nil
    end

    local tab = {
      [CHOICE[type]] = retval
    }
    return tab, pos + elen
  end,

  objectName = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {
      ["\xa1"] = "domain_specific"
    }

    local retval
    if CHOICE[type] then
      retval =  self[CHOICE[type]](self, str, len, newpos)
    else
      retval = nil
    end

    local tab = {
      [CHOICE[type]] = retval
    }
    return tab, pos + elen
  end,

  domain_specific = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local domainID, itemID
    domainID, newpos = self.decodeStr(str, len, newpos)

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    itemID, newpos = self.decodeStr(str, len, newpos)

    local tab = {
      ["domainID"] = domainID,
      ["itemID"] = itemID,
    }

    return tab, pos + elen
  end,

  decodeLength = asn1.ASN1Decoder.decodeLength,

  decodeInt = asn1.ASN1Decoder.decodeInt,

  decodeBool = function( str, elen, pos )
    local val = string.byte(str, pos)
    return val ~= 0, pos + 1
  end,

  decodeStr = function(encStr, elen, pos )
    return string.unpack("c" .. elen, encStr, pos)
  end
}

MMSEncoder = {

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  packmmsInTPKT = function(self, mmsStr)
    local sendstr = mmsStr
    sendstr = "\xa0"..self.encodeLength(#sendstr)..sendstr
    sendstr = "\x02\x01\x03"..sendstr
    sendstr = self.encodeSeq(sendstr)
    sendstr = "\x61"..self.encodeLength(#sendstr)..sendstr --ISO8823
    sendstr = "\x01\x00\x01\x00"..sendstr                  --ISO8327 2x
    sendstr = "\x02\xf0\x80"..sendstr                      --ISO8073
    local final_len = #sendstr+4
    sendstr = "\x03\x00"..string.char(math.floor(final_len / 256), final_len % 256)..sendstr
    return sendstr
  end,

  encodeAndPack = function(self, mmsTab)
    local mmsStr = self.mmsPDU(self, mmsTab)
    return self.packmmsInTPKT(self, mmsStr)
  end,

  mmsPDU = function(self, message)
    local CHOICE = {
      ["confirmed_RequestPDU"] = "\xa0",
      ["confirmed_ResponsePDU"] = "\xa1",
    }

    local type = type(message)

    if type ~= 'table' then
      stdnse.print_debug(1,"mmsPDU: must be a table")
      return nil
    end

    if self.tabElementCount(message) ~= 1 then
      stdnse.print_debug(1,"mmsPDU: table muss have exactly one element")
      return nil
    end

    local key, val = next(message)
    if not CHOICE[key] then
      stdnse.print_debug(1,"mmsPDU: no PDU type ", key)
      return nil
    end

    local pdustr = self[key](self, message[key])
    local retstr = CHOICE[key].. self.encodeLength(#pdustr) .. pdustr
    return retstr

  end,

  confirmed_RequestPDU = function(self, message)
    local CHOICE = {
      ["Read_Request"] = "\xa4",
      ["getNameList"] = "\xa1",
    }

    if type(message) ~= 'table' then
      stdnse.print_debug(1,"confirmed_RequestPDU: must be a table")
      return ""
    end

    local tablen = self.tabElementCount(message)
    if tablen < 2 or tablen > 4 then
      stdnse.print_debug(1,"confirmed_RequestPDU: table must have between 2 and 4 elements")
      return ""
    end

    if not message["invokeID"] then
      stdnse.print_debug(1,"confirmed_RequestPDU: message must contain invokeID ")
      return ""
    end

    local confServReqKey = self.tabContainsKeyOfTab(message, CHOICE)
    if not confServReqKey then
      stdnse.print_debug(1,"confirmed_RequestPDU: message must contain confirmedServiceRequest")
      return ""
    end

    local invokeID = self.encodeInt(message["invokeID"])
    local retstr = "\x02" .. self.encodeLength(#invokeID) .. invokeID

    local confirmedServiceRequest = self[confServReqKey](self, message[confServReqKey])
    retstr = retstr .. CHOICE[confServReqKey] .. self.encodeLength(#confirmedServiceRequest) .. confirmedServiceRequest

    return retstr
  end,

  getNameList = function(self, message)
    if type(message) ~= 'table' then
      stdnse.debug(1,"getNameList: must be a table")
      return ""
    end

    if message["objectClass"] == nil then
      stdnse.debug(1,"getNameList: message must contain objectClass")
      return ""
    end

    local oC = self.objectClass(self, message["objectClass"])
    local retstr = "\xa0" .. self.encodeLength(#oC) .. oC

    if message["objectScope"] == nil then
      stdnse.debug(1,"getNameList: message must contain objectScope")
      return ""
    end

    local oS = self.objectScope(self, message["objectScope"])
    retstr = retstr .. "\xa1" .. self.encodeLength(#oS) .. oS

    if message["continueAfter"] ~= nil then
      local continueAfter = self.encodeStr(message["continueAfter"])
      retstr = retstr .. "\x82" .. self.encodeLength(#continueAfter) .. continueAfter
    end

    return retstr
  end,

  objectClass = function(self, message)
    if type(message) ~= 'string' then
      stdnse.debug(1,"objectClass: must be a String")
      return ""
    end

    local CHOICE = {
      ["namedVariable"] = 0,
      ["domain"] = 9,
    }

    if CHOICE[message] == nil then
      stdnse.debug(1,"objectClass: message not valid")
      return ""
    end
    local res = self.encodeInt(CHOICE[message])
    local retstr = "\x80" .. self.encodeLength(#res) .. res

    return retstr
  end,

  objectScope = function(self, message)
    if type(message) ~= 'table' then
      stdnse.debug(1,"objectScope: must be a table")
      return ""
    end

    local tablen = self.tabElementCount(message)
    if tablen ~= 1 then
      stdnse.print_debug(1,"objectScope: table must have 1 element")
      return ""
    end

    local CHOICE = {
      ["vmdSpecific"] = "\x80",
      ["domainSpecific"] = "\x81",
    }

    local Key = self.tabContainsKeyOfTab(message, CHOICE)
    if not Key then
      stdnse.print_debug(1,"objectScope: message must contain valid element")
      return ""
    end

    local res = self[Key](self, message[Key])
    local retstr = CHOICE[Key] .. self.encodeLength(#res) .. res

    return retstr
  end,

  domainSpecific = function(self, message)
    return self.encodeStr(message)
  end,

  vmdSpecific = function(self, message)
    return ""
  end,

  Read_Request = function(self, message)
    local type = type(message)

    if type ~= 'table' then
      stdnse.print_debug(1,"Read_Request: must be a table")
      return ""
    end

    local tablen = self.tabElementCount(message)
    if tablen ~= 2  then
      stdnse.print_debug(1,"Read_Request: table must have 2 elements")
      return ""
    end

    if message["specificationWithResult"] == nil then
      stdnse.print_debug(1,"Read_Request: message must contain specificationWithResult")
      return ""
    end

    if message["variableAccessSpecification"] == nil then
      stdnse.print_debug(1,"Read_Request: message must contain variableAccessSpecification")
      return ""
    end

    local specificationWithResult = self.encodeBool(message["specificationWithResult"])
    local retstr = "\x80" .. self.encodeLength(#specificationWithResult) .. specificationWithResult

    local variableAccessSpecification = self.variableAccessSpecification(self, message["variableAccessSpecification"] )
    retstr = retstr .. "\xa1" .. self.encodeLength(#variableAccessSpecification) .. variableAccessSpecification

    return retstr
  end,

  variableAccessSpecification = function(self, message)
    local type = type(message)

    if type ~= 'table' then
      stdnse.print_debug(1,"variableAccessSpecification: must be a table")
      return ""
    end

    local tablen = self.tabElementCount(message)
    if tablen ~= 1  then
      stdnse.print_debug(1,"variableAccessSpecification: table must have 1 element")
      return ""
    end

    if message["listOfVariable"] == nil then
      stdnse.print_debug(1,"variableAccessSpecification: message must contain listOfVariable")
      return ""
    end
    local listOfVariable = self.listOfVariable(self, message["listOfVariable"])
    local retstr = "\xa0" .. self.encodeLength(#listOfVariable) .. listOfVariable

    return retstr
  end,

  listOfVariable = function(self, message)
    local type = type(message)

    if type ~= 'table' then
      stdnse.print_debug(1,"listOfVariable: must be a table")
      return ""
    end

    local retstr = {}
    local value
    for k, v in pairs(message) do
      value = self.variableSpecification(self, v)
      retstr[#retstr+1] = self.encodeSeq(value)
    end

    return table.concat(retstr)
  end,

  variableSpecification = function (self, message)
    local CHOICE = {
      ["objectName"] = "\xa0",
    }

    local type = type(message)

    if type ~= 'table' then
      stdnse.print_debug(1,"variableSpecification: must be a table")
      return ""
    end

    local tablen = self.tabElementCount(message)
    if tablen ~= 1  then
      stdnse.print_debug(1,"variableSpecification: table must have 1 element")
      return ""
    end

    local varSpec = self.tabContainsKeyOfTab(message, CHOICE)
    if not varSpec then
      stdnse.print_debug(1,"variableSpecification: message must contain variableSpecification")
      return ""
    end

    local specstr = self[varSpec](self, message[varSpec])
    local retstr = CHOICE[varSpec] .. self.encodeLength(#specstr) .. specstr

    return retstr
  end,

  objectName = function (self, message)
    local CHOICE = {
      ["vmd_specific"] = "\xa0",
      ["domain_specific"] = "\xa1",
      ["aa_specific"] = "\xa2",
    }

    local type = type(message)

    if type ~= 'table' then
      stdnse.print_debug(1,"objectName: must be a table")
      return ""
    end

    local tablen = self.tabElementCount(message)
    if tablen ~= 1  then
      stdnse.print_debug(1,"objectName: table must have 1 element")
      return ""
    end

    local key = self.tabContainsKeyOfTab(message, CHOICE)
    if not key then
      stdnse.print_debug(1,"objectName: must contain objectName")
      return ""
    end

    local value = self[key](self, message[key])
    local retstr = CHOICE[key] .. self.encodeLength(#value) .. value
    return retstr
  end,

  domain_specific = function(self, message)
    local type = type(message)

    if type ~= 'table' then
      stdnse.print_debug(1,"domain_specific: must be a table")
      return ""
    end

    local tablen = self.tabElementCount(message)
    if tablen ~= 2  then
      stdnse.print_debug(1,"objectName: table must have 2 elements")
      return ""
    end

    if message["domainID"] == nil then
      stdnse.print_debug(1,"domain_specific: message must contain domainID")
      return ""
    end

    if message["itemID"] == nil then
      stdnse.print_debug(1,"domain_specific: message must contain itemID")
      return ""
    end

    local retstr = ""
    local valstr

    valstr = self.encodeStr(message["domainID"])
    retstr = retstr .. "\x1a" .. self.encodeLength(#valstr) .. valstr

    valstr = self.encodeStr(message["itemID"])
    retstr = retstr .. "\x1a" .. self.encodeLength(#valstr) .. valstr

    return retstr
  end,

  tabContainsKeyOfTab = function(tab, source)
    local retval = nil
    for key, val in pairs(source) do
      if tab[key] then
        retval = key
        break
      end
    end
    return retval
  end,

  tabElementCount = function(tab)
    local count = 0
    for _ in pairs(tab) do count = count + 1 end
    return count
  end,

  encodeLength = asn1.ASN1Encoder.encodeLength,

  encodeInt = asn1.ASN1Encoder.encodeInt,

  encodeBool = function(val)
    if val then
      return '\xFF'
    else
      return '\x00'
    end
  end,

  encodeStr = function(str)
    return str
  end,

  encodeSeq = asn1.ASN1Encoder.encodeSeq,
}

MMSQueries = {
  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  askfor = function(self, invokeID, domainID, itemIDs)
    local iIdType = type(itemIDs)

    -- make table if we got a single value
    if type(itemIDs) ~= 'table' then
      itemIDs = {itemIDs}
    end

    -- check if all elements are strings
    for _, value in pairs(itemIDs) do
      if type(value) ~= 'string' then
        stdnse.print_debug(1,"All itemIDs must be strings!")
        return nil
      end
    end

    --create structure
    local tab = {}
    for k, v in pairs(itemIDs) do
      local objName = {objectName = {domain_specific = {itemID = v, domainID = domainID}}}
      table.insert(tab, objName)
    end
    local rr = {
      variableAccessSpecification = {listOfVariable = tab},
      specificationWithResult = false
    }

    local structure = {confirmed_RequestPDU = { Read_Request = rr, invokeID = invokeID}}

    -- encode and return
    local encoder = MMSEncoder:new()
    local result = encoder:mmsPDU(structure)
    return result
  end,

  nameList = function(self, invokeID, objectScope, continueAfter)
    if invokeID == nil then
      stdnse.debug(1, "no invokeID setting to 1")
      invokeID = 1
    end

    local oC
    local oS
    if objectScope == nil then
      oC = "domain"
      oS = {vmdSpecific = ""}
    else
      oC = "namedVariable"
      oS = {domainSpecific = objectScope}
    end
    local cA = continueAfter


    local cSR = {objectClass = oC, objectScope = oS}
    if cA ~= nil and cA ~= "" then
      cSR["continueAfter"] = cA
    end
    local structure = {confirmed_RequestPDU = { getNameList = cSR, invokeID = invokeID}}
    return structure
  end
}

return _ENV;
