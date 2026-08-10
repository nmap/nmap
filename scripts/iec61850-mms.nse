local iec61850mms = require "iec61850mms"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries a IEC 61850-8-1 MMS server. Sends Initate-Request, Identify-Request and Read-Request to LN0 and LPHD.

Output contains following attributes:

* modelName_identify:   Identify-Response attribute model_name
* vendorName_identify:  Identify-Response attribute vendor_name
* modelNumber_identify: Identify-Response attribute revision
* productFamily:        Read-Response attribute 'LLN0$DC$NamPlt$d'
* configuration:        Read-Response attribute 'LLN0$DC$NamPlt$configRev'
* vendorName:           Read-Response attribute 'LPHD$DC$PhyNam$vendor' (old: 'LLN0$DC$NamPlt$vendor')
* serialNumber:         Read-Response attribute 'LPHD$DC$PhyNam$serNum'
* modelNumber:          Read-Response attribute 'LPHD$DC$PhyNam$model'
* firmwareVersion:      Read-Response attribute 'LPHD$DC$PhyNam$swRev' (old: 'LLN0$DC$NamPlt$swRev')
]]

---
-- @usage
-- nmap --script iec61850-mms.nse -p 102 <target>
--

---
-- @output
-- 102/tcp open  iso-tsap
--|	iec61850_mms.nse:
--|   modelName_identify: MMS-LITE-80X-001
--|   productFamily: High End Meter
--|   vendorName: Schneider Electric
--|   vendorName_identify: SISCO
--|   serialNumber: ME-1810A424-02
--|   modelNumber: 8000
--|   modelNumber_identify: 6.0000.3
--|   firmwareVersion: 001.004.003
--|_  configuration: 2022-08-19 08:27:20


author = "Dennis Rösch, Max Helbig"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive", "version"}

-- Helpers
function replaceEmptyStrings(tbl)
  for key, value in pairs(tbl) do
    if type(value) == "table" then
      replaceEmptyStrings(value)
    elseif type(value) == "string" and value == "" then
      tbl[key] = "<EMPTY_STRING>"
    end
  end
end

function searchTable(searchString, myTable)
  local matches = {}
  local uniqueEntries = {}
  local extractedPart
  for i, entry in ipairs(myTable) do
    if string.find(entry, searchString) then
      local dollarIndex = string.find(entry, "%$")
      if not dollarIndex then
        extractedPart = entry
      else
        extractedPart = string.sub(entry, 1, dollarIndex - 1)
      end
      if not uniqueEntries[extractedPart] then
        uniqueEntries[extractedPart] = true
        table.insert(matches, extractedPart)
      end
    end
  end
  return matches
end

-- Rules
portrule = shortport.portnumber(102, "iso-tsap")

-- Actions
action = function(host, port)
  local timeout = 500

  local status, recv
  local output = {}
  local socket = nmap.new_socket()

  local decoder = iec61850mms.MMSDecoder:new()
  local encoder = iec61850mms.MMSEncoder:new()
  local query = iec61850mms.MMSQueries:new()

  socket:set_timeout(timeout)

  stdnse.debug(2, "Connecting to host")
  status, recv = socket:connect(host, port, "tcp")
  if not status then
    return nil
  end
  stdnse.debug(2, "Connected")

  stdnse.debug(2, "Sending CR_TPDU")
  local CR_TPDU = "\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x00\x00\xc2\x02\x00\x01\xc0\x01\x0a"
  status = socket:send( CR_TPDU )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(1024)
  stdnse.debug(2, "Response recieved")
  stdnse.debug(3, "cr_tpdu: %s", stdnse.tohex(recv) )


  local MMS_INITIATE = "\x03\x00\x00\xd3\x02\xf0\x80\x0d\xca\x05\x06\x13\x01\x00\x16\x01\x02\x14\x02\x00\x02\x33\x02" ..
  "\x00\x01\x34\x02\x00\x01\xc1\xb4\x31\x81\xb1\xa0\x03\x80\x01\x01" ..
  "\xa2\x81\xa9\x81\x04\x00\x00\x00\x01\x82\x04\x00\x00\x00\x01\xa4" ..
  "\x23\x30\x0f\x02\x01\x01\x06\x04\x52\x01\x00\x01\x30\x04\x06\x02" ..
  "\x51\x01\x30\x10\x02\x01\x03\x06\x05\x28\xca\x22\x02\x01\x30\x04" ..
  "\x06\x02\x51\x01\x61\x76\x30\x74\x02\x01\x01\xa0\x6f\x60\x6d\xa1" ..
  "\x07\x06\x05\x28\xca\x22\x02\x03\xa2\x07\x06\x05\x29\x01\x87\x67" ..
  "\x01\xa3\x03\x02\x01\x0c\xa4\x03\x02\x01\x00\xa5\x03\x02\x01\x00" ..
  "\xa6\x06\x06\x04\x29\x01\x87\x67\xa7\x03\x02\x01\x0c\xa8\x03\x02" ..
  "\x01\x00\xa9\x03\x02\x01\x00\xbe\x33\x28\x31\x06\x02\x51\x01\x02" ..
  "\x01\x03\xa0\x28\xa8\x26\x80\x03\x00\xfd\xe8\x81\x01\x0a\x82\x01" ..
  "\x0a\x83\x01\x05\xa4\x16\x80\x01\x01\x81\x03\x05\xf1\x00\x82\x0c" ..
  "\x03\xee\x1c\x00\x00\x00\x00\x00\x00\x00\xed\x18"

  stdnse.debug(2, "Sending MMS initiate")
  status = socket:send( MMS_INITIATE )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(1024)
  stdnse.debug(2, "Response recieved")
  stdnse.debug(3, "mms_initiate: %s", stdnse.tohex(recv) )

  local MMS_IDENTIFY = "\x03\x00\x00\x1b\x02\xf0\x80\x01\x00\x01\x00\x61\x0e\x30\x0c\x02" ..
  "\x01\x03\xa0\x07\xa0\x05\x02\x01\x01\x82\x00"

  stdnse.debug(2, "Sending MMS identify")
  status = socket:send( MMS_IDENTIFY )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(2048)
  stdnse.debug(2, "Response recieved")
  stdnse.debug(3, "mms_identify: %s", stdnse.tohex(recv) )

  local output = stdnse.output_table()

  if ( status and recv ) then
    local mmsIdentstruct = decoder:unpackAndDecode(recv)
    if not mmsIdentstruct then
      stdnse.debug(1, "error while decoding")
      return output
    end
    replaceEmptyStrings(mmsIdentstruct)

    local vendor_name = mmsIdentstruct.confirmed_ResponsePDU.identify.vendorName
    local model_name = mmsIdentstruct.confirmed_ResponsePDU.identify.modelName
    local revision = mmsIdentstruct.confirmed_ResponsePDU.identify.revision

    stdnse.debug(1, "vendor_name: %s", vendor_name )
    stdnse.debug(1, "model_name: %s", model_name )
    stdnse.debug(1, "revision: %s", revision )
    output["modelName_identify"] = model_name
    output["vendorName_identify"] = vendor_name
    output["modelNumber_identify"] = revision
  else
    return nil
  end

  local invokeID = 1



  local vmd_NameList_Struct = query:nameList(invokeID)
  local MMS_GETNAMELIST_vmdspecific = encoder:packmmsInTPKT(encoder:mmsPDU(vmd_NameList_Struct))
  stdnse.debug(2, "Sending MMS getNameList (vmdSpecific)")
  status = socket:send( MMS_GETNAMELIST_vmdspecific )
  if not status then
    stdnse.debug(1, "error while sending MMS getNameList (vmdSpecific)")
    return output
  end

  status, recv = socket:receive_bytes(1024)
  stdnse.debug(2, "Response recieved")
  stdnse.debug(3, "mms_getnamelist: %s", stdnse.tohex(recv) )

  local vmd_names
  if ( status and recv ) then
    local mmsNLTab = decoder:unpackAndDecode(recv)
    if not mmsNLTab then
      stdnse.debug(1, "error while decoding")
      return output
    end
    vmd_names = mmsNLTab.confirmed_ResponsePDU.getNameList.listOfIdentifier
    stdnse.debug(1, "found %d vmdNames", #vmd_names )
    for i, v in ipairs(vmd_names) do
      stdnse.debug(1, "vmd_name %d: %s", i, v )
    end
  else
    stdnse.debug(1, "error while processing MMS getNameList (vmdSpecific) response")
    return output
  end

  -- reading complete vmdspecific NameList



  local matches
  local vmd_name
  stdnse.debug(2, "Start reading complete NameList")
  for i, v in ipairs(vmd_names) do
    local morefollows = true
    local continueAfter = ""
    local allIdentifiers = {}
    stdnse.debug(2, "get NameList for vmdName %s", v)
    while morefollows do
      local mmsStruct = query:nameList(invokeID, v, continueAfter)
      local sendString = encoder:packmmsInTPKT(encoder:mmsPDU(mmsStruct))
      stdnse.debug(2, "Sending getNameList request")
      status = socket:send( sendString )
      if not status then
        stdnse.debug(1, "error sending request")
        return output
      end

      status, recv = socket:receive_bytes(100000)
      stdnse.debug(2, "Response recieved")
      stdnse.debug(3, "mms_getnamelist recv: %s", stdnse.tohex(recv) )
      if ( status and recv ) then
        local recv_Struct = decoder:unpackAndDecode(recv)
        if not recv_Struct then
          stdnse.debug(1, "error while decoding")
          return output
        end

        local identifier = recv_Struct.confirmed_ResponsePDU.getNameList.listOfIdentifier
        for i, v in ipairs(identifier) do table.insert(allIdentifiers, v) end
        if #identifier > 100 then
          stdnse.debug(1, "Response contains more then 100 identifiers")
          stdnse.debug(2, "Just got %d identifiers", #identifier)
        end

        morefollows = recv_Struct.confirmed_ResponsePDU.getNameList.moreFollows
        if morefollows then
          continueAfter = identifier[#identifier]
          stdnse.debug(2, "More identifiers availible!")
        end

        invokeID = invokeID + 1
      else
        stdnse.debug(1, "error while processing MMS getNameList response")
        return output
      end
    end
    stdnse.debug(2, "Reading complete NameList done")

    stdnse.debug(2, "Searching for LPHD in %d identifiers", #allIdentifiers)
    matches = searchTable("LPHD", allIdentifiers)
    if #matches >= 1 then
      vmd_name = v
      break
    end
  end -- for loop
  stdnse.debug(2, "Searching done: found %d unique entrys", #matches)


  if #matches == 0 then
    stdnse.debug(1, "No Logical Node contains LPHD")
  end

  if #matches > 1 then
    stdnse.debug(1, "Found more then one Node")
    return output
  end



  local attributes = {
    'LLN0$DC$NamPlt$d',
    'LLN0$DC$NamPlt$configRev'
  }

  local Node_Ready = false
  local node
  if #matches == 1 then
    node = matches[1]
    Node_Ready = true
    stdnse.debug(2, "Node is: %s", node)
    table.insert(attributes, node .. '$DC$PhyNam$vendor')
    table.insert(attributes, node .. '$DC$PhyNam$serNum')
    table.insert(attributes, node .. '$DC$PhyNam$model')
    table.insert(attributes, node .. '$DC$PhyNam$swRev')
  end

  local mmsRequest = query:askfor(invokeID, vmd_name, attributes)
  local MMS_READREQUEST = encoder:packmmsInTPKT(mmsRequest)

  stdnse.debug(2, "Sending MMS readRequest")
  status = socket:send( MMS_READREQUEST )
  if not status then
    return nil
  end

  status, recv = socket:receive_bytes(1024)
  stdnse.debug(2, "Response recieved")
  stdnse.debug(3, "mms_read: %s", stdnse.tohex(recv) )

  local mmsstruct
  if ( status and recv ) then
    mmsstruct = decoder:unpackAndDecode(recv)
    if not mmsstruct then
      stdnse.debug(1, "error while decoding")
      return output
    end
    replaceEmptyStrings(mmsstruct)
  else
    stdnse.debug(1, "error while processing MMS getNameList response")
    return output
  end

  local mmsoutput
  local attNum = #attributes
  local rplNum = #mmsstruct.confirmed_ResponsePDU.Read_Response.listOfAccessResult
  if rplNum == attNum then
    mmsoutput = mmsstruct.confirmed_ResponsePDU.Read_Response.listOfAccessResult
  else

    stdnse.debug(2,"\nReply from Host %s at port %d was not compliant with standard", host["ip"], port["number"])
    stdnse.debug(2,"Request for %d attributes has been replied with %d values", attNum, rplNum)
    stdnse.debug(2,"attempting individual queries...\n")
    mmsoutput = {}
    for i = 1, attNum do
      local mmsRequest = query:askfor(i, vmd_name, attributes[i])
      local MMS_READREQUEST = encoder:packmmsInTPKT(mmsRequest)

      status = socket:send( MMS_READREQUEST )
      if not status then
        return nil
      end

      status, recv = socket:receive_bytes(1024)
      stdnse.debug(1, "mms_read recv: %s", stdnse.tohex(recv) )

      if ( status and recv ) then
        local mmsstruct = decoder:unpackAndDecode(recv)
        if not mmsstruct then
          stdnse.debug(1, "error while decoding")
          return output
        end
        replaceEmptyStrings(mmsstruct)
        table.insert(mmsoutput, {})
        mmsoutput[i][1] = mmsstruct.confirmed_ResponsePDU.Read_Response.listOfAccessResult[1][1]
      else
        return nil
      end
    end
  end

  -- create table for output
  output["productFamily"] = mmsoutput[1][1]
  output["configuration"] = mmsoutput[2][1]

  if Node_Ready then
    output["vendorName"] = mmsoutput[3][1]
    output["serialNumber"] = mmsoutput[4][1]
    output["modelNumber"] = mmsoutput[5][1]
    output["firmwareVersion"] = mmsoutput[6][1]
  else
    output["vendorName"] = "<NO_LPHD_FOUND>"
    output["serialNumber"] = "<NO_LPHD_FOUND>"
    output["modelNumber"] = "<NO_LPHD_FOUND>"
    output["firmwareVersion"] = "<NO_LPHD_FOUND>"
  end
  return output

end
