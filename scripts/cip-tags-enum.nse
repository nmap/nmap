description = [[
Collects all tag names and types for Allen-Bradley Logix 5000 PLCs via
CIP Service Code 0x55 - Get_Instance_Attribute_List

See Logix 5000 Controllers Data Access
https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

]]

author = "Luis Rosa"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

---
-- @usage
-- nmap --script cip-tags-discover.nse -p 44818 <host>
--
--
-- @output
--PORT      STATE SERVICE
--44818/tcp open  EtherNetIP-2
--| cip-tags-enum:
--|   Controller Tags:
--|     (0x0002) VAR_1: REAL
--|     (0x000D) VAR_2: BOOL
--|     (0x000E) VAR_3: INT
--|   Program Tags:
--|     (0x0002) VAR_1: REAL
--|     (0x000D) VAR_2: BOOL
--|     (0x000E) VAR_3: INT

-- @xmloutput
--<table key="Controller Tags">
--    <elem key="(0x0002) VAR_1">REAL</elem>
--    <elem key="(0x000D) VAR_2">BOOL</elem>
--    <elem key="(0x000E) VAR_3">INT</elem>
--</table>
--<table key="Program Tags">
--    <elem key="(0x0002) VAR_1">REAL</elem>
--    <elem key="(0x000D) VAR_2">BOOL</elem>
--    <elem key="(0x000E) VAR_3">INT</elem>
--</table>

local math = require "math"
local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"

portrule = shortport.port_or_service(44818, "EtherNet-IP-2")

local tag_types = {
    ['c1'] = 'BOOL',
    ['c2'] = 'SINT',
    ['c3'] = 'INT',
    ['c4'] = 'DINT',
    ['ca'] = 'REAL',
    ['d3'] = 'DWORD',
    ['c5'] = 'LINT',
}

-- return a ENIP/CIP request with service code 0x55
get_instance_attribute_list_request = function(session, ot_connection_id, sequence, request_path)
    local command_specific_data = ""..
    "0200".. -- # attributes
    "0100".. -- symbol name
    "0200"   -- symbol type

    local sequence_s = string.gsub(string.format('%04X', sequence) , "(..)(..)", "%2%1") -- 2 bytes le sequence id
    local cip_payload = ""..
    "55"..   -- service code
    string.format('%02x', request_path:len()/4)..   -- path size
    request_path..
    command_specific_data

    local item_2_len = string.format("%04x", (sequence_s..cip_payload):len()/2):gsub("(..)(..)", "%2%1")

    local enip_payload = ""..
    "00000000"..          -- interface (cip)
    "0000"..              -- timeout
    "0200"..              -- item count (2)
    "a100"..              -- item 1 type (connected address item)
    "0400"..              -- item 1 length
    ot_connection_id..    -- item 1 connection id
    "b100"..              -- item 2 type (connected data item)
    item_2_len..          -- item 2 length
    sequence_s ..         -- sequence
    cip_payload

    local enip_len = string.format("%04x", (enip_payload):len()/2):gsub("(..)(..)", "%2%1")

    return ""..
    stdnse.fromhex(""..
    "7000"..              -- command (Send Unit Data)
    enip_len..            -- length
    session..             -- session handle
    "00000000"..          -- status
    "0000000000000000"..  -- sender context
    "00000000"..          -- options
    enip_payload)         -- req path + payload
end

-- return a ENIP/CIP Connection Manager Forward Open (0x54)
cm_forward_open = function(session)
    connection_serial_number = string.byte(math.random(0x00, 0xFF))..string.byte(math.random(0x00, 0xFF))
    return ""..
    stdnse.fromhex(""..
    "6f00"..                    -- command (Send RR Data)
    "4000"..                    -- length
    session..                   -- session handle
    "00000000"..                -- status
    "0000000000000000"..        -- sender context
    "00000000"..                -- options
    "00000000"..                -- interface (cip)
    "0000"..                    -- timeout
    "0200"..                    -- item count
    "0000"..                    -- item 1 type (Null Address Item)
    "0000"..                    -- item 1 length
    "b200"..                    -- item 2 type (Unconnected Data Item)
    "3000"..                    -- item 2 length
    "54"..                      -- service code
    "02"..                      -- request path length
    "20062401"..                -- request path
    "0af0"..                    -- timeout
    "00000000"..                -- ot_connection_id
    "00000000"..                -- to_connection_id
    connection_serial_number..  -- connection serial number
    "0000"..                    -- originator vendor id
    "00000000"..                -- originator serial number
    "07"..                      -- connection timeout
    "000000"..                  -- reserved
    "00400000" ..               -- ot rpi
    "1243" ..                   -- ot network connection params
    "00400000"..                -- to rpi
    "1243" ..                   -- to network connection parms
    "a3"..                      -- transport type
    "03"..                      -- connection path length
    "010020022401"              -- connection path
    )
end

-- return a ENIP/CIP Connection Manager Forward Close (0x4e)
cm_forward_close = function(session)
    connection_serial_number = string.byte(math.random(0x00, 0xFF))..string.byte(math.random(0x00, 0xFF))
    return ""..
    stdnse.fromhex(""..
    "6f00"..                    -- command (Send RR Data)
    "2800"..                    -- length
    session..                   -- session handle
    "00000000"..                -- status
    "0000000000000000"..        -- sender context
    "00000000"..                -- options
    "00000000"..                -- interface (cip)
    "0000"..                    -- timeout
    "0200"..                    -- item count
    "0000"..                    -- item 1 type (Null Address Item)
    "0000"..                    -- item 1 length
    "b200"..                    -- item 2 type (Unconnected Data Item)
    "1800"..                    -- item 2 length
    "4e"..                      -- service code
    "02"..                      -- request path length
    "20062401"..                -- request path
    "0af0"..                    -- timeout
    connection_serial_number..  -- connection serial number
    "0000"..                    -- originator vendor id
    "00000000"..                -- originator serial number
    "03"..                      -- connection path length
    "00"..                      -- reserved
    "010020022401"              -- connection path
    )
end

get_instances = function(session, ot_connection_id, sequence, base_request_path, output)

    local last_instance_id = "0000" -- starting instance id
    local instance_id
    repeat
        local request_path = base_request_path ..
        "206b2500".. -- class
        last_instance_id  -- instance id

        try(socket:send(get_instance_attribute_list_request(session, ot_connection_id, sequence, request_path))) -- AB CIP 0x55
        local response = try(socket:receive())

        local general_status = string.unpack("I1", response, 49)
        stdnse.debug("Received a general Status %d", general_status)

        offset = 51
        while(offset<response:len()) do
            instance_id, idx, pos = string.unpack("<I4", response, offset)
            offset = offset + 4

            local symbol_name_length = string.unpack("<I2", response, offset)
            offset = offset + 2

            local symbol_name = response:sub(offset,offset+symbol_name_length-1)
            offset = offset + symbol_name_length

            local symbol_type = string.unpack("<I2", response, offset)
            offset = offset + 2

            if not symbol_name:match("^__") then -- discard internal tags
                if tag_types[stdnse.tohex(symbol_type)] then
                    output["("..string.format('0x%04X', instance_id)..") "..symbol_name] = tag_types[stdnse.tohex(symbol_type)]
                else
                    output["("..string.format('0x%04X', instance_id)..") "..symbol_name] = "Unknown type (0x"..stdnse.tohex(symbol_type)..")"
                end
            end
        end
        last_instance_id = stdnse.tohex(string.pack("<I2",instance_id+1))
        sequence = sequence + 1
    until (general_status == 0)
end

action = function(host, port)

    local output = stdnse.output_table()

    local register_session_request = stdnse.fromhex(""..
    "6500"..             -- register session
    "0400"..             -- length
    "00000000"..         -- session
    "00000000"..         -- status
    "0000000000000000".. -- sender context
    "00000000"..         -- options
    "0100"..             -- protocol version
    "0000"               -- flags
    )

    socket = nmap.new_socket()
    local catch = function()
        socket:close()
    end

    try = nmap.new_try(catch)
    try(socket:connect(host, port))
    try(socket:send(register_session_request))
    local response = try(socket:receive())
    local session, status = stdnse.tohex(response):match("65000400(........)(........).*")
    if (status == '00000000') then -- success
        stdnse.debug("ENIP Register Session successful: 0x%s", session)
        try(socket:send(cm_forward_open(session))) -- CIP CM FO
        local response = try(socket:receive())

        local ot_connection_id = string.unpack(">I4", response, 45) -- CIP O->T Network Connection ID
        ot_connection_id = stdnse.tohex(ot_connection_id)

        -- controller tags
        local sequence = 1
        local last_instance_id = "0000" -- starting instance id

        -- get global tags
        local request_path = ""
        local controller_tags = stdnse.output_table()
        get_instances(session, ot_connection_id, sequence, request_path, controller_tags)

        -- get local tags
        request_path = ""..
        "91"..                                -- class
        "13"..                                -- tag name length
        stdnse.tohex("Program:MainProgram").. -- Default Main Program
        "00"                                  -- Padding

        local program_tags = stdnse.output_table()
        get_instances(session, ot_connection_id, sequence, request_path, program_tags)

        output["Controller Tags"] = controller_tags
        output["Program Tags"] = program_tags

        stdnse.debug(stdnse.tohex(cm_forward_close(session)))
        try(socket:send(cm_forward_close(session))) -- CIP CM FC
        response = try(socket:receive())
        session, status = stdnse.tohex(response):match("67001e00(........)(........).*")
        stdnse.debug("ENIP Forward Close %s", status)
        if (status == '00000000') then -- success
            stdnse.debug("ENIP Forward Close")
        end
    end

    stdnse.debug("ENIP Register Session failed")
    socket:close()

    return output
end
