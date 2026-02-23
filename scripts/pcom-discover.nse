description = [[
Collects device information for Unitronics PLCs via PCOM protocol.

PCOM is a protocol to communicate with Unitronics PLCs either by serial or TCP.

See https://unitronicsplc.com/Download/SoftwareUtilities/Unitronics%20PCOM%20Protocol.pdf

]]

author = "Luis Rosa"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","version"}

-- inspired by modbus-discover.nse
-- PLCs Model data adapted from Unitronics .NET driver

---
-- @usage
-- nmap --script pcom-discover.nse --script-args='pcom-discover.aggressive=true' -p 20256 <host>
--
-- @args aggressive - boolean value defines find all or just direct connected unit id (default: false)
-- @args seconds_between_requests - number of seconds between each packet (default: 1)
--
-- @output
--PORT      STATE SERVICE
--20256/tcp open  pcom
--| pcom-discover:
--|   master:
--|     Unit ID 3:
--|       Model: V130-33-T38
--|       HW version: A
--|       OS Build: 41
--|       OS Version: 3.9
--|       PLC Name: some_name
--|       PLC Unique ID: XXXXXXXX
--|   slaves:
--|     Unit ID 4:
--|       Model: V130-33-T38
--|       HW version: A
--|       OS Build: 41
--|       OS Version: 3.9
--|       PLC Name: some_name
--|_      PLC Unique ID: XXXXXXXX

-- @xmloutput
-- <table key="master">
--   <table key="Unit ID 3">
--     <elem key="Model">V130-33-T38</elem>
--     <elem key="HW version">A</elem>
--     <elem key="OS Build">41</elem>
--     <elem key="OS Version">3.9</elem>
--     <elem key="PLC Name">some_name</elem>
--     <elem key="PLC Unique ID">XXXXXXXX</elem>
--   </table>
-- </table>
-- <table key="slaves">
--   <table key="Unit ID 4">
--     <elem key="Model">V130-33-T38</elem>
--     <elem key="HW version">A</elem>
--     <elem key="OS Build">41</elem>
--     <elem key="OS Version">3.9</elem>
--     <elem key="PLC Name">some_name</elem>
--     <elem key="PLC Unique ID">XXXXXXXX</elem>
--   </table>
-- </table>

local math = require "math"
local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"

portrule = shortport.port_or_service(20256, "pcom")
local models = {
    ['PRBT'] = 'FACTORY BOOT',
    ['13PRBT'] = 'V130 FACTORY BOOT',
    ['35PRBT'] = 'V350 FACTORY BOOT',
    ['43PRBT'] = 'V430 FACTORY BOOT',
    ['10PRBT'] = 'V1040/V1210 FACTORY BOOT',
    ['PC15'] = 'EXF-RC15 FACTORY BOOT',
    ['SM35PB'] = 'SM35-J FACTORY BOOT',
    ['SM43PB'] = 'SM43-J FACTORY BOOT',
    ['SM70PB'] = 'SM70-J FACTORY BOOT',
    ['SM7OPB'] = 'SM70-OEM FACTORY BOOT',
    ['70PR'] = 'V700-T20BJ FACTORY BOOT',
    ['ADF1'] = 'ADP-PB1 FACTORY BOOT',
    ['BOOT'] = 'BOOT',
    ['CLBT'] = 'CLR BOOT',
    ['13BOOT'] = 'V130 BOOT',
    ['35BOOT'] = 'V350 BOOT',
    ['SM35BT'] = 'SM35-J BOOT',
    ['SM43BT'] = 'SM43-J BOOT',
    ['SM70BT'] = 'SM70-J BOOT',
    ['SM7OBT'] = 'SM70-OEM BOOT',
    ['SMBT'] = 'SM35 BOOT',
    ['10BOOT'] = 'V1040 BOOT',
    ['12BOOT'] = 'V1210 BOOT',
    ['43BOOT'] = 'V430 BOOT',
    ['70BOOT'] = 'V700-T20BJ BOOT',
    ['ADB1'] = 'ADP-PB1 BOOT',
    ['BM90'] = 'BOOT',
    ['BNX1'] = 'BOOT',
    ['BNR1'] = 'BOOT',
    ['BRC1'] = 'EX-RC1 BOOT',
    ['BC15'] = 'EXF-RC15 BOOT',
    ['B1'] = 'M90-19-B1',
    ['B1A'] = 'M90-19-B1A',
    ['R1'] = 'M90-R1',
    ['R1C'] = 'M90-R1-CAN',
    ['R2C'] = 'M90-R2-CAN',
    ['T'] = 'M90-T',
    ['T1'] = 'M90-T1',
    ['T1C'] = 'M90-T1-CAN',
    ['TA2C'] = 'M90-TA2-CAN',
    ['TA3C'] = 'M90-TA3-CAN',
    ['1TC2'] = 'M91-19-TC2',
    ['1UN2'] = 'M91-19-UN2',
    ['1R1'] = 'M91-19-R1',
    ['1R2'] = 'M91-19-R2',
    ['1R2C'] = 'M91-19-R2C',
    ['1T1'] = 'M91-19-T1',
    ['1UA2'] = 'M91-19-UA2',
    ['1T2C'] = 'M91-19-T2C',
    ['7B1'] = 'M90-2-B1',
    ['7B1A'] = 'M90-2-B1A',
    ['7R1'] = 'M90-2-R1',
    ['7R1C'] = 'M90-2-R1-CAN',
    ['7R2C'] = 'M90-2-R2-CAN',
    ['7T'] = 'M90-2-T',
    ['7T1'] = 'M90-2-T1',
    ['7T1C'] = 'M90-2-T1-CAN',
    ['7TA2'] = 'M90-2-TA2-CAN',
    ['7TA3'] = 'M90-2-TA3-CAN',
    ['8TC2'] = 'M91-2-TC2',
    ['8UN2'] = 'M91-2-UN2',
    ['8R1'] = 'M91-2-R1',
    ['8R2'] = 'M91-2-R2',
    ['8R2C'] = 'M91-2-R2C',
    ['8T1'] = 'M91-2-T1',
    ['8UA2'] = 'M91-2-UA2',
    ['8T38'] = 'M91-2-T38',
    ['8T2C'] = 'M91-2-T2C',
    ['8R6C'] = 'M91-2-R6C',
    ['8R34'] = 'M91-2-R34',
    ['8A19'] = 'M91-2-RA19',
    ['8A22'] = 'M91-2-RA22',
    ['1T38'] = 'M91-19-T38',
    ['JR14'] = 'BOSCH',
    ['JR17'] = 'JZ10-11-R17',
    ['JR10'] = 'JZ10-11-R10',
    ['JR16'] = 'JZ10-11-R16',
    ['JT10'] = 'JZ10-11-T10',
    ['JT17'] = 'JZ10-11-T17',
    ['JEW1'] = 'JZB2-11-EW1',
    ['JE10'] = 'JZB1-11-SE10',
    ['JR31'] = 'JZ10-11-R31',
    ['JT40'] = 'JZ10-11-T40',
    ['JP15'] = 'JZ10-11-PT15',
    ['JE13'] = 'JZ10-11-UE13',
    ['JA24'] = 'JZ10-11-UA24',
    ['JN20'] = 'JZ10-11-UN20',
    ['8RZ'] = 'M91-2-R1-AZ1',
    ['2320'] = 'V230-13-B20',
    ['2620'] = 'V260-16-B20',
    ['2820'] = 'V280-18-B20',
    ['2920'] = 'V290-19-B20',
    ['VUN2'] = 'V120-12-UN2',
    ['VR1'] = 'V120-12-R1',
    ['VR2C'] = 'V120-12-R2C',
    ['VUA2'] = 'V120-12-UA2',
    ['VT1'] = 'V120-12-T1',
    ['VT40'] = 'V120-12-T40',
    ['VT2C'] = 'V120-12-T2C',
    ['VT38'] = 'V120-12-T38',
    ['WUN2'] = 'V120-22-UN2',
    ['WR1'] = 'V120-22-R1',
    ['WR2C'] = 'V120-22-R2C',
    ['WUA2'] = 'V120-22-UA2',
    ['WT1'] = 'V120-22-T1',
    ['WT40'] = 'V120-22-T40',
    ['WT2C'] = 'V120-22-T2C',
    ['WT38'] = 'V120-22-T38',
    ['WR6C'] = 'V120-22-R6C',
    ['WR34'] = 'V120-22-R34',
    ['WA19'] = 'V120-22-RA19',
    ['WA22'] = 'V120-22-RA22',
    ['ERC1'] = 'EX-RC1',
    ['5320'] = 'V530-53-B20B',
    ['49C3'] = 'V570-57-C30 / V290-19-C30',
    ['57C3'] = 'V570-57-C30 / V290-19-C30',
    ['49T3'] = 'V570-57-T34 / V290-19-T34',
    ['57T3'] = 'V570-57-T34 / V290-19-T34',
    ['49T2'] = 'V570-57-T20 / V290-19-T20',
    ['57T2'] = 'V570-57-T20 / V290-19-T20',
    ['49T4'] = 'V570-57-T40 / V290-19-T40',
    ['57T4'] = 'V570-57-T40 / V290-19-T40',
    ['56C3'] = 'V560-56-C30',
    ['56T4'] = 'V560-56-T40',
    ['56T3'] = 'V560-56-T34',
    ['56T2'] = 'V560-56-T25B',
    ['13TR22'] = 'V130-33-TRA22',
    ['13XXXX'] = 'V130-33-XXXX',
    ['13R2'] = 'V130-33-R2',
    ['13R34'] = 'V130-33-R34',
    ['13T2'] = 'V130-33-T2',
    ['13T38'] = 'V130-33-T38',
    ['13RA22'] = 'V130-33-RA22',
    ['13TA24'] = 'V130-33-TA24',
    ['13B1'] = 'V130-33-B1',
    ['13T40'] = 'V130-33-T40',
    ['13R6'] = 'V130-33-R6',
    ['13TR34'] = 'V130-33-TR34',
    ['13TR20'] = 'V130-33-TR20',
    ['13TR6'] = 'V130-33-TR6',
    ['13TU24'] = 'V130-33-TU24',
    ['35R2'] = 'V350-35-R2',
    ['35R34'] = 'V350-35-R34',
    ['35T2'] = 'V350-35-T2',
    ['35T38'] = 'V350-35-T38',
    ['35RA22'] = 'V350-35-RA22',
    ['35TA24'] = 'V350-35-TA24',
    ['35B1'] = 'V350-35-B1',
    ['35T40'] = 'V350-35-T40',
    ['35R6'] = 'V350-35-R6',
    ['35TR34'] = 'V350-35-TR34',
    ['35TR22'] = 'V350-35-TRA22',
    ['35TR20'] = 'V350-35-TR20',
    ['35TR6'] = 'V350-35-TR6',
    ['35TU24'] = 'V350-35-TU24',
    ['35XXXX'] = 'V350-35-XXXX',
    ['S3T20'] = 'SM35-J-T20',
    ['S3TA2'] = 'SM35-J-R20',
    ['S3R20'] = 'SM35-J-R20',
    ['S4T20'] = 'SM43-J-T20',
    ['S4TA2'] = 'SM43-J-R20',
    ['S4R20'] = 'SM43-J-R20',
    ['70T2'] = 'V700-T20BJ',
    ['EC15'] = 'EXF-RC15',
    ['10T2'] = 'V1040',
    ['12T2'] = 'V1210',
    ['ADP1'] = 'ADP-PB1',
}

pcom_ascii_checksum = function(msg)
    local checksum = 0
    for idx in msg:gmatch("..") do
        checksum = checksum + tonumber(idx,16)
    end
    checksum = checksum % 256
    return string.format('%02X', checksum):gsub(".", function (c) return string.format('%X', c:byte()) end)
end

pcom_binary_checksum = function(msg)
    local checksum = 0
    for idx in msg:gmatch("..") do
        checksum = checksum + tonumber(idx,16)
    end
    -- two complement of checksum
    return string.gsub(string.format('%04X', (0x10000 - (checksum % 0x10000))) , "(..)(..)", "%2%1")
end

pcom_tcp_request = function (mode, payload)
    --PCOM/TCP
    return "" ..
    string.byte(math.random(0x00, 0xFF))..string.byte(math.random(0x00, 0xFF)) .. -- transaction id
    mode .. -- mode
    "00" .. -- reserved
    string.gsub(string.format('%04X', payload:len()/2) , "(..)(..)", "%2%1") -- length
end

pcom_ascii_request = function (command,uid)
    local pcom_ascii_payload = "" ..
    "2f" .. -- "/"
    uid ..
    command ..
    pcom_ascii_checksum(uid..command) ..
    "0d" -- "\r"

    return "" ..
    pcom_tcp_request("65", pcom_ascii_payload) .. -- PCOM/TCP
    pcom_ascii_payload                            -- PCOM/ASCII
end

pcom_binary_get_plc_name = function(id)
    local pcom_binary_header = "" ..
    "2f5f4f504c43" .. -- stx
    id .. -- id
    "fe01010000" .. -- reserved
    "0c" .. -- command
    "00" .. -- reserved
    "000000000000" .. -- command details
    "0000"  -- data length

    local pcom_binary_payload = "" ..
    pcom_binary_header ..                       -- PCOM/Binary header
    pcom_binary_checksum(pcom_binary_header) .. -- checksum
    "0000" .. -- footer checksum
    "5c" -- etx

    return "" ..
    pcom_tcp_request("66", pcom_binary_payload) .. -- PCOM/TCP
    pcom_binary_payload                            -- PCOM/Binary
end

parse_id_result = function (payload, uid_t)
    local modelreply, hwversion, osversion1, osversion2, osbuild = payload:match(".*/A..ID(......)(.)(...)(...)(..)B")
    modelreply = modelreply:gsub("^%s*(.-)%s*$", "%1")
    uid_t["Model"] = models[modelreply]
    uid_t["HW version"] = hwversion
    uid_t["OS Build"] = osbuild
    uid_t["OS Version"] = osversion1:match("0*(%d+)").."."..osversion2:match("0*(%d+)")
end

parse_plc_name_result = function (payload, uid_t)
    uid_t["PLC Name"] = payload:match("/_OPLC..................(.*)...")
end

action = function(host, port)

    -- If false, does not lookup for slaves
    local aggressive = stdnse.get_script_args('pcom-discover.aggressive')
    -- Minimal number of seconds between requests (to prevent rejected request)
    local seconds_between_requests = tonumber(stdnse.get_script_args('pcom-discover.seconds_between_requests')) or 1

    local output = stdnse.output_table()
    local uid_master = 0
    output.master = stdnse.output_table()
    stdnse.debug("PCOM/ASCII ID request (unitID = ".."00 )")
    local status, result = comm.exchange(host, port, stdnse.fromhex(pcom_ascii_request("4944", "3030"))) -- ID, 00 command
    if (status) then
        stdnse.debug("PCOM/ASCII ID reply (UnitID = 00 )")

        local uid_t = stdnse.output_table()
        parse_id_result(result, uid_t)

        stdnse.sleep(seconds_between_requests)
        local status, result = comm.exchange(host, port, stdnse.fromhex(pcom_binary_get_plc_name("00")))
        if (status) then
            parse_plc_name_result(result, uid_t)
        end
        stdnse.sleep(seconds_between_requests)
        status, result = comm.exchange(host, port, stdnse.fromhex(pcom_ascii_request("5547", "3030"))) -- UG , 00 command
        if (status) then
            uid_master = tonumber(result:match(".*/A..UG(..)"),16)
        end
        stdnse.sleep(seconds_between_requests)
        -- Read SDW9 (Unique ID number, used if PLC name is not set), 00 command
        status, result = comm.exchange(host, port, stdnse.fromhex(pcom_ascii_request("524e4a303030393031", "3030")))
        if (status) then
            uid_t["PLC Unique ID"] = tonumber(result:match(".*/A..RN(.*)..."),16)
        end
        stdnse.sleep(seconds_between_requests)

        output.master[("Unit ID %d"):format(uid_master)] = uid_t
    else
        return
    end

    if(aggressive) then
        output.slaves = stdnse.output_table()
        for uid = 1,127 do
            if (uid ~= uid_master) then -- skip master
                stdnse.debug("PCOM/ASCII ID request (unitID = "..uid.." )")
                local uid_s = string.format("%02X", uid):gsub(".", function (c) return string.format('%X', c:byte()) end)
                local status, result = comm.exchange(host, port, stdnse.fromhex(pcom_ascii_request("4944",uid_s))) -- ID command
                stdnse.sleep(seconds_between_requests)
                if (status) then
                    local uid_t = stdnse.output_table()

                    stdnse.debug("PCOM/ASCII ID reply (UnitID = "..uid.." )")
                    parse_id_result(result, uid_t)

                    local status, result = comm.exchange(host, port, stdnse.fromhex(pcom_binary_get_plc_name(string.format("%02X",uid))))
                    if (status) then
                        parse_plc_name_result(result, uid_t)
                    end
                    stdnse.sleep(seconds_between_requests)
                    -- Read SDW9 (Unique ID number, used if PLC name is not set)
                    status, result = comm.exchange(host, port, stdnse.fromhex(pcom_ascii_request("524e4a303030393031",uid_s)))
                    if (status) then
                        uid_t["PLC Unique ID"] = tonumber(result:match(".*/A..RN(.*)..."),16)
                    end

                    output.slaves[("Unit ID %d"):format(uid)] = uid_t
                end
            end
        end
    end
    return output
end
