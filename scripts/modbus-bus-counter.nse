local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"

description = [[
Queries a Modbus TCP device (port 502) using Function Code 08 (Diagnostics) 
with Sub-function 0x000B to retrieve the total Bus Message Count.
]]

---
-- @usage
-- nmap --script modbus-bus-counter -p 502 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 502/tcp open  modbus
-- |_modbus-bus-counter: Modbus diagnostics successful | Bus Message Count: 1337
---

author = "Emir"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(502, "modbus")

action = function(host, port)
    local soket = nmap.new_socket()
    soket:set_timeout(5000)

    local baglandi_mi, hata = soket:connect(host, port)
    if not baglandi_mi then
        soket:close()
        return stdnse.format_output(false, "Connection failed: " .. tostring(hata))
    end

    -- Diagnostics Query: Sub-function 0x000B (Return Bus Message Count)
    -- MBAP: TransID (1), Proto (0), Len (6), Unit (1) | PDU: FC 08, Sub-FC 0x000B, Data 0x0000
    local soru_paketi = "\x00\x01\x00\x00\x00\x06\x01\x08\x00\x0B\x00\x00"
    soket:send(soru_paketi)

    local okundu_mu, gelen_veri = soket:receive()
    soket:close()

    if not okundu_mu or not gelen_veri or #gelen_veri < 12 then
        return stdnse.format_output(false, "No valid Modbus response received from device.")
    end

    -- Check for Exception Response (Function Code 0x88)
    local fn_kodu = string.byte(gelen_veri, 8)
    if fn_kodu == 136 then
        return stdnse.format_output(false, "Device returned exception: Diagnostics (FC 08) not supported.")
    end

    -- Unpack 16-bit Big-Endian integer from bytes 11 and 12
    local _, sayac = string.unpack(">I2", gelen_veri, 11)

    return stdnse.format_output(true, string.format("Modbus diagnostics successful | Bus Message Count: %d", sayac))
end
