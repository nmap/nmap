description = [[
Attempts to extract system information from the Service Tags.
Based on protocol specs from
http://arc.opensolaris.org/caselog/PSARC/2006/638/stdiscover_protocolv2.pdf
http://arc.opensolaris.org/caselog/PSARC/2006/638/stlisten_protocolv2.pdf
http://arc.opensolaris.org/caselog/PSARC/2006/638/ServiceTag_API_CLI_v07.pdf
]]

---
-- @output
-- | servicetags:
-- |   URN: urn:st:3bf76681-5e68-415b-f980-abcdef123456
-- |   System: SunOS
-- |   Release: 5.10
-- |   Hostname: myhost
-- |   Architecture: sparc
-- |   Platform: SUNW,SPARC-Enterprise-T5120::Generic_142900-13
-- |   Manufacturer: Sun Microsystems, Inc.
-- |   CPU Manufacturer: Sun Microsystems, Inc.
-- |   Serial Number: ABC123456
-- |   HostID: 12345678
-- |   RAM: 16256
-- |   CPUs: 1
-- |   Cores: 4
-- |   Virtual CPUs: 32
-- |   CPU Name: UltraSPARC-T2
-- |   CPU Clock Rate: 1165
-- |   Service Tags
-- |     Solaris 10 Operating System
-- |       Product Name: Solaris 10 Operating System
-- |       Instance URN: urn:st:90592a79-974d-ebcc-c17a-b87b8eee5f1f
-- |       Product Version: 10
-- |       Product URN: urn:uuid:5005588c-36f3-11d6-9cec-fc96f718e113
-- |       Product Parent URN: urn:uuid:596ffcfa-63d5-11d7-9886-ac816a682f92
-- |       Product Parent: Solaris Operating System
-- |       Product Defined Instance ID:
-- |       Timestamp: 2010-08-10 07:35:40 GMT
-- |       Container: global
-- |       Source: SUNWstosreg
-- |     SUNW,SPARC-Enterprise-T5120 SPARC System
-- |       Product Name: SUNW,SPARC-Enterprise-T5120 SPARC System
-- |       Instance URN: urn:st:51c61acd-9f37-65af-a667-c9925a5b0ee9
-- |       Product Version:
-- |       Product URN: urn:st:hwreg:SUNW,SPARC-Enterprise-T5120:Sun Microsystems:sparc
-- |       Product Parent URN: urn:st:hwreg:System:Sun Microsystems
-- |       Product Parent: System
-- |       Product Defined Instance ID:
-- |       Timestamp: 2010-08-10 07:35:41 GMT
-- |       Container: global
-- |       Source: SUNWsthwreg
-- |     Explorer
-- |       Product Name: Explorer
-- |       Instance URN: urn:st:2dc5ab61-9bb5-409b-e910-fa39840d0d85
-- |       Product Version: 6.4
-- |       Product URN: urn:uuid:9cb70a38-7d15-11de-9d26-080020a9ed93
-- |       Product Parent URN:
-- |       Product Parent:
-- |       Product Defined Instance ID:
-- |       Timestamp: 2010-08-10 07:35:42 GMT
-- |       Container: global
-- |_      Source: Explorer


-- version 1.0

author = "Matthew Flanagan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

require("stdnse")
require("shortport")
require("strbuf")

---
-- Runs on UDP port 6481
portrule = shortport.portnumber(6481, "udp", {"open", "open|filtered"})

---
-- Sends Service Tags discovery packet to host, 
-- and extracts service information from results
action = function(host, port)
    
    -- create the socket used for our connection
    local socket = nmap.new_socket()
    
    -- set a reasonable timeout value
    socket:set_timeout(5000)
    
    -- do some exception handling / cleanup
    local catch = function()
        socket:close()
    end
    
    local try = nmap.new_try(catch)
    
    -- connect to the potential service tags discoverer
    try(socket:connect(host.ip, port.number, "udp"))
    
    local payload = strbuf.new()
    
    payload = payload .. "[PROBE] "
    payload = payload .. tostring(os.time())
    payload = payload .. "\r\n"
    
    try(socket:send(strbuf.dump(payload)))
    
    local status
    local response
    
    -- read in any response we might get
    status, response = socket:receive_bytes(1)

    if (not status) or (response == "TIMEOUT") then
        socket:close()
        return
    end

    -- since we got something back, the port is definitely open
    nmap.set_port_state(host, port, "open")
    
    -- buffer to hold script output
    local output = {}
    
    if response ~= nil then
        -- We should get a response back that has contains one line for the
        -- agent URN and TCP port
        local urn, xport, split
        split = stdnse.strsplit(" ", response)
        urn = split[1]
        xport = split[2]
        table.insert(output, "URN: " .. urn)
        if xport ~= nil then
            strbuf.clear(payload)
            payload = payload .. "GET /stv1/agent/ HTTP/1.0\r\n"

            socket = nmap.new_socket()
            socket:set_timeout(5000)

            try(socket:connect(host.ip, xport, "tcp"))
            try(socket:send(strbuf.dump(payload)))

            status, response = socket:receive_buf("</st1:response>", true)

            if (not status) or (response == "TIMEOUT") then
                socket:close()
                return
            end

            local v

            v = string.match(response, "<system>(.-)</system>")
            if v ~= nil then table.insert(output, "System: " .. v) end

            v = string.match(response, "<release>(.-)</release>")
            if v ~= nil then table.insert(output, "Release: " .. v) end

            v = string.match(response, "<host>(.-)</host>")
            if v ~= nil then table.insert(output, "Hostname: " .. v) end

            v = string.match(response, "<architecture>(.-)</architecture>")
            if v ~= nil then table.insert(output, "Architecture: " .. v) end

            v = string.match(response, "<platform>(.-)</platform>")
            if v ~= nil then table.insert(output, "Platform: " .. v) end

            v = string.match(response, "<manufacturer>(.-)</manufacturer>")
            if v ~= nil then table.insert(output, "Manufacturer: " .. v) end

            v = string.match(response, "<cpu_manufacturer>(.-)</cpu_manufacturer>")
            if v ~= nil then table.insert(output, "CPU Manufacturer: " .. v) end

            v = string.match(response, "<serial_number>(.-)</serial_number>")
            if v ~= nil then table.insert(output, "Serial Number: " .. v) end

            v = string.match(response, "<hostid>(.-)</hostid>")
            if v ~= nil then table.insert(output, "HostID: " .. v) end

            v = string.match(response, "<physmem>(.-)</physmem>")
            if v ~= nil then table.insert(output, "RAM: " .. v) end

            v = string.match(response, "<sockets>(.-)</sockets>")
            if v ~= nil then table.insert(output, "CPUs: " .. v) end

            v = string.match(response, "<cores>(.-)</cores>")
            if v ~= nil then table.insert(output, "Cores: " .. v) end

            v = string.match(response, "<virtcpus>(.-)</virtcpus>")
            if v ~= nil then table.insert(output, "Virtual CPUs: " .. v) end

            v = string.match(response, "<name>(.-)</name>")
            if v ~= nil then table.insert(output, "CPU Name: " .. v) end

            v = string.match(response, "<clockrate>(.-)</clockrate>")
            if v ~= nil then table.insert(output, "CPU Clock Rate: " .. v) end
            socket:close()

            -- Check if any other service tags are registerd and enumerate them
            strbuf.clear(payload)
            payload = payload .. "GET /stv1/svctag/ HTTP/1.0\r\n"
            try(socket:connect(host.ip, xport, "tcp"))
            try(socket:send(strbuf.dump(payload)))

            status, response = socket:receive_buf("</service_tags>", true)

            if (not status) or (response == "TIMEOUT") then
                socket:close()
                return
            end
            local svctags = {}
            if string.match(response, "<link type") then
                svctags['name'] = "Service Tags"
            end
            for svctag in string.gmatch(response, "<link type=\"service_tag\" href=\"(.-)\" />") do
                local tag = {}

                strbuf.clear(payload)
                payload = payload .. "GET "
                payload = payload .. svctag
                payload = payload .. " HTTP/1.0\r\n"

                try(socket:connect(host.ip, xport, "tcp"))
                try(socket:send(strbuf.dump(payload)))

                status, response = socket:receive_buf("</st1:response>", true)

                if (not status) or (response == "TIMEOUT") then
                    socket:close()
                    return
                end

                local v
                v = string.match(response, "<product_name>(.-)</product_name>")
                table.insert(tag, "Product Name: " .. v)
                tag['name'] = v

                v = string.match(response, "<instance_urn>(.-)</instance_urn>")
                if v ~= nil then table.insert(tag, "Instance URN: " .. v) end

                v = string.match(response, "<product_version>(.-)</product_version>")
                if v ~= nil then table.insert(tag, "Product Version: " .. v) end

                v = string.match(response, "<product_urn>(.-)</product_urn>")
                if v ~= nil then table.insert(tag, "Product URN: " .. v) end

                v = string.match(response, "<product_parent_urn>(.-)</product_parent_urn>")
                if v ~= nil then table.insert(tag, "Product Parent URN: " .. v) end

                v = string.match(response, "<product_parent>(.-)</product_parent>")
                if v ~= nil then table.insert(tag, "Product Parent: " .. v) end

                v = string.match(response, "<product_defined_inst_id>(.-)</product_defined_inst_id>")
                if v ~= nil then table.insert(tag, "Product Defined Instance ID: " .. v) end

                v = string.match(response, "<product_vendor>(.-)</product_vendor>")
                if v ~= nil then table.insert(tag, "Product Vendor: " .. v) end

                v = string.match(response, "<timestamp>(.-)</timestamp>")
                if v ~= nil then table.insert(tag, "Timestamp: " .. v) end

                v = string.match(response, "<container>(.-)</container>")
                if v ~= nil then table.insert(tag, "Container: " .. v) end

                v = string.match(response, "<source>(.-)</source>")
                if v ~= nil then table.insert(tag, "Source: " .. v) end

                v = string.match(response, "<platform_arch>(.-)</platform_arch>")
                if v ~= nil then table.insert(tag, "Platform Arch: " .. v) end

                v = string.match(response, "<installer_uid>(.-)</installer_uid>")
                if v ~= nil then table.insert(tag, "Installer UID: " .. v) end

                v = string.match(response, "<version>(.-)</version>")
                if v ~= nil then table.insert(tag, "Version: " .. v) end

                table.insert(svctags, tag)
                socket:close()
            end
            socket:close()
            table.insert(output, svctags)
        end
        return stdnse.format_output(true, output)
    end
end
