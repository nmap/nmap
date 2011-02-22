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

-- Mapping from XML element names to human-readable table labels.
local XML_TO_TEXT = {
    -- Information about the agent.
    system = "System",
    release = "Release",
    host = "Hostname",
    architecture = "Architecture",
    platform = "Platform",
    manufacturer = "Manufacturer",
    cpu_manufacturer = "CPU Manufacturer",
    serial_number = "Serial Number",
    hostid = "HostID",
    physmem = "RAM",
    sockets = "CPUs",
    cores = "Cores",
    virtcpus = "Virtual CPUs",
    name = "CPU Name:",
    clockrate = "CPU Clock Rate",

    -- Information about an individual svctag.
    product_name = "Product Name",
    instance_urn = "Instance URN",
    product_version = "Product Version",
    product_urn = "Product URN",
    product_parent_urn = "Product Parent URN",
    product_parent = "Product Parent",
    product_defined_inst_id = "Product Defined Instance ID",
    product_vendor = "Product Vendor",
    timestamp = "Timestamp",
    container = "Container",
    source = "Source",
    platform_arch = "Platform Arch",
    installer_uid = "Installer UID",
    version = "Version",
}

---
-- Runs on UDP port 6481
portrule = shortport.portnumber(6481, "udp", {"open", "open|filtered"})

local get_agent, get_svctag_list, get_svctag

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
    
    local payload
    
    payload = "[PROBE] ".. tostring(os.time()) .. "\r\n"
    
    try(socket:send(payload))
    
    local status
    local response
    
    -- read in any response we might get
    response = try(socket:receive())
    socket:close()

    -- since we got something back, the port is definitely open
    nmap.set_port_state(host, port, "open")
    
    -- buffer to hold script output
    local output = {}
    
    -- We should get a response back that has contains one line for the
    -- agent URN and TCP port
    local urn, xport, split
    split = stdnse.strsplit(" ", response)
    urn = split[1]
    xport = split[2]
    table.insert(output, "URN: " .. urn)

    if xport ~= nil then
        get_agent(host, xport, output)

        -- Check if any other service tags are registered and enumerate them
        status, svctags_list = get_svctag_list(host, xport, output)
        if status then
            svctags = {}
            for _, svctag in ipairs(svctags_list) do
                svctags['name'] = "Service Tags"
                status, tag = get_svctag(host, port, svctag)
                if status then
                    svctags[#svctags + 1] = tag
                end
            end
            table.insert(output, svctags)
        end
    end

    return stdnse.format_output(true, output)
end

function get_agent(host, port, output)
    local socket = nmap.new_socket()
    local status, err, response
    socket:set_timeout(5000)

    status, err = socket:connect(host.ip, port, "tcp")
    if not status then
        return nil, err
    end
    status, err = socket:send("GET /stv1/agent/ HTTP/1.0\r\n")
    if not status then
        socket:close()
        return nil, err
    end
    status, response = socket:receive_buf("</st1:response>", true)
    if not status then
        socket:close()
        return nil, response
    end

    socket:close()

    for elem, contents in string.gmatch(response, "<([^>]+)>([^<]-)</%1>") do
        if XML_TO_TEXT[elem] then
            table.insert(output,
                string.format("%s: %s", XML_TO_TEXT[elem], contents))
        end
    end

    return true, output
end

function get_svctag_list(host, port)
    local socket = nmap.new_socket()
    local status, err, response
    socket:set_timeout(5000)

    status, err = socket:connect(host.ip, port, "tcp")
    if not status then
        return nil, err
    end
    status, err = socket:send("GET /stv1/svctag/ HTTP/1.0\r\n")
    if not status then
        socket:close()
        return nil, err
    end
    status, response = socket:receive_buf("</service_tags>", true)
    if not status then
        socket:close()
        return nil, response
    end

    socket:close()

    local svctags = {}
    for svctag in string.gmatch(response, "<link type=\"service_tag\" href=\"(.-)\" />") do
        svctags[#svctags + 1] = svctag
    end

    return true, svctags
end

function get_svctag(host, port, svctag)
    local socket = nmap.new_socket()
    local status, err, response
    socket:set_timeout(5000)

    status, err = socket:connect(host.ip, port, "tcp")
    if not status then
        return nil, err
    end
    status, err = socket:send("GET " .. svctag .. " HTTP/1.0\r\n")
    if not status then
        socket:close()
        return nil, err
    end
    status, response = socket:receive_buf("</st1:response>", true)
    if not status then
        socket:close()
        return nil, response
    end

    socket:close()

    local tag = {}
    for elem, contents in string.gmatch(response, "<([^>]+)>([^<]-)</%1>") do
        if elem == "product_name" then
            tag['name'] = contents
        end
        if XML_TO_TEXT[elem] then
            table.insert(tag,
                string.format("%s: %s", XML_TO_TEXT[elem], contents))
        end
    end

    return true, tag
end
