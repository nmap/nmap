local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects availability of the PJLink protocol used 
to monitor and control projectors and monitors.
Sends a specific PJLink message and parses the response.
]]

author = "Jaroslav Svoboda"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({4352}, "pjlink")

action = function(host, port)
    local socket = nmap.new_socket()
    local status, err
    local output

    status, err = socket:connect(host, port)

    -- Connect to the target host and port
    status, err = socket:connect(host, port)
    if not status then
        return "Failed to connect: " .. err
    end

    -- Receive the response
    local lines
    status, lines = socket:receive_lines(1)
    if not status then
        socket:close()
        return "Failed to receive response: " .. lines
    end

    socket:close()

    stdnse.print_debug(1, "Raw response received: " .. stdnse.tohex(lines))
    if lines:match("^PJLINK 0") then
        output = "PJLink device detected: No authentication required."
    elseif lines:match("^PJLINK 1") then
        output = "PJLink device detected: Authentication required."
    else
        output = "No valid PJLink response detected."
    end

    return output
end
