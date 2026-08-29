local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects availability of the ESC/VP.net protocol used to 
monitor and control Epson projectors.
Sends a specific ESC/VP.net message and parses the response.
]]

author = "Jaroslav Svoboda"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({3629}, "escvpnet")

action = function(host, port)
    local socket = nmap.new_socket()
    local status, err
    local output

    -- Define the ESC/VP.net message
    local message = "ESC/VP.net\x10\x01\x00\x00\x00\x00"

    -- Try to connect to the target
    status, err = socket:connect(host, port)
    if not status then
        return "Failed to connect: " .. err
    else
        stdnse.print_debug(1, "Connected to " .. host.ip .. ":" .. port.number)
    end

    -- Send the ESC/VP.net message
    status, err = socket:send(message)
    if not status then
        socket:close()
        return "Failed to send message: " .. err
    else
        stdnse.print_debug(1, "Command sent: " .. stdnse.tohex(message))
    end

    -- Receive the response
    local status, lines = socket:receive_lines(1)
    if not status then
        socket:close()
        return "Failed to receive response: " .. lines
    end

    socket:close()

    stdnse.print_debug(1, "Raw response received: " .. stdnse.tohex(lines))
    if lines:match("^ESC/VP.net") then
        output = "ESC/VP.net device detected"
    else
        output = "No valid ESC/VP.net response detected."
    end

    return output
end
