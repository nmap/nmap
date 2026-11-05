local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Scans an SMTP service and records the response codes returned
for selected standard SMTP commands.
]]

author = "Aravind M"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({25, 587}, "smtp")

action = function(host, port)

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status = socket:connect(host.ip, port.number)

    if not status then
        return "Could not connect to SMTP service"
    end

    local output = {}

    -- Read SMTP banner
    local _, banner = socket:receive_lines(1)
    if banner then
        table.insert(output, "Banner: " .. banner:gsub("\r?\n", ""))
    end

    -- Commands to scan
    local commands = {
        "EHLO localhost",
        "NOOP",
        "HELP",
        "VRFY test"
    }

    for _, command in ipairs(commands) do

        socket:send(command .. "\r\n")

        local _, response = socket:receive_lines(1)

        if response then
            local code = response:match("^(%d%d%d)")

            table.insert(output,
                command .. ": " .. (code or "Response received"))
        else
            table.insert(output, command .. ": No response")
        end
    end

    socket:send("QUIT\r\n")
    socket:close()

    return table.concat(output, "\n")
end
