local nmap = require('nmap')
local stdnse = require('stdnse')

author = "Andrew Farabee"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

-- @usage
-- nmap -sK --script=connectscan <host>
-- @output
-- TODO


local function getports(host)
    local ports = {}
    local port = nil

    repeat
        port = nmap.get_ports(host, port, "tcp", "unknown")
        if port then
            table.insert(ports, port)
        end
    until not port

    return ports
end

-- Temporarily just returning true for each host until I can think of all
-- conditions for not continuing with scanning.
scanrule = function(host)
    return true
end

action = function(host)
    local ports = getports(host)
    for _, port in ipairs(ports) do
        local socket = nmap.new_socket()
        local status, err = socket:connect(host, port, "tcp")
        if status then
            nmap.set_port_state(host, port, "open")
        else
            nmap.set_port_state(host, port, "closed")
        end
        socket:close()
    end
end
