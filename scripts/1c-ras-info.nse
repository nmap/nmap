local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Collect info from 1545 port
]]

---
-- @output
-- PORT     STATE SERVICE
-- 1545/tcp open  1c-ras  1C:Enterprise Remote Administration Server
-- | 1cinfo:
-- |    ffffffff-ffff-ffff-ffff-ffffffffffff[port]: 1541
-- |        ffffffff-ffff-ffff-ffff-ffffffffffff[desc]: infobase decription
-- |        ffffffff-ffff-ffff-ffff-ffffffffffff[name]: infobase_name

author = "Levatein"

categories = {"discovery", "safe"}

portrule = function(host, port)
	return port.state == "open"
		and port.protocol == "tcp"
end

action = function(host, port)
    local output = stdnse.output_table()
    local socket = nmap.new_socket()
    local catch = function()
        socket:close()
    end
    local try = nmap.new_try(catch)
    try(socket:connect(host, port))
    local response = ""
    rac_connect(socket)
    response = get_clusters(socket)
    output = server_admin_is_set(socket, output)
    output = prepare_cl_output(output, response, socket)
    rac_close(socket)
    socket:close()
    return output
end

function prepare_cl_output(output, response, socket)
    local function hexencode(str)
        return (str:gsub(".", function(char) return string.format("%02x", char:byte()) end))
    end
    local cl_count = string.unpack(">I1", string.sub(response,6,6))
    local pointer = 7
    for i=1,cl_count,1 do
        local clid = hexencode(string.sub(response,pointer,pointer+15))
        local clid_out = hexencode(string.sub(response,pointer,pointer+3))..'-'..hexencode(string.sub(response,pointer+4,pointer+5))..'-'..hexencode(string.sub(response,pointer+6,pointer+7))..'-'..hexencode(string.sub(response,pointer+8,pointer+9))..'-'..hexencode(string.sub(response,pointer+10,pointer+15))
        pointer = pointer + 16 + 4
        local cl_host_len = string.unpack(">I1", string.sub(response,pointer,pointer))
        pointer = pointer + 1
        pointer = pointer + cl_host_len + 4
        output[clid_out..'[port]'] = string.unpack(">I2", string.sub(response,pointer,pointer+1))
        pointer = pointer + 6
        local name_len = string.unpack(">I5", string.sub(response,pointer,pointer+4))
        pointer = pointer + 5
        output[clid_out..'[name]'] = string.sub(response,pointer,pointer+name_len-1)

        response2, name = cluster_admin_is_set(socket, clid, string.sub(response,pointer,pointer+name_len-1))
        output = prepare_ib_output(output, response2, socket, clid)
        pointer = pointer + name_len + 18
    end
    return output
end

function prepare_ib_output(output, response, socket, clid)
    local function hexencode(str)
        return (str:gsub(".", function(char) return string.format("%02x", char:byte()) end))
    end
    if not string.find(response, "service.Admin.Cluster#Rights") then
        local ib_count = string.unpack(">I1", string.sub(response,6,6))
        local pointer = 7
        local clusters = {}
        for j=1,ib_count,1 do
            local ibid = hexencode(string.sub(response,pointer,pointer+15))
            local out_ibid = hexencode(string.sub(response,pointer,pointer+3))..'-'..hexencode(string.sub(response,pointer+4,pointer+5))..'-'..hexencode(string.sub(response,pointer+6,pointer+7))..'-'..hexencode(string.sub(response,pointer+8,pointer+9))..'-'..hexencode(string.sub(response,pointer+10,pointer+15))
            pointer = pointer + 16
            local ib_descr_len = string.unpack(">I1", string.sub(response,pointer,pointer))
            pointer = pointer + 1
            output['    '..out_ibid..'[desc]'] = string.sub(response,pointer,pointer+ib_descr_len-1)
            pointer = pointer + ib_descr_len
            local ib_name_len = string.unpack(">I1", string.sub(response,pointer,pointer))
            pointer = pointer + 1
            output['    '..out_ibid..'[name]'] = string.sub(response,pointer,pointer+ib_name_len-1)
            pointer = pointer + ib_name_len
        end
    end
    return output
end

function rac_close(socket)
    local start_ending = stdnse.fromhex( "0d01")
    local ending = stdnse.fromhex( "01")
    socket:send(start_ending)
    socket:send(ending)
end

function cluster_admin_is_set(socket, clid)
    local start_info = stdnse.fromhex( "0e17")
    local info = stdnse.fromhex( "0100000109"..clid.."0000")
    socket:send(start_info)
    socket:send(info)
    local rcvstatus, response = socket:receive()
    local rcvstatus, response = socket:receive()

    local start_info = stdnse.fromhex( "0e15")
    local info = stdnse.fromhex( "010000012a"..clid)
    socket:send(start_info)
    socket:send(info)
    local rcvstatus, response = socket:receive()
    local rcvstatus, response = socket:receive()
    return response
end

function server_admin_is_set(socket, output)
    local start_info = stdnse.fromhex( "0e07")
    local info = stdnse.fromhex( "01000001080000")
    socket:send(start_info)
    socket:send(info)
    local rcvstatus, response = socket:receive()
    local rcvstatus, response = socket:receive()
    if not string.find(response, "service.Admin.Cluster#Failure") then
        output['server admin'] = 'is not configured'
    end
    return output
end

function get_clusters(socket)
    local start_info = stdnse.fromhex( "0e05")
    local info = stdnse.fromhex( "010000010b")
    socket:send(start_info)
    socket:send(info)
    local rcvstatus, response = socket:receive()
    local rcvstatus, response = socket:receive()
    return response
end

function rac_connect(socket)
    local start1 = stdnse.fromhex( "1c53575001000100")
    local start2 = stdnse.fromhex("0116010f636f6e6e6563742e74696d656f757404000007d0")
    socket:send(start1)
    socket:send(start2)
    local rcvstatus, response = socket:receive()
    local rcvstatus, response = socket:receive()
    local start_version = stdnse.fromhex( "0b1f")
    local version_10 = stdnse.fromhex( "1876382e736572766963652e41646d696e2e436c75737465720431302e3080")
    socket:send(start_version)
    socket:send(version_10)
    local rcvstatus, response = socket:receive()
    local rcvstatus, response = socket:receive()
    if string.find(response, "UnsupportedService") then
        local nums = {'e','d','c','b','a','9','8','7','6'}
        for i=1,9 do
            local start_version = stdnse.fromhex("0b1"..nums[i])
            local version = stdnse.fromhex( "1876382e736572766963652e41646d696e2e436c757374657203"..tostring(40-i).."2e3080")
            socket:send(start_version)
            socket:send(version)
            local rcvstatus, response = socket:receive()
            local rcvstatus, response = socket:receive()
            if not string.find(response, "UnsupportedService") then
                break
            end
        end
    end
end
