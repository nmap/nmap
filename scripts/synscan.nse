local bin = require('bin')
local bit = require('bit')
local nmap = require('nmap')
local stdnse = require('stdnse')
local packet = require('packet')

description = [[
A simple SYN scanning script.
]]


---
-- @usage
-- nmap -sK --script=synscan <host>
--
-- @output
-- Scanned at 2011-04-25 10:33:41 CEST for 1s
-- PORT     STATE  SERVICE      REASON
-- 21/tcp   closed ftp          script-set
-- 22/tcp   closed ssh          script-set
-- 23/tcp   open   telnet       script-set
-- 25/tcp   closed smtp         script-set
-- 53/tcp   closed domain       script-set
-- 80/tcp   open   http         script-set

-- 04/25/2011: initial version

author = "Jacek Wielemborek"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

-- TCP flags
local TH_SYN = 0x02
local TH_RST = 0x04
local TH_ACK = 0x10

--- Return the list of TCP ports to scan
-- @return ports an array of port objects
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

--- Make a host table, with ip and bin_ip fields, from a host specification string
-- @args hoststr hostname or IP address
-- @return the resulting table or nil on error
local function make_host_table(hoststr)
    if hoststr == nil then
        return nil
    end

    local status, addresses = nmap.resolve(hoststr, nmap.address_family())

    if status then
        local host = {}

        host.ip = addresses[1]
        host.bin_ip = packet.iptobin(host.ip)
        return host
    end

    return nil
end

--- Generate a TCP probe
-- @args src_ip source IPv4 address (packed)
-- @args dst_ip destination IPv4 address (packed)
-- @args sport TCP source port
-- @args dport TCP destination port
-- @args tcp_flags value of the TCP flags field
-- @return ip the resulting IP packet object
local function make_probe(src_ip, dst_ip, sport, dport, tcp_flags)
    local pktbin = bin.pack("H",
        "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
        "0000 0000 0000 0000 0000 0000 6002 0c00 0000 0000 0204 05b4"
    )

    local ip = packet.Packet:new(pktbin, pktbin:len())

    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_TCP)
    ip.ip_p = packet.IPPROTO_TCP
    ip:ip_set_len(pktbin:len())
    ip:ip_set_ttl(64)

    ip:ip_set_bin_src(src_ip)
    ip:ip_set_bin_dst(dst_ip)

    ip:tcp_parse(false)
    ip:tcp_set_flags(tcp_flags)
    ip:tcp_set_sport(sport)
    ip:tcp_set_dport(dport)
    ip:tcp_set_seq(math.random(1, 0x7fffffff))
    ip:tcp_count_checksum()
    ip:ip_count_checksum()

    return ip
end

--- Check wether an incoming packet is a correct reply or not
-- @arg scanner scanner object from which the expected values are read
-- @arg pkt the received reply
-- @arg flags expected flags
-- @return boolean result
local function check_reply(scanner, pkt, flags)
    local ip = packet.Packet:new(pkt, pkt:len())

    return (ip.ip_bin_dst == scanner.target.bin_ip_src
        and ip.ip_bin_src == scanner.target.bin_ip
        and ip.ip_p == packet.IPPROTO_TCP
        and ip.tcp_sport == scanner.current_port.number
        and ip.tcp_dport == scanner.scanport
        and ip.tcp_flags == flags)
end

--- Receive replies from the target
-- @arg scanner the scanner object from which scan parameters are read
-- @return status (true or false)
-- @return rst_coun number of catched replies or error string if status is false
local function read_replies(scanner)
    local timeout = 1000

    repeat
        local start = nmap.clock_ms()

        scanner.pcap:set_timeout(timeout)

        local status, res, _, l3, _ = scanner.pcap:pcap_receive()

        if not status and res ~= 'TIMEOUT' then
            nmap.set_port_state(scanner.target, scanner.current_port, "filtered");
            return false, res
        end

        if status then
            if check_reply(scanner, l3, bit.bor(TH_SYN, TH_ACK)) then
                nmap.set_port_state(scanner.target, scanner.current_port, "open");
            end
            if check_reply(scanner, l3, bit.bor(TH_RST, TH_ACK)) then
                nmap.set_port_state(scanner.target, scanner.current_port, "closed");
            end

        end

        timeout = timeout - (nmap.clock_ms() - start)

    until timeout <= 0

    return true

end

scanrule = function(host)
    if not nmap.is_privileged() then
        if nmap.verbosity() > 0 then
            stdnse.print_debug("%s not running for lack of privileges.", SCRIPT_NAME)
        end

        return false
    end

    if nmap.address_family() ~= 'inet' then
        stdnse.print_debug("%s is IPv4 compatible only.", SCRIPT_NAME)
        return false
    end

    if not host.interface then
        return false
    end

    return true
end

action = function(host)
    local saddr = packet.toip(host.bin_ip_src)
    local try = nmap.new_try()
    local ports = getports(host)
    local iface = host.interface
    local scanner = {
        sock = nmap.new_dnet(),
        pcap = nmap.new_socket(),
        target = host,
        current_port = 0,
        scanport = math.random(0x401, 0xffff)
    }

    scanner.pcap:pcap_open(iface, 104, false, "tcp and (dst host " .. saddr .. ") and (src host " .. host.ip .. ")")

    try(scanner.sock:ip_open())

    for _, port in ipairs(ports) do
        scanner.current_port = port
        stdnse.print_debug("Scanning port: %s", scanner.current_port.number)

        local probe_syn = make_probe(scanner.target.bin_ip_src,
                                       scanner.target.bin_ip,
                                       scanner.scanport,
                                       scanner.current_port.number,
                                       TH_SYN)

        -- send probes to the target & the scanner
        scanner.sock:ip_send(probe_syn.buf)
        stdnse.sleep(1)
        scanner.sock:ip_send(probe_syn.buf)

        local status, res = read_replies(scanner)
        if not status then
            stdnse.print_debug("%s: error (%s)", SCRIPT_NAME, res)
            scanner.sock:ip_close()
            scanner.pcap:pcap_close()
            return
        end

    end

    scanner.sock:ip_close()
    scanner.pcap:pcap_close()

end

