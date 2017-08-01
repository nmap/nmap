local bin = require('bin')
local bit = require('bit')
local nmap = require('nmap')
local stdnse = require('stdnse')
local packet = require('packet')

description = [[
Perform port scan using RST rate limiting of a zombie machine. This scan is
similar to the traditional idle scan as the actual IP address of the scanner is
never revealed to the target, but it relies upon RST rate limitation on the
zombie instead of predictable IP ID sequences.

See http://www.usenix.org/events/sec10/tech/full_papers/Ensafi.pdf for the
details.
]]


---
-- @usage
-- nmap -sK --script=idlescan-rst --script-args=idlescan-rst.zombie=10.0.0.1:1234 <host>
--
-- @args idlescan-rst.zombie zombie specification string expressed as host:port
-- @args idlescan-rst.iface alternative interface to use for packet capture
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

author = "Henri Doreau"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


-- # of probes to send per port
local NB_PROBES = 500

-- # of probe to send per second and per host (target & zombie)
local SEND_RATE = 180

-- proportion of replied probes under which we consider the port as open (0 < x < 1)
local OPEN_PORT_TRESHOLD = 0.90


-- TCP flags
local TH_SYN = 0x02
local TH_RST = 0x04
local TH_ACK = 0x10


--- Get zombie specification from command line
-- @return zombiehost string describing the zombie host (hostname or IP address)
-- @return zombieport string describing the zombie port
local function get_zombie_spec()
    local zombiestr = stdnse.get_script_args("idlescan-rst.zombie")

    if not zombiestr then
        stdnse.print_debug('%s: missing mandatory argument "idlescan-rst.zombie"', SCRIPT_NAME)
        return nil
    end

    local tokens = stdnse.strsplit(":", zombiestr)
    if #tokens ~= 2 then
        stdnse.print_debug('%s: invalid zombie specification (use host:port format)', SCRIPT_NAME)
        return nil
    end

    return unpack(tokens)
end

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
-- @return boolean result
local function check_reply(scanner, pkt)
    local ip = packet.Packet:new(pkt, pkt:len())

    return (ip.ip_bin_dst == scanner.target.bin_ip_src
        and ip.ip_bin_src == scanner.zombiehost.bin_ip
        and ip.ip_p == packet.IPPROTO_TCP
        and ip.tcp_sport == scanner.zombieport
        and ip.tcp_dport == scanner.scanport
        and bit.band(ip.tcp_flags, TH_RST) == TH_RST)
end

--- Receive replies from the zombie
-- @arg scanner the scanner object from which scan parameters are read
-- @return status (true or false)
-- @return rst_coun number of catched replies or error string if status is false
local function read_replies(scanner)
    local rst_count = 0
    local timeout = 1000 / SEND_RATE

    repeat
        local start = nmap.clock_ms()

        scanner.pcap:set_timeout(timeout)

        local status, res, _, l3, _ = scanner.pcap:pcap_receive()

        if not status and res ~= 'TIMEOUT' then
            return false, res
        end

        if status and check_reply(scanner, l3) then
            rst_count = rst_count + 1
        end

        timeout = timeout - (nmap.clock_ms() - start)

    until timeout <= 0

    return true, rst_count

end

scanrule = function(host)
    if not nmap.is_privileged() then
        if not nmap.registry['idlescan-rst'] then
            nmap.registry['idlescan-rst'] = {}
        end

        if nmap.registry['idlescan-rst']['rootfail'] then
            return false
        end

        nmap.registry['idlescan-rst']['rootfail'] = true

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
    local iface = stdnse.get_script_args("idlescan-rst.iface") or host.interface
    local zombiehost, zombieport = get_zombie_spec()
    local scanner = {
        sock = nmap.new_dnet(),
        pcap = nmap.new_socket(),
        target = host,
        zombiehost = make_host_table(zombiehost),
        zombieport = tonumber(zombieport),
        scanport = math.random(0x401, 0xffff)
    }

    if not scanner.zombiehost or not scanner.zombieport then
        stdnse.print_debug("%s: invalid zombie specification (use idlescan-rst.zombie=<host>:<port>)", SCRIPT_NAME)
        return
    end

    -- filter tcp packets exchanged between us and the zombie
    
    scanner.pcap:pcap_open(iface, 104, false, "tcp and (dst host " .. saddr .. ") and (src host " .. scanner.zombiehost.ip .. ")")

    try(scanner.sock:ip_open())

    -- the TCP SYN|ACK probe to send to the zombie
    local probe_synack = make_probe(scanner.target.bin_ip_src,
                              scanner.zombiehost.bin_ip,
                              scanner.scanport,
                              scanner.zombieport,
                              bit.bor(TH_SYN, TH_ACK))

    ---- MAIN SCANNING LOOP ----
    for _, port in ipairs(ports) do

        local rst_count = 0

        -- the TCP SYN spoofed probe to send to the target (masquerading as the zombie)
        local probe_spoofed_syn = make_probe(scanner.zombiehost.bin_ip,
                                       scanner.target.bin_ip,
                                       scanner.zombieport,
                                       port.number,
                                       TH_SYN)

        for i = 1, NB_PROBES do
            -- send probes to the target & the scanner
            scanner.sock:ip_send(probe_spoofed_syn.buf)
            scanner.sock:ip_send(probe_synack.buf)

            local status, res = read_replies(scanner)
            if not status then
                stdnse.print_debug("%s: error (%s)", SCRIPT_NAME, res)
                scanner.sock:ip_close()
                scanner.pcap:pcap_close()
                return
            end

            -- count the number of received RST
            rst_count = rst_count + res
        end
            
        stdnse.print_debug("rst_count for port %d/%s: %.02f%% (%d/%d)",
            port.number, port.protocol, (100  * rst_count) / NB_PROBES, rst_count, NB_PROBES)

        if rst_count < (OPEN_PORT_TRESHOLD * NB_PROBES) then
            nmap.set_port_state(host, port, "open");
        else
            nmap.set_port_state(host, port, "closed");
        end
    end

    scanner.sock:ip_close()
    scanner.pcap:pcap_close()

end

