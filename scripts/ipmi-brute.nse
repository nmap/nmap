local brute = require "brute"
local creds = require "creds"
local ipmi = require "ipmi"
local shortport = require "shortport"
local rand = require "rand"

description = [[
Performs brute force password auditing against IPMI RPC server.
]]

---
-- @usage
-- nmap -sU --script ipmi-brute -p 623 <host>
--
-- @output
-- PORT     STATE  SERVICE REASON
-- 623/udp  open|filtered  unknown
-- | ipmi-brute:
-- |   Accounts
-- |_    admin:admin => Valid credentials
--

author = "Claudiu Perta"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(623, "asf-rmcp", "udp", {"open", "open|filtered"})

Driver = {

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  connect = function(self)
    self.socket = brute.new_socket()
    self.socket:set_timeout(
      ((self.host.times and self.host.times.timeout) or 8) * 1000)
    self.socket:connect(self.host, self.port, "udp")

    return true
  end,

  login = function(self, username, password)
    local console_session_id = rand.random_string(4)
    local console_random_id = rand.random_string(16)

    local request = ipmi.session_open_request(console_session_id)
    local status, reply

    self.socket:send(request)
    status, reply = self.socket:receive()

    if not status then
      return false, brute.Error:new(
        "No response to IPMI open session request")
    end

    local session = ipmi.parse_open_session_reply(reply)
    if session["session_payload_type"] ~= ipmi.PAYLOADS["RMCPPLUSOPEN_REP"] then
      return false, brute.Error:new("Unknown response to open session request")
    end

    if session["error_code"] ~= 0 then
      return false, brute.Error:new(ipmi.RMCP_ERRORS[session.error_code] or "Unknown error")
    end
    local bmc_session_id = session["bmc_session_id"]
    local rakp1_request = ipmi.rakp_1_request(
      bmc_session_id, console_random_id, username)

    self.socket:send(rakp1_request)
    status, reply = self.socket:receive()

    if not status then
      return false, brute.Error:new("No response to RAKP1 message")
    end

    local rakp2_message = ipmi.parse_rakp_1_reply(reply)
    if rakp2_message["session_payload_type"] ~= ipmi.PAYLOADS["RAKP2"] then
      return false, brute.Error:new("Unknown response to RAPK1 request")
    end

    if rakp2_message["error_code"] ~= 0 then
      return false, brute.Error:new(
        ipmi.RMCP_ERRORS[rakp2_message["error_code"]])
    end

    local hmac_salt = ipmi.rakp_hmac_sha1_salt(
      console_session_id,
      session["bmc_session_id"],
      console_random_id,
      rakp2_message["bmc_random_id"],
      rakp2_message["bmc_guid"],
      0x14,
      username
    )

    local found = ipmi.verify_rakp_hmac_sha1(
      hmac_salt, rakp2_message["hmac_sha1"], password)

    if found then
      return true, creds.Account:new(username, password, creds.State.VALID)
    else
      return false, brute.Error:new("Incorrect password")
    end

  end,

  disconnect = function(self)
    self.socket:close()
  end,

  check = function(host, port)
    return true
  end
}

action = function(host, port)
  local status, result
  local engine = brute.Engine:new(Driver, host, port)

  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()
  return result
end
