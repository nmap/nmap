local bin = require "bin"
local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local openssl = stdnse.silent_require "openssl"

description = [[
Performs brute force password auditing against an Nping Echo service.

See https://nmap.org/book/nping-man-echo-mode.html for Echo Mode
documentation.
]]

---
-- @usage
-- nmap -p 9929 --script nping-brute <target>
--
-- @output
-- 9929/tcp open  nping-echo
-- | nping-brute:
-- |   Accounts
-- |     123abc => Valid credentials
-- |   Statistics
-- |_    Perfomed 204 guesses in 204 seconds, average tps: 1

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}


portrule = shortport.port_or_service(9929, "nping-echo")

local function readmessage(socket, length)
  local msg = ""
  while #msg < length do
    local status, tmp = socket:receive_bytes(1)
    if not status then
      return nil
    end
    msg = msg .. tmp
  end
  return msg
end

Driver =
{
  NEP_VERSION = 0x01,
  AES_128_CBC = "aes-128-cbc",
  SHA256 = "sha256",

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  nepkey = function(self, password, nonce, typeid)
    local seed = password .. nonce .. typeid
    local h = openssl.digest(self.SHA256, seed)
    for i = 1, 1000 do
      h = openssl.digest(self.SHA256, h)
    end
    local _, key = bin.unpack("A16", h)
    return key
  end,

  getservernonce = function(self, serverhs)
    local parts = {bin.unpack("CC>S>I>Ix4A32x15A32", serverhs)}
    return parts[7]
  end,

  chsbody = function(self)
    local IP4 = 0x04
    local IP6 = 0x06
    local family = IP6
    local target = self.host.bin_ip
    if #target == 4 then
      target = bin.pack("Ax12", target)
      family = IP4
    end
    return bin.pack("ACx15", target, family)
  end,

  clienths = function(self, snonce, password)
    local NEP_HANDSHAKE_CLIENT = 0x02
    local NEP_HANDSHAKE_CLIENT_LEN = 36
    local NEP_CLIENT_CIPHER_ID = "NEPkeyforCiphertextClient2Server"
    local NEP_CLIENT_MAC_ID = "NEPkeyforMACClient2Server"

    local now = nmap.clock()
    local seqb = openssl.rand_bytes(4)
    local cnonce = openssl.rand_bytes(32)
    local nonce = snonce .. cnonce
    local enckey = self:nepkey(password, nonce, NEP_CLIENT_CIPHER_ID)
    local mackey = self:nepkey(password, nonce, NEP_CLIENT_MAC_ID)
    local _, iv = bin.unpack("A16", cnonce)
    local plain = self:chsbody()
    local crypted = openssl.encrypt(self.AES_128_CBC, enckey, iv, plain)
    local head = bin.pack("CC>SA>Ix4A", self.NEP_VERSION, NEP_HANDSHAKE_CLIENT, NEP_HANDSHAKE_CLIENT_LEN, seqb, now, nonce)
    local mac = openssl.hmac(self.SHA256, mackey, head .. plain)

    return head .. crypted .. mac
  end,

  testpass = function(self, password)
    local SERVERHS_LEN = 96
    local FINALHS_LEN = 112
    local serverhs = readmessage(self.socket, SERVERHS_LEN)
    if serverhs == nil then
      return false
    end
    local snonce = self:getservernonce(serverhs)
    local response = self:clienths(snonce, password)
    self.socket:send(response)
    local finalhs = readmessage(self.socket, FINALHS_LEN)
    if finalhs == nil then
      return false
    end
    return true
  end,

  connect = function(self)
    self.socket = nmap.new_socket()
    return self.socket:connect(self.host, self.port)
  end,

  login = function(self, _, password)
    if self:testpass(password) then
      return true, creds.Account:new("", password, creds.State.VALID)
    end
    return false, brute.Error:new("Incorrect password")
  end,

  disconnect = function(self)
    return self.socket:close()
  end,
}

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.firstonly = true
  engine.options:setOption("passonly", true)
  engine.options.script_name = SCRIPT_NAME
  local status, result = engine:start()
  return result
end
