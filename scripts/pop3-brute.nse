local brute = require "brute"
local comm = require "comm"
local creds = require "creds"
local pop3 = require "pop3"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tries to log into a POP3 account by guessing usernames and passwords.
Automatically detects supported authentication mechanisms and upgrades
to TLS using STLS when available.
]]

author = {"Philip Pickering", "Piotr Olma", "Sweekar-cmd"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({110, 995}, {"pop3", "pop3s"})

---
-- Choose best supported auth method from CAPA
local function choose_auth(capas)
  if capas.AUTH then
    local mechs = {}
    for _, m in ipairs(capas.AUTH) do
      mechs[m:upper()] = true
    end

    if mechs["CRAM-MD5"] then
      return pop3.login_sasl_crammd5, false
    elseif mechs["LOGIN"] then
      return pop3.login_sasl_login, false
    elseif mechs["PLAIN"] then
      return pop3.login_sasl_plain, false
    end
  end

  if capas.APOP then
    return pop3.login_apop, true
  end

  return pop3.login_user, false
end

local Driver = {
  new = function(self, host, port, login_function, is_apop, use_stls, implicit_tls)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.login_function = login_function
    o.is_apop = is_apop
    o.use_stls = use_stls
    o.implicit_tls = implicit_tls
    return o
  end,

  connect = function(self)
    local opts = { timeout = 10000, recv_before = true }
    local line

    -- Implicit TLS (POP3S, usually port 995)
    if self.implicit_tls then
      self.socket = brute.new_socket()
      local ok = self.socket:connect(self.host, self.port, "ssl")
      if not ok then
        local err = brute.Error:new("SSL connection failed.")
        err:setAbort(true)
        return false, err
      end
      line = self.socket:receive_lines(1)
    else
      self.socket, _, _, line = comm.tryssl(self.host, self.port, "", opts)
    end

    if not self.socket then
      local err = brute.Error:new("Failed to connect.")
      err:setAbort(true)
      return false, err
    end

    if not pop3.stat(line) then
      local err = brute.Error:new("Invalid POP3 greeting.")
      err:setAbort(true)
      return false, err
    end

    -- Extract APOP challenge
    if self.is_apop then
      self.additional = line:match("<[^>]+>")
    end

    -- Upgrade to TLS using STLS (only for port 110)
    if self.use_stls then
      self.socket:send("STLS\r\n")
      local _, resp = self.socket:receive_lines(1)
      if not pop3.stat(resp) then
        local err = brute.Error:new("STLS negotiation failed.")
        err:setAbort(true)
        return false, err
      end

      local ssl = self.socket:sslhandshake()
      if not ssl then
        local err = brute.Error:new("TLS handshake failed.")
        err:setAbort(true)
        return false, err
      end
      self.socket = ssl
    end

    return true
  end,

  login = function(self, username, password)
    local ok, code =
      self.login_function(self.socket, username, password, self.additional)

    if ok then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end

    local err
    if code == pop3.err.pwError then
      err = brute.Error:new("Wrong password.")
    elseif code == pop3.err.userError then
      err = brute.Error:new("Wrong username.")
      err:setInvalidAccount(username)
    elseif code == pop3.err.OpenSSLMissing then
      err = brute.Error:new("OpenSSL required for this authentication method.")
      err:setAbort(true)
    else
      err = brute.Error:new("Login failed.")
    end

    return false, err
  end,

  disconnect = function(self)
    if self.socket then
      self.socket:close()
    end
  end,

  check = function(self)
    return true
  end,
}

action = function(host, port)
  local capas = pop3.capabilities(host, port)
  if not capas then
    return "Could not retrieve capabilities."
  end

  local login_function, is_apop = choose_auth(capas)

  local use_stls = capas.STLS and port.number == 110
  local implicit_tls = (port.number == 995 or port.service == "pop3s")

  if use_stls then
    stdnse.print_debug(1, "POP3: Upgrading to TLS using STLS")
  end

  local engine = brute.Engine:new(
    Driver,
    host,
    port,
    login_function,
    is_apop,
    use_stls,
    implicit_tls
  )

  engine.options.script_name = SCRIPT_NAME
  local _, accounts = engine:start()
  return accounts
end
