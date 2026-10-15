local brute    = require "brute"
local comm     = require "comm"
local creds    = require "creds"
local pop3     = require "pop3"
local shortport = require "shortport"
local stdnse   = require "stdnse"

description = [[
Tries to log into a POP3 account by guessing usernames and passwords.
Automatically detects supported authentication mechanisms via CAPA and
upgrades to TLS using STLS when available on port 110. Supports implicit
TLS for POP3S (port 995). The auth method can be overridden manually via
the <code>pop3loginmethod</code> script argument.
]]

---
-- @args pop3loginmethod Override automatic auth selection. Valid values:
--   <code>"USER"</code>, <code>"SASL-PLAIN"</code>,
--   <code>"SASL-LOGIN"</code>, <code>"SASL-CRAM-MD5"</code>,
--   <code>"APOP"</code>. If not set, the best method is chosen from CAPA.
--
-- @output
-- PORT    STATE SERVICE
-- 110/tcp open  pop3
-- | pop3-brute:
-- |   Accounts:
-- |     admin:password - Valid credentials
-- |   Statistics:
-- |_    Performed 101 guesses in 22 seconds, average tps: 4.5

author   = {"Philip Pickering", "Piotr Olma", "Sweekar-cmd"}
license  = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({110, 995, 1110}, {"pop3", "pop3s"})

-- Select the best available auth method from CAPA capabilities.
-- Preference order: CRAM-MD5 > LOGIN > PLAIN > APOP > USER
local function choose_auth(capas)
  local sasl = capas.SASL or capas.AUTH
  if sasl then
    local mechs = {}
    for _, m in ipairs(sasl) do
      mechs[m:upper()] = true
    end
    if mechs["CRAM-MD5"] then return pop3.login_sasl_crammd5, false end
    if mechs["LOGIN"]    then return pop3.login_sasl_login,   false end
    if mechs["PLAIN"]    then return pop3.login_sasl_plain,   false end
  end
  if capas.APOP then return pop3.login_apop, true end
  return pop3.login_user, false
end

local Driver = {
  new = function(self, host, port, opts)
    local o = setmetatable({}, self)
    self.__index = self
    o.host         = host
    o.port         = port
    o.login_function = opts.login_function
    o.is_apop      = opts.is_apop
    o.use_stls     = opts.use_stls
    o.implicit_tls = opts.implicit_tls
    return o
  end,

  connect = function(self)
    local line

    if self.implicit_tls then
      self.socket = brute.new_socket()
      local ok = self.socket:connect(self.host, self.port, "ssl")
      if not ok then
        local e = brute.Error:new("SSL connection failed.")
        e:setAbort(true)
        return false, e
      end
      local _, resp = self.socket:receive_lines(1)
      line = resp
    else
      self.socket, _, _, line =
        comm.tryssl(self.host, self.port, "", { timeout = 10000, recv_before = true })
    end

    if not self.socket then
      local e = brute.Error:new("Failed to connect.")
      e:setAbort(true)
      return false, e
    end

    if not pop3.stat(line) then
      local e = brute.Error:new("Invalid POP3 greeting.")
      e:setAbort(true)
      return false, e
    end

    if self.is_apop then
      self.additional = line:match("<[^>]+@[^>]+>")
    end

    if self.use_stls then
      self.socket:send("STLS\r\n")
      local _, resp = self.socket:receive_lines(1)
      if not pop3.stat(resp) then
        local e = brute.Error:new("STLS negotiation failed.")
        e:setAbort(true)
        return false, e
      end
      local ok, ssl_err = self.socket:reconnect_ssl()
      if not ok then
        local e = brute.Error:new("TLS handshake failed: " .. (ssl_err or "unknown"))
        e:setAbort(true)
        return false, e
      end
    end

    return true
  end,

  login = function(self, username, password)
    local ok, code =
      self.login_function(self.socket, username, password, self.additional)
    if ok then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end

    local e
    if code == pop3.err.pwError then
      e = brute.Error:new("Wrong password.")
    elseif code == pop3.err.userError then
      e = brute.Error:new("Wrong username.")
      e:setInvalidAccount(username)
    elseif code == pop3.err.OpenSSLMissing then
      e = brute.Error:new("OpenSSL required for this authentication method.")
      e:setAbort(true)
    else
      e = brute.Error:new("Login failed.")
    end
    return false, e
  end,

  disconnect = function(self)
    if self.socket then self.socket:close() end
  end,

  check = function(self) return true end,
}

action = function(host, port)
  local capas = pop3.capabilities(host, port)
  if not capas then
    return "Could not retrieve capabilities."
  end

  local login_function, is_apop

  -- Manual override takes priority over auto-detection
  local pMeth = stdnse.get_script_args("pop3loginmethod")
  if pMeth then
    if     pMeth == "SASL-PLAIN"    then login_function = pop3.login_sasl_plain
    elseif pMeth == "SASL-LOGIN"    then login_function = pop3.login_sasl_login
    elseif pMeth == "SASL-CRAM-MD5" then login_function = pop3.login_sasl_crammd5
    elseif pMeth == "APOP"          then login_function = pop3.login_apop; is_apop = true
    else                                 login_function = pop3.login_user
    end
  else
    login_function, is_apop = choose_auth(capas)
  end

  local implicit_tls = (port.number == 995 or port.service == "pop3s")
  local use_stls = (port.number == 110 and not implicit_tls and capas.STLS ~= nil)
  local engine = brute.Engine:new(Driver, host, port, {
    login_function = login_function,
    is_apop        = is_apop,
    use_stls       = use_stls,
    implicit_tls   = implicit_tls,
  })

  engine.options.script_name = SCRIPT_NAME
  local _, accounts = engine:start()
  return accounts
end
