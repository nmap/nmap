---
-- The VNC library provides some basic functionality needed in order to
-- communicate with VNC servers, and derivatives such as Tight- or Ultra-
-- VNC.
--
-- Summary
-- -------
-- The library currently supports the VNC Authentication security type only.
-- This security type is supported by default in VNC, TightVNC and
-- "Remote Desktop Sharing" in eg. Ubuntu. For servers that do not support
-- this authentication security type the login method will fail.
--
-- Overview
-- --------
-- The library contains the following classes:
--
--   o VNC
--     - This class contains the core functions needed to communicate with VNC
--

-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>

-- Version 0.1
-- Created 07/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

local bits = require "bits"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"
_ENV = stdnse.module("vnc", stdnse.seeall)

local HAVE_SSL, openssl = pcall(require,'openssl')

VENCRYPT_SUBTYPES = {
  PLAIN = 256,
  TLSNONE = 257,
  TLSVNC = 258,
  TLSPLAIN = 259,
  X509NONE = 260,
  X509VNC = 261,
  X509PLAIN = 262,
  X509SASL = 263,
  TLSSASL = 264,
}
VENCRYPT_SUBTYPES_STR = {
  [256] = "Plain",
  [257] = "None, Anonymous TLS",
  [258] = "VNC auth, Anonymous TLS",
  [259] = "Plain, Anonymous TLS",
  [260] = "None, Server-authenticated TLS",
  [261] = "VNC auth, Server-authenticated TLS",
  [262] = "Plain, Server-authenticated TLS",
  [263] = "SASL, Server-authenticated TLS",
  [264] = "SASL, Anonymous TLS",
}

local function process_error(socket)
  local status, tmp = socket:receive_buf(match.numbytes(4), true)
  if( not(status) ) then
    return false, "VNC:handshake failed to retrieve error message"
  end
  local len = string.unpack(">I4", tmp)
  local status, err = socket:receive_buf(match.numbytes(len), true)
  if( not(status) ) then
    return false, "VNC:handshake failed to retrieve error message"
  end
  return false, err
end

local function first_of (list, lookup)
  for i=1, #list do
    if tableaux.contains(lookup, list[i]) then
      return list[i]
    end
  end
end

-- generalized output formatter for security types and subtypes
local function get_types_as_table (types, lookup)
  local tmp = {}
  local typemt = {
    __tostring = function(me)
      return ("%s (%s)"):format(me.name, me.type)
    end
  }
  for i=1, types.count do
    local t = {name = lookup[types.types[i]] or "Unknown security type", type=types.types[i]}
    setmetatable(t, typemt)
    table.insert( tmp, t )
  end
  return tmp
end

VNC = {

  versions = {
    ["RFB 003.003"] = "3.3",
    ["RFB 003.007"] = "3.7",
    ["RFB 003.008"] = "3.8",

    -- Mac Screen Sharing, could probably be used to fingerprint OS
    ["RFB 003.889"] = "3.889",
  },

  sectypes = {
    INVALID = 0,
    NONE = 1,
    VNCAUTH = 2,
    RA2 = 5,
    RA2NE = 6,
    TIGHT = 16,
    ULTRA = 17,
    TLS = 18,
    VENCRYPT = 19,
    GTK_VNC_SASL = 20,
    MD5 = 21,
    COLIN_DEAN_XVP = 22,
    MAC_OSX_SECTYPE_30 = 30,
    MAC_OSX_SECTYPE_35 = 35,
    MSLOGON = 0xfffffffa,
  },

  -- Security types are fetched from the rfbproto.pdf
  sectypes_str = {
    [0] = "Invalid security type",
    [1] = "None",
    [2] = "VNC Authentication",
    [5] = "RA2",
    [6] = "RA2ne",
    [16]= "Tight",
    [17]= "Ultra",
    [18]= "TLS",
    [19]= "VeNCrypt",
    [20]= "GTK-VNC SASL",
    [21]= "MD5 hash authentication",
    [22]= "Colin Dean xvp",
    -- Mac OS X screen sharing uses 30 and 35
    [30]= "Apple Remote Desktop",
    [35]= "Mac OS X security type",
    [0xfffffffa] = "UltraVNC MS Logon",
  },

  new = function(self, host, port, socket)
    local o = {
      host = host,
      port = port,
      socket = socket or nmap.new_socket(),
    }
    o.socket:set_timeout(5000)
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects the VNC socket
  connect = function(self)
    return self.socket:connect(self.host, self.port, "tcp")
  end,

  --- Disconnects the VNC socket
  disconnect = function(self)
    return self.socket:close()
  end,

  --- Performs the VNC handshake and determines
  -- * The RFB Protocol to use
  -- * The supported authentication security types
  --
  -- @return status, true on success, false on failure
  -- @return error string containing error message if status is false
  handshake = function(self)
    local status, data = self.socket:receive_buf(match.pattern_limit("[\r\n]+", 16), true)
    if not status or not string.match(data, "^RFB %d%d%d%.%d%d%d[\r\n]") then
      stdnse.debug1("ERROR: Not a VNC port. Banner: %s", data)
      return false, "Not a VNC port."
    end
    data = data:sub(1,11)
    local vncsec = {
      count = 1,
      types = {}
    }

    if ( not(status) ) then
      return status, "ERROR: VNC:handshake failed to receive protocol version"
    end

    self.protover = VNC.versions[data]
    local cli_version = data
    if ( not(self.protover) ) then
      stdnse.debug1("ERROR: VNC:handshake unsupported version (%s)", data)
      self.protover = string.match(data, "^RFB (%d+%.%d+)")
      --return false, ("Unsupported version (%s)"):format(data:sub(1,11))
      local versions = {
        "RFB 003.003",
        "RFB 003.007",
        "RFB 003.008",
        "RFB 003.889",
      }
      for i=1, #versions do
        if versions[i] >= data then
          break
        end
        cli_version = versions[i]
      end
    end

    self.client_version = VNC.versions[cli_version or "RFB 003.889"]
    status = self.socket:send( (cli_version or "RFB 003.889") .. "\n" )
    if ( not(status) ) then
      stdnse.debug1("ERROR: VNC:handshake failed to send client version")
      return false, "ERROR: VNC:handshake failed"
    end

    if ( self.client_version == "3.3" ) then
      local status, tmp = self.socket:receive_buf(match.numbytes(4), true)
      if( not(status) ) then
        return false, "VNC:handshake failed to receive security data"
      end

      vncsec.types[1] = string.unpack(">I4", tmp)
      self.vncsec = vncsec

      -- do we have an invalid security type, if so we need to handle an
      -- error condition
      if ( vncsec.types[1] == 0 ) then
        return process_error(self.socket)
      end
    else
      local status, tmp = self.socket:receive_buf(match.numbytes(1), true)
      if ( not(status) ) then
        stdnse.debug1("ERROR: VNC:handshake failed to receive security data")
        return false, "ERROR: VNC:handshake failed to receive security data"
      end

      vncsec.count = string.unpack("B", tmp)
      if ( vncsec.count == 0 ) then
        return process_error(self.socket)
      end
      status, tmp = self.socket:receive_buf(match.numbytes(vncsec.count), true)

      if ( not(status) ) then
        stdnse.debug1("ERROR: VNC:handshake failed to receive security data")
        return false, "ERROR: VNC:handshake failed to receive security data"
      end

      for i=1, vncsec.count do
        table.insert( vncsec.types, (string.unpack("B", tmp, i)) )
      end
      self.vncsec = vncsec
    end

    return true
  end,

  --- Creates the password bit-flip needed before DES encryption
  --
  -- @param password string containing the password to process
  -- @return password string containing the processed password
  createVNCDESKey = function( self, password )
    -- exactly 8 chars needed
    if #password > 8 then
      password = password:sub(1,8)
    elseif #password < 8 then
      password = password .. string.rep('\0', 8 - #password)
    end
    return password:gsub(".", function(c) return string.char(bits.reverse(c:byte())) end)
  end,

  --- Encrypts a password with the server's challenge to create the challenge response
  --
  -- @param password string containing the password to process
  -- @param challenge string containing the server challenge
  -- @return the challenge response string
  encryptVNCDES = function (self, password, challenge)
    local key = self:createVNCDESKey(password)
    return openssl.encrypt("des-ecb", key, nil, challenge, false)
  end,

  sendSecType = function (self, sectype)
    return self.socket:send( string.pack("B", sectype))
  end,

  --- Attempts to login to the VNC service using any supported method
  --
  -- @param username string, could be anything when VNCAuth is used
  -- @param password string containing the password to use for authentication
  -- @param authtype The VNC auth type from the <code>VNC.sectypes</code> table (default: best available method)
  -- @return status true on success, false on failure
  -- @return err string containing error message when status is false
  login = function( self, username, password, authtype )
    if ( not(password) ) then
      return false, "No password was supplied"
    end

    if not authtype then
      if self:supportsSecType( VNC.sectypes.NONE ) then
        self:sendSecType(VNC.sectypes.NONE)
        return self:login_none()

      elseif self:supportsSecType( VNC.sectypes.VNCAUTH ) then
        self:sendSecType(VNC.sectypes.VNCAUTH)
        return self:login_vncauth(username, password)

      elseif self:supportsSecType( VNC.sectypes.TLS ) then
        self:sendSecType(VNC.sectypes.TLS)
        return self:login_tls(username, password)

      elseif self:supportsSecType( VNC.sectypes.VENCRYPT ) then
        self:sendSecType(VNC.sectypes.VENCRYPT)
        return self:login_vencrypt(username, password)

      elseif self:supportsSecType( VNC.sectypes.TIGHT ) then
        self:sendSecType(VNC.sectypes.TIGHT)
        return self:login_tight(username, password)

      elseif self:supportsSecType( VNC.sectypes.MAC_OSX_SECTYPE_30 ) then
        self:sendSecType(VNC.sectypes.MAC_OSX_SECTYPE_30)
        return self:login_ard(username, password)

      else
        return false, "The server does not support any matching security type"
      end
    elseif ( not( self:supportsSecType( authtype ) ) ) then
      return false, string.format(
        'The server does not support the "%s" security type.', VNC.sectypes_str[authtype])
    end

  end,

  login_none = function (self)
    if self.client_version == "3.8" then
      return self:check_auth_result()
    end
    -- nothing to do here!
    return true
  end,

  --- Attempts to login to the VNC service using VNC Authentication
  --
  -- @param username string, could be anything when VNCAuth is used
  -- @param password string containing the password to use for authentication
  -- @return status true on success, false on failure
  -- @return err string containing error message when status is false
  login_vncauth = function( self, username, password )
    local status, chall = self.socket:receive_buf(match.numbytes(16), true)
    if ( not(status) ) then
      return false, "Failed to receive authentication challenge"
    end

    local resp = self:encryptVNCDES(password, chall)

    status = self.socket:send( resp )
    if ( not(status) ) then
      return false, "Failed to send authentication response to server"
    end
    return self:check_auth_result()
  end,

  check_auth_result = function(self)
    local status, result = self.socket:receive_buf(match.numbytes(4), true)
    if ( not(status) ) then
      return false, "Failed to retrieve authentication status from server"
    end

    if string.unpack(">I4", result) ~= 0 then
      return false, "Authentication failed"
    end
    return true
  end,

  handshake_aten = function(self, buffer)
    -- buffer is 24 bytes, currently unused, no idea what it's for.
    if #buffer ~= 24 then
      return false
    end
    self.aten = buffer
    return true
  end,

  login_aten = function(self, username, password)
    username = username or ""
    self.socket:send(username .. ("\0"):rep(24 - #username) .. password .. ("\0"):rep(24 - #password))
    return self:check_auth_result()
  end,

  handshake_tight = function(self)
    -- TightVNC security type
    -- https://vncdotool.readthedocs.org/en/0.8.0/rfbproto.html#tight-security-type
    -- Sometimes also ATEN KVM VNC:
    -- https://github.com/thefloweringash/chicken-aten-ikvm
    local status, buf = self.socket:receive_bytes(4)
    if not status then
      return false, "Failed to get number of tunnels"
    end
    -- If it's ATEN, it sends 24 bytes right away. Need to try parsing these
    -- in case it's TightVNC instead, though.
    local aten = #buf == 24 and buf
    local ntunnels, pos = string.unpack(">I4", buf)
    -- reasonable limits: ATEN might send a huge number here
    if ntunnels > 0x10000 then
      return self:handshake_aten(aten)
    end
    local tight = {
      tunnels = {},
      types = {}
    }
    if ntunnels > 0 then
      local have = #buf - pos + 1
      if have < 16 * ntunnels then
        local newbuf
        status, newbuf = self.socket:receive_bytes(16 * ntunnels - have)
        if not status then
          if aten then
            return self:handshake_aten(aten)
          end
          return false, "Failed to get list of tunnels"
        end
        buf = buf .. newbuf
        aten = false -- we must have read something beyond 24 bytes
      end

      local have_none_tunnel = false
      for i=1, ntunnels do
        local tunnel = {}
        tunnel.code, tunnel.vendor, tunnel.signature, pos = string.unpack(">I4 c4 c8", buf, pos)
        if tunnel.code == 0 then
          have_none_tunnel = true
        end
        tight.tunnels[#tight.tunnels+1] = tunnel
      end

      -- at this point, might still be ATEN with a first byte of 1, but chances are it's Tight
      if have_none_tunnel then
        -- Try the "NOTUNNEL" tunnel, for simplicity, if it's available.
        self.socket:send("\0\0\0\0")
      else
        -- for now, just return the first one. TODO: choose a supported tunnel type
        self.socket:send(string.pack(">I4", tight.tunnels[1].code))
      end
    end

    local have = #buf - pos + 1
    if have < 4 then
      local newbuf
      status, newbuf = self.socket:receive_bytes(4 - have)
      if not status then
        if aten then
          return self:handshake_aten(aten)
        end
        return false, "Failed to get number of Tight auth types"
      end
      buf = buf .. newbuf
      if #buf > 24 then aten = false end
    end
    local nauth
    nauth, pos = string.unpack(">I4", buf, pos)
    -- reasonable limits: ATEN might send a huge number here
    if nauth > 0x10000 then
      return self:handshake_aten(aten)
    end
    if nauth > 0 then
      have = #buf - pos + 1
      if have < 16 * nauth then
        local newbuf
        status, newbuf = self.socket:receive_bytes(16 * nauth - have)
        if not status then
          if aten then
            return self:handshake_aten(aten)
          end
          return false, "Failed to get list of Tight auth types"
        end
        buf = buf .. newbuf
        if #buf > 24 then aten = false end
      end

      for i=1, nauth do
        local auth = {}
        auth.code, auth.vendor, auth.signature, pos = string.unpack(">I4 c4 c8", buf, pos)
        tight.types[#tight.types+1] = auth
      end
    end

    if aten and pos < 24 then
      -- server sent 24 bytes but we could only parse some of them. Probably ATEN KVM
      return self:handshake_aten(aten)
    end

    self.tight = tight

    return true
  end,

  login_tight = function(self, username, password)
    local status, err = self:handshake_tight()
    if not status then
      return status, err
    end

    if self.aten then
      return self:login_aten(username, password)
    end

    if #self.tight.types == 0 then
      -- nothing further, no auth
      return true
    end

    -- choose a supported auth type
    for _, auth in ipairs({
        {1, "login_none"},
        {2, "login_vncauth"},
        {19, "login_vencrypt"},
      }) do
      for _, t in ipairs(self.tight.types) do
        if t.code == auth[1] then
          self.socket:send(string.pack(">I4", t.code))
          return self[auth[2]](self, username, password)
        end
      end
    end
    return false, "The server does not support any supported Tight security type"
  end,

  handshake_tls = function(self)
    local status, err = self.socket:reconnect_ssl()
    if not status then
      return false, "Failed to reconnect SSL"
    end

    local status, tmp = self.socket:receive_buf(match.numbytes(1), true)
    if ( not(status) ) then
      stdnse.debug1("ERROR: VNC:handshake failed to receive security data")
      return false, "ERROR: VNC:handshake failed to receive security data"
    end

    local vncsec = {
      count = 1,
      types = {}
    }
    vncsec.count = string.unpack("B", tmp)
    if ( vncsec.count == 0 ) then
      return process_error(self.socket)
    end
    status, tmp = self.socket:receive_buf(match.numbytes(vncsec.count), true)

    if ( not(status) ) then
      stdnse.debug1("ERROR: VNC:handshake failed to receive security data")
      return false, "ERROR: VNC:handshake failed to receive security data"
    end
    for i=1, vncsec.count do
      table.insert( vncsec.types, (string.unpack("B", tmp, i)) )
    end
    self.vncsec = vncsec
    return true
  end,

  login_tls = function( self, username, password )
    local status, err = self:handshake_tls()
    if not status then
      return status, err
    end
    return self:login(username, password)
  end,

  handshake_vencrypt = function(self)
    local status, buf = self.socket:receive_buf(match.numbytes(2), true)
    local maj, min, pos = string.unpack("BB", buf)
    if maj ~= 0 or min ~= 2 then
      return false, string.format("Unknown VeNCrypt version: %d.%d", maj, min)
    end
    self.socket:send(string.pack("BB", maj, min))
    status, buf = self.socket:receive_buf(match.numbytes(1), true)
    status, pos = string.unpack("B", buf)
    if status ~= 0 then
      return false, string.format("Server refused VeNCrypt version %d.%d", maj, min)
    end

    status, buf = self.socket:receive_buf(match.numbytes(1), true)
    local nauth, pos = string.unpack("B", buf)
    if nauth == 0 then
      return false, "No VeNCrypt auth subtypes received"
    end

    -- vencrypt auth types are u32
    status, buf = self.socket:receive_buf(match.numbytes(nauth * 4), true)
    pos = 1
    local vencrypt = {
      count = nauth,
      types = {}
    }
    for i=1, nauth do
      local auth
      auth, pos = string.unpack(">I4", buf, pos)
      table.insert(vencrypt.types, auth)
    end
    self.vencrypt = vencrypt
    return true
  end,

  login_vencrypt = function(self, username, password)
    local status, err = self:handshake_vencrypt()
    if not status then
      return status, err
    end

    local subauth = first_of({
        VENCRYPT_SUBTYPES.TLSNONE,
        VENCRYPT_SUBTYPES.X509NONE,
        VENCRYPT_SUBTYPES.PLAIN,
        VENCRYPT_SUBTYPES.TLSPLAIN,
        VENCRYPT_SUBTYPES.X509PLAIN,
        VENCRYPT_SUBTYPES.TLSVNC,
        VENCRYPT_SUBTYPES.X509VNC,
        -- These not supported yet
        --VENCRYPT_SUBTYPES.TLSSASL,
        --VENCRYPT_SUBTYPES.X509SASL,
      }, self.vencrypt.types)

    if not subauth then
      return false, "The server does not support any supported security type"
    end

    self.socket:send(string.pack(">I4", subauth))
    local status, buf = self.socket:receive_buf(match.numbytes(1), true)
    if not status or string.byte(buf, 1) ~= 1 then
      return false, "VeNCrypt auth subtype refused"
    end

    if subauth == VENCRYPT_SUBTYPES.PLAIN then
      return self:login_plain(username, password)
    end

    status, err = self.socket:reconnect_ssl()
    if not status then
      return false, "Failed to reconnect SSL to VNC server"
    end

    if subauth == VENCRYPT_SUBTYPES.TLSNONE or subauth == VENCRYPT_SUBTYPES.X509NONE then
      return self:check_auth_result()
    elseif subauth == VENCRYPT_SUBTYPES.TLSVNC or subauth == VENCRYPT_SUBTYPES.X509VNC then
      return self:login_vncauth(username, password)
    elseif subauth == VENCRYPT_SUBTYPES.TLSPLAIN or subauth == VENCRYPT_SUBTYPES.X509PLAIN then
      return self:login_plain(username, password)
    elseif subauth == VENCRYPT_SUBTYPES.TLSSASL or subauth == VENCRYPT_SUBTYPES.X509SASL then
      return self:login_sasl(username, password)
    end

  end,

  login_plain = function(self, username, password)
    username = username or ""
    local status = self.socket:send(string.pack(">I4 I4", #username, #password) .. username .. password)
    if not status then
      return false, "Failed to send plain auth"
    end

    return self:check_auth_result()
  end,

  login_sasl = function(self, username, password)
    -- TODO: support this!
    return false, "Unsupported"
  end,

  login_ard = function(self, username, password)
    -- Check for empty username
    if not username then
      return false, "No username provided"
    end
    
    -- Thanks to David Simmons for describing this protocol:
    -- https://cafbit.com/post/apple_remote_desktop_quirks/
    local status, buf = self.socket:receive_bytes(4)
    if not status then
      return false, "Failed to get auth material lengths"
    end
    local gen, keylen, pos = string.unpack(">I2I2", buf)
    if #buf - (pos - 1) < 2*keylen then
      local status, buf2 = self.socket:receive_bytes(2*keylen - #buf)
      if not status then
        return false, "Failed to get auth material"
      end
      buf = buf .. buf2
    end
    local modulus, pos = string.unpack("c"..keylen, buf, pos)
    local pubkey, pos = string.unpack("c"..keylen, buf, pos)

    -- DH key exchange
    pubkey = openssl.bignum_bin2bn(pubkey)
    modulus = openssl.bignum_bin2bn(modulus)
    gen = openssl.bignum_dec2bn(gen)

    local secret = openssl.bignum_pseudo_rand(512) -- 512 bit DH? yeah, ok.
    local ourkey = openssl.bignum_mod_exp(gen, secret, modulus)
    local shared = openssl.bignum_mod_exp(pubkey, secret, modulus)

    -- Pad shared secret with nulls
    shared = openssl.bignum_bn2bin(shared)
    shared = ('\0'):rep(keylen - #shared) .. shared

    -- Generate AES key as MD5 of shared DH secret
    local aeskey = openssl.md5(shared)

    -- Encrypt username and password with AES in ECB mode
    local blob = username .. ('\0'):rep(64 - #username) .. password .. ('\0'):rep(64 - #password)
    local hash = openssl.encrypt('aes-128-ecb', aeskey, '', blob, false)

    -- Send encrypted blob and DH public key
    local tmpkey = openssl.bignum_bn2bin(ourkey)
    -- pad public key on the left with nulls
    self.socket:send(hash .. ('\0'):rep(keylen - #tmpkey) .. tmpkey)

    return self:check_auth_result()
  end,

  --- Returns all supported security types as a table
  --
  -- @return table containing a entry for each security type
  getSecTypesAsTable = function( self )
    return get_types_as_table(self.vncsec, VNC.sectypes_str)
  end,
  getVencryptTypesAsTable = function (self)
    return get_types_as_table(self.vencrypt, VENCRYPT_SUBTYPES_STR)
  end,

  --- Checks if the supplied security type is supported or not
  --
  -- @param sectype number containing the security type to check for
  -- @return status true if supported, false if not supported
  supportsSecType = function( self, sectype )
    for i=1, self.vncsec.count do
      if ( self.vncsec.types[i] == sectype ) then
        return true
      end
    end
    return false
  end,

  --- Returns the protocol version reported by the server
  --
  -- @param version string containing the version number
  getProtocolVersion = function( self )
    return self.protover
  end,

  --- Send a ClientInit message.
  --@param shared boolean determining whether the screen should be shared, or whether other logged-on users should be booted.
  --@return status true if message was successful, false otherwise
  --@return table containing contents of ServerInit message, or error message.
  client_init = function (self, shared)
    self.socket:send(shared and "\x01" or "\x00")
    local status, buf = self.socket:receive_buf(match.numbytes(24), true)
    if not status then
      return false, "Did not receive ServerInit message"
    end
    local width, height, bpp, depth, bigendian, truecolor, rmax, gmax, bmax, rshift, gshift, bshift, pad1, pad2, namelen, pos = string.unpack(">I2I2 BBBB I2I2 I2BB BI2B I4", buf)
    local status, buf = self.socket:receive_buf(match.numbytes(namelen), true)
    if not status then
      return false, "Did not receive ServerInit desktop name"
    end
    local name = buf:sub(1,namelen)
    return true, {
      width = width,
      height = height,
      bpp = bpp,
      depth = depth,
      bigendian = bigendian,
      truecolor = truecolor,
      rmax = rmax,
      gmax = gmax,
      bmax = bmax,
      rshift = rshift,
      gshift = gshift,
      bshift = bshift,
      name = name
    }

  end
}

if not HAVE_SSL then
  local login_unsupported = function()
    return false, "Login type unsupported without OpenSSL"
  end
  VNC.login_vncauth = login_unsupported
  VNC.login_tls = login_unsupported
  VNC.login_ard = login_unsupported
end

local unittest = require "unittest"
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()
-- Crypto tests require OpenSSL
if HAVE_SSL then
  local test_vectors = {
    -- from John the Ripper's vnc_fmt_plug.c
    -- pass, challenge, response
    {
      "1234567890",
      "\x2f\x75\x32\xb3\xef\xd1\x7e\xea\x5d\xd3\xa0\x94\x9f\xfd\xf1\xd8",
      "\x0e\xb4\x2d\x4d\x9a\xc1\xef\x1b\x6e\xf6\x64\x7b\x95\x94\xa6\x21"
    },
    {
      "123",
      "\x79\x63\xf9\xbb\x7b\xa6\xa4\x2a\x08\x57\x63\x80\x81\x56\xf5\x70",
      "\x47\x5b\x10\xd0\x56\x48\xe4\x11\x0d\x77\xf0\x39\x16\x10\x6f\x98"
    },
    {
      "Password",
      "\x08\x05\xb7\x90\xb5\x8e\x96\x7f\x2a\x35\x0a\x0c\x99\xde\x38\x81",
      "\xae\xcb\x26\xfa\xea\xaa\x62\xd7\x96\x36\xa5\x93\x4b\xac\x10\x78"
    },
    {
      "pass\xc2\xA3",
      "\x84\x07\x6f\x04\x05\x50\xee\xa9\x34\x19\x67\x63\x3b\x5f\x38\x55",
      "\x80\x75\x75\x68\x95\x82\x37\x9f\x7d\x80\x7f\x73\x6d\xe9\xe4\x34"
    },
  }

  for _, v in ipairs(test_vectors) do
    test_suite:add_test(unittest.equal(
      VNC:encryptVNCDES(v[1], v[2]), v[3]), v[1])
  end
end

return _ENV
