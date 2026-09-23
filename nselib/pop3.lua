---
-- POP3 helper functions for NSE scripts.
--
-- @copyright Same as Nmap
-- See https://nmap.org/book/man-legal.html
--

local base64    = require "base64"
local comm      = require "comm"
local match     = require "match"
local stdnse    = require "stdnse"
local stringaux = require "stringaux"

local string = string
local table  = table

_ENV = stdnse.module("pop3", stdnse.seeall)

local HAVE_SSL, openssl = pcall(require, "openssl")

-- Error codes returned by login helpers
local err = {
  none                = 0,
  userError           = 1,
  pwError             = 2,
  informationMissing  = 3,
  OpenSSLMissing      = 4,
}

---
-- Check whether a POP3 response indicates success.
-- @param line POP3 response line
-- @return true if response starts with "+OK"
local function stat(line)
  return type(line) == "string" and line:match("^%+OK")
end

---
-- USER / PASS authentication
function login_user(socket, user, pw)
  socket:send("USER " .. user .. "\r\n")
  local _, line = socket:receive_lines(1)
  if not stat(line) then
    return false, err.userError
  end

  socket:send("PASS " .. pw .. "\r\n")
  _, line = socket:receive_lines(1)

  if stat(line) then
    return true, err.none
  end

  return false, err.pwError
end

---
-- SASL PLAIN authentication
function login_sasl_plain(socket, user, pw)
  local auth64 = base64.enc(user .. "\0" .. user .. "\0" .. pw)
  socket:send("AUTH PLAIN " .. auth64 .. "\r\n")

  local _, line = socket:receive_lines(1)
  if stat(line) then
    return true, err.none
  end

  return false, err.pwError
end

---
-- SASL LOGIN authentication
function login_sasl_login(socket, user, pw)
  socket:send("AUTH LOGIN\r\n")

  local _, line = socket:receive_lines(1)
  local prompt = base64.dec(string.sub(line or "", 3)):lower()

  if not prompt:find("user") then
    return false, err.userError
  end

  socket:send(base64.enc(user) .. "\r\n")
  _, line = socket:receive_lines(1)

  prompt = base64.dec(string.sub(line or "", 3)):lower()
  if not prompt:find("pass") then
    return false, err.userError
  end

  socket:send(base64.enc(pw) .. "\r\n")
  _, line = socket:receive_lines(1)

  if stat(line) then
    return true, err.none
  end

  return false, err.pwError
end

---
-- APOP authentication (RFC 1939)
function login_apop(socket, user, pw, challenge)
  if not HAVE_SSL then
    return false, err.OpenSSLMissing
  end

  if type(challenge) ~= "string" then
    return false, err.informationMissing
  end

  local digest = stdnse.tohex(openssl.md5(challenge .. pw))
  socket:send(("APOP %s %s\r\n"):format(user, digest))

  local _, line = socket:receive_lines(1)
  if stat(line) then
    return true, err.none
  end

  return false, err.pwError
end

---
-- SASL CRAM-MD5 authentication
function login_sasl_crammd5(socket, user, pw)
  if not HAVE_SSL then
    return false, err.OpenSSLMissing
  end

  socket:send("AUTH CRAM-MD5\r\n")
  local _, line = socket:receive_lines(1)

  local challenge = base64.dec(string.sub(line or "", 3))
  local digest = stdnse.tohex(openssl.hmac("md5", pw, challenge))
  local auth = base64.enc(user .. " " .. digest)

  socket:send(auth .. "\r\n")
  _, line = socket:receive_lines(1)

  if stat(line) then
    return true, err.none
  end

  return false, err.pwError
end

---
-- Query POP3 server capabilities (RFC 2449)
function capabilities(host, port)
  local socket, _, _, greeting =
    comm.tryssl(host, port, "", { recv_before = true })

  if not socket then
    return nil, "Could not connect"
  end

  if not stat(greeting) then
    socket:close()
    return nil, "Invalid POP3 greeting"
  end

  local capas = {}

  -- APOP challenge present in greeting
  if greeting:find("<[^>]+>") then
    capas.APOP = {}
  end

  socket:send("CAPA\r\n")
  local status, response =
    socket:receive_buf(match.pattern_limit("%.\r?\n", 4096), false)

  socket:close()
  if not status then
    return nil, "Failed to receive CAPA response"
  end

  local lines = stringaux.strsplit("\r\n", response)
  if not stat(table.remove(lines, 1)) then
    capas.capa = false
    return capas
  end

  for _, line in ipairs(lines) do
    if line and #line > 0 then
      local name, args = line:match("^(%S+)%s*(.*)")
      capas[name] = args ~= "" and stringaux.strsplit(" ", args) or {}
    end
  end

  return capas
end

return _ENV
