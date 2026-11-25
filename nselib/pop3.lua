---
-- POP3 helper functions for NSE scripts.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local base64    = require "base64"
local comm      = require "comm"
local match     = require "match"
local stdnse    = require "stdnse"
local stringaux = require "stringaux"

local string = string
local table  = table

_ENV = stdnse.module("pop3", stdnse.seeall)

local HAVE_SSL, openssl = pcall(require, "openssl")

-- Error codes returned by login helpers.
-- Must remain module-level so scripts can access pop3.err.*
err = {
  none               = 0,
  userError          = 1,
  pwError            = 2,
  informationMissing = 3,
  OpenSSLMissing     = 4,
}

---
-- Check whether a POP3 response indicates success.
-- @param line POP3 response line.
-- @return true if response starts with "+OK", false otherwise.
function stat(line)
  return type(line) == "string" and line:match("^%+OK") ~= nil
end

---
-- USER/PASS authentication.
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
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
-- SASL PLAIN authentication.
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
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
-- SASL LOGIN authentication.
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
function login_sasl_login(socket, user, pw)
  socket:send("AUTH LOGIN\r\n")

  local _, line = socket:receive_lines(1)
  if type(line) ~= "string" or line:sub(1, 1) ~= "+" then
    return false, err.userError
  end

  local prompt = base64.dec(line:sub(3)):lower()
  if not prompt:find("user") then
    return false, err.userError
  end

  socket:send(base64.enc(user) .. "\r\n")
  _, line = socket:receive_lines(1)
  if type(line) ~= "string" or line:sub(1, 1) ~= "+" then
    return false, err.userError
  end

  prompt = base64.dec(line:sub(3)):lower()
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
-- APOP authentication (RFC 1939).
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @param challenge APOP challenge string from the server greeting.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
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
-- SASL CRAM-MD5 authentication.
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
function login_sasl_crammd5(socket, user, pw)
  if not HAVE_SSL then
    return false, err.OpenSSLMissing
  end

  socket:send("AUTH CRAM-MD5\r\n")
  local _, line = socket:receive_lines(1)
  if type(line) ~= "string" or line:sub(1, 1) ~= "+" then
    return false, err.pwError
  end

  local challenge = base64.dec(line:sub(3))
  local digest    = stdnse.tohex(openssl.hmac("md5", pw, challenge))
  local auth      = base64.enc(user .. " " .. digest)

  socket:send(auth .. "\r\n")
  _, line = socket:receive_lines(1)

  if stat(line) then
    return true, err.none
  end
  return false, err.pwError
end

---
-- Query POP3 server capabilities (RFC 2449).
-- @param host Host to query.
-- @param port Port to connect to.
-- @return capas Table of capabilities, or nil on error.
-- @return nil or error string on failure.
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

  -- APOP challenge must match <process-ID.clock@hostname> per RFC 1939
  if greeting:find("<[^>]+@[^>]+>") then
    capas.APOP = {}
  end

  socket:send("CAPA\r\n")
  local status, response =
    socket:receive_buf(match.pattern_limit("%.\r?\n", 4096), false)
  socket:close()

  if not status then
    return nil, "Failed to receive CAPA response"
  end

  -- Normalize line endings to handle both CRLF and LF-only servers
  response = response:gsub("\r\n", "\n")
  local lines = stringaux.strsplit("\n", response)

  if not stat(table.remove(lines, 1)) then
    capas.capa = false
    return capas
  end

  for _, ln in ipairs(lines) do
    if ln and #ln > 0 then
      local name, args = ln:match("^(%S+)%s*(.*)")
      if name then
        capas[name] = args ~= "" and stringaux.strsplit(" ", args) or {}
      end
    end
  end

  return capas
end

return _ENV
