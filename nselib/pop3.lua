---
-- POP3 helper functions for NSE scripts.
<<<<<<< Updated upstream
--
-- @copyright Same as Nmap
-- See https://nmap.org/book/man-legal.html
=======
>>>>>>> Stashed changes
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

<<<<<<< Updated upstream
-- Error codes returned by login helpers
local err = {
  none                = 0,
  userError           = 1,
  pwError             = 2,
  informationMissing  = 3,
  OpenSSLMissing      = 4,
=======
-- Error codes returned by login helpers.
-- Must remain module-level so scripts can access pop3.err.*
err = {
  none               = 0,
  userError          = 1,
  pwError            = 2,
  informationMissing = 3,
  OpenSSLMissing     = 4,
>>>>>>> Stashed changes
}

---
-- Check whether a POP3 response indicates success.
<<<<<<< Updated upstream
-- @param line POP3 response line
-- @return true if response starts with "+OK"
function stat(line)
  return type(line) == "string" and line:match("^%+OK")
end

---
-- USER / PASS authentication
=======
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
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes
  return false, err.pwError
end

---
<<<<<<< Updated upstream
-- SASL PLAIN authentication
=======
-- SASL PLAIN authentication.
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
>>>>>>> Stashed changes
function login_sasl_plain(socket, user, pw)
  local auth64 = base64.enc(user .. "\0" .. user .. "\0" .. pw)
  socket:send("AUTH PLAIN " .. auth64 .. "\r\n")

  local _, line = socket:receive_lines(1)
  if stat(line) then
    return true, err.none
  end
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes
  return false, err.pwError
end

---
<<<<<<< Updated upstream
-- SASL LOGIN authentication
=======
-- SASL LOGIN authentication.
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
>>>>>>> Stashed changes
function login_sasl_login(socket, user, pw)
  socket:send("AUTH LOGIN\r\n")

  local _, line = socket:receive_lines(1)
<<<<<<< Updated upstream
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

=======
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

>>>>>>> Stashed changes
  socket:send(base64.enc(pw) .. "\r\n")
  _, line = socket:receive_lines(1)

  if stat(line) then
    return true, err.none
  end
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes
  return false, err.pwError
end

---
<<<<<<< Updated upstream
-- APOP authentication (RFC 1939)
=======
-- APOP authentication (RFC 1939).
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @param challenge APOP challenge string from the server greeting.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
>>>>>>> Stashed changes
function login_apop(socket, user, pw, challenge)
  if not HAVE_SSL then
    return false, err.OpenSSLMissing
  end
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes
  if type(challenge) ~= "string" then
    return false, err.informationMissing
  end

  local digest = stdnse.tohex(openssl.md5(challenge .. pw))
  socket:send(("APOP %s %s\r\n"):format(user, digest))

  local _, line = socket:receive_lines(1)
  if stat(line) then
    return true, err.none
  end
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes
  return false, err.pwError
end

---
<<<<<<< Updated upstream
-- SASL CRAM-MD5 authentication
=======
-- SASL CRAM-MD5 authentication.
-- @param socket Socket connected to POP3 server.
-- @param user Username string.
-- @param pw Password string.
-- @return status true on success, false on failure.
-- @return err Error code if status is false.
>>>>>>> Stashed changes
function login_sasl_crammd5(socket, user, pw)
  if not HAVE_SSL then
    return false, err.OpenSSLMissing
  end

  socket:send("AUTH CRAM-MD5\r\n")
  local _, line = socket:receive_lines(1)
<<<<<<< Updated upstream

  local challenge = base64.dec(string.sub(line or "", 3))
  local digest = stdnse.tohex(openssl.hmac("md5", pw, challenge))
  local auth = base64.enc(user .. " " .. digest)
=======
  if type(line) ~= "string" or line:sub(1, 1) ~= "+" then
    return false, err.pwError
  end

  local challenge = base64.dec(line:sub(3))
  local digest    = stdnse.tohex(openssl.hmac("md5", pw, challenge))
  local auth      = base64.enc(user .. " " .. digest)
>>>>>>> Stashed changes

  socket:send(auth .. "\r\n")
  _, line = socket:receive_lines(1)

  if stat(line) then
    return true, err.none
  end
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes
  return false, err.pwError
end

---
<<<<<<< Updated upstream
-- Query POP3 server capabilities (RFC 2449)
=======
-- Query POP3 server capabilities (RFC 2449).
-- @param host Host to query.
-- @param port Port to connect to.
-- @return capas Table of capabilities, or nil on error.
-- @return nil or error string on failure.
>>>>>>> Stashed changes
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

<<<<<<< Updated upstream
  -- APOP challenge present in greeting
  if greeting:find("<[^>]+>") then
=======
  -- APOP challenge must match <process-ID.clock@hostname> per RFC 1939
  if greeting:find("<[^>]+@[^>]+>") then
>>>>>>> Stashed changes
    capas.APOP = {}
  end

  socket:send("CAPA\r\n")
  local status, response =
    socket:receive_buf(match.pattern_limit("%.\r?\n", 4096), false)
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes
  socket:close()
  if not status then
    return nil, "Failed to receive CAPA response"
  end

<<<<<<< Updated upstream
  local lines = stringaux.strsplit("\r\n", response)
=======
  if not status then
    return nil, "Failed to receive CAPA response"
  end

  -- Normalize line endings to handle both CRLF and LF-only servers
  response = response:gsub("\r\n", "\n")
  local lines = stringaux.strsplit("\n", response)

>>>>>>> Stashed changes
  if not stat(table.remove(lines, 1)) then
    capas.capa = false
    return capas
  end

<<<<<<< Updated upstream
  for _, line in ipairs(lines) do
    if line and #line > 0 then
      local name, args = line:match("^(%S+)%s*(.*)")
      capas[name] = args ~= "" and stringaux.strsplit(" ", args) or {}
=======
  for _, ln in ipairs(lines) do
    if ln and #ln > 0 then
      local name, args = ln:match("^(%S+)%s*(.*)")
      if name then
        capas[name] = args ~= "" and stringaux.strsplit(" ", args) or {}
      end
>>>>>>> Stashed changes
    end
  end

  return capas
end

return _ENV
