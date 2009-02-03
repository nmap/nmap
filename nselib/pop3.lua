--- POP3 functions.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "pop3",package.seeall)

local HAVE_SSL = false

require 'base64'
require 'bit'
require 'stdnse'

if pcall(require,'openssl') then
  HAVE_SSL = true
end
  


err = {
   none = 0,
   userError = 1,
   pwError = 2,
   informationMissing = 3,
   OpenSSLMissing = 4,
}

---
-- Check a POP3 response for <code>"+OK"</code>.
-- @param line First line returned from an POP3 request.
-- @return The string <code>"+OK"</code> if found or <code>nil</code> otherwise.
function stat(line)
   return string.match(line, "+OK")
end



---
-- Try to log in using the <code>USER</code>/<code>PASS</code> commands.
-- @param socket Socket connected to POP3 server.
-- @param user User string.
-- @param pw Password string.
-- @return Status (true or false).
-- @return Error code if status is false.
function login_user(socket, user, pw)
   socket:send("USER " .. user .. "\r\n")
   status, line = socket:receive_lines(1)
   if not stat(line) then return false, err.user_error end
   socket:send("PASS " .. pw .. "\r\n")
      
   status, line = socket:receive_lines(1)
      
   if stat(line) then return true, err.none 
   else return false, err.pwError
   end
end


---
-- Try to login using the the <code>AUTH</code> command using SASL/Plain method.
-- @param socket Socket connected to POP3 server.
-- @param user User string.
-- @param pw Password string.
-- @return Status (true or false).
-- @return Error code if status is false.
function login_sasl_plain(socket, user, pw)
   
   local auth64 = base64.enc(user .. "\0" .. user .. "\0" .. pw)
   socket:send("AUTH PLAIN " .. auth64 .. "\r\n")
   
   status, line = socket:receive_lines(1)
   
   if stat(line) then 
      return true, err.none
   else 
      return false, err.pwError
   end
end

---
-- Try to login using the <code>AUTH</code> command using SASL/Login method.
-- @param user User string.
-- @param pw Password string.
-- @param pw String containing password to login.
-- @return Status (true or false).
-- @return Error code if status is false.
function login_sasl_login(socket, user, pw)

   local user64 = base64.enc(user)
   
   local pw64 = base64.enc(pw)

   socket:send("AUTH LOGIN\r\n")
      
   status, line = socket:receive_lines(1)
   if not base64.dec(string.sub(line, 3)) == "User Name:" then 
      return false, err.userError 
   end

   socket:send(user64)
      
   status, line = socket:receive_lines(1)

   if not base64.dec(string.sub(line, 3)) == "Password:" then 
      return false, err.userError
   end

   socket:send(pw64)
      
   status, line = socket:receive_lines(1)
    
   if stat(line) then
      return true, err.none
   else
      return false, err.pwError
   end
end

---
-- Try to login using the <code>APOP</code> command.
-- @param socket Socket connected to POP3 server.
-- @param user User string.
-- @param pw Password string.
-- @param challenge String containing challenge from POP3 server greeting.
-- @return Status (true or false).
-- @return Error code if status is false.
function login_apop(socket, user, pw, challenge)
   if type(challenge) ~= "string" then return false, err.informationMissing end

   local apStr = stdnse.tohex(openssl.md5(challenge .. pw))
   socket:send(("APOP %s %s\r\n"):format(user, apStr))
      
   status, line = socket:receive_lines(1)
   
   if (stat(line)) then 
      return true, err.none
   else
      return false, err.pwError
   end
end

---
-- Asks a POP3 server for capabilities.
--
-- See RFC 2449.
-- @param host Host to be queried.
-- @param port Port to connect to.
-- @return Table containing capabilities or nil on error.
-- @return nil or String error message.
function capabilities(host, port)
   local socket = nmap.new_socket()
   local capas = {}
   socket:set_timeout(10000)
   if not socket:connect(host.ip, port.number) then return nil, "Could Not Connect" end

   status, line = socket:receive_lines(1)
   if not stat(line) then return nil, "No Response" end
   
   if string.find(line, "<[%p%w]+>") then capas.APOP = true end
   
   socket:send("CAPA\r\n")
   status, line = socket:receive_buf("\r\n", false)
   if not stat(line) then 
      capas.capa = false
   else 
      status, line = socket:receive_buf("\r\n", false)
      while line do
	 if line ~= "." then
	    local capability = string.sub(line, string.find(line, "[%w-]+"))
	    line = string.sub(line, #capability + 1)
	    capas[capability] = true
	    local args = {}
	    local w
	    for w in string.gmatch(line, "[%w-]+") do
	       table.insert(args, w)
	    end
	    if #args == 1 then capas[capability] = args[1]
	    else if #args > 1 then capas[capability] = args 
	    end end
	 else
	    break 
	 end
	 status, line = socket:receive_buf("\r\n", false)
      end
   end
   socket:close()
   return capas
end

---
-- Try to login using the <code>AUTH</code> command using SASL/CRAM-MD5 method.
-- @param socket Socket connected to POP3 server.
-- @param user User string.
-- @param pw Password string.
-- @return Status (true or false).
-- @return Error code if status is false.
function login_sasl_crammd5(socket, user, pw)

   socket:send("AUTH CRAM-MD5\r\n")
   
   status, line = socket:receive_lines(1)
   
   local challenge = base64.dec(string.sub(line, 3))

   local digest = stdnse.tohex(openssl.hmac('md5', pw, challenge))
   local authStr = base64.enc(user .. " " .. digest)
   socket:send(authStr .. "\r\n")
      
   status, line = socket:receive_lines(1)
   
   if stat(line) then 
      return true, err.none
   else 
      return false, err.pwError
   end
end

-- Overwrite functions requiring OpenSSL if we got no OpenSSL.
if not HAVE_SSL then

  local no_ssl = function()
    return false, err.OpenSSLMissing
  end

  login_apop = no_ssl
  login_sasl_crammd5 = no_ssl
end

