--- POP3 functions
--@copyright See nmaps COPYING for licence

module(... or "pop3",package.seeall)

require 'base64'
require 'bit'


err = {
   none = 0,
   userError = 1,
   pwError = 2,
   informationMissing = 3
}

---
-- Checks POP3 response for 
--@param line First line returned from an POP3 request
--@return Found "+OK" string or nil
function stat(line)
   return string.match(line, "+OK")
end



---
-- Try to login using USER/PASS commands
--@param socket Socket connected to POP3 server
--@param user User string
--@param pw Password string
--@return Success as boolean and error code as in err table
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
-- Try to login using AUTH command using SASL/Plain method
--@param socket Socket connected to POP3 server
--@param user User string
--@param pw Password string
--@return Success as boolean and error code as in err table
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
-- Try to login using AUTH command using SASL/Login method
--@param user User string
--@param pw Password string
--@param pw String containing password to login
--@return Success as boolean and error code as in err table
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
-- Try to login using APOP command
--@param socket Socket connected to POP3 server
--@param user User string
--@param pw Password string
--@param challenge String containing challenge from POP3 server greeting
--@return Success as boolean and error code as in err table
function login_apop(socket, user, pw, challenge)
   if type(challenge) ~= "string" then return false, err.informationMissing end

   local apStr = hash.md5(challenge .. pw)
   socket:send("APOP " .. user .. " " .. apStr .. "\r\n")
      
   status, line = socket:receive_lines(1)
   
   if (stat(line)) then 
      return true, err.none
   else
      return false, err.pwError
   end
end

---
-- Asks POP3 server for capabilities
--@param host Host to be queried
--@param port Port to connect to
--@return Table containing capabilities
function capabilities(host, port)
   local socket = nmap.new_socket()
   local capas = {}
   if not socket:connect(host.ip, port.number) then return "no conn" end
   
   status, line = socket:receive_lines(1)
   if not stat(line) then return "no popconn" end
   
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
-- Calculate HMAC-MD5 hash
--@param key Key for hash calculation
--@param msg Message to be hashed
--@return HMAC-MD5 of given message
function hmacMD5(key, msg)
   local ipad = {}
   local opad = {}

   if (string.len(key) > 64) then
      key = hash.md5binary(key)
   end

   -- create both pads, XORing with key
   for i = 1, string.len(key) do
      ipad[i] = string.char(bit.bxor(0x36, string.byte(string.sub(key, i))))
      opad[i] = string.char(bit.bxor(0x5c, string.byte(string.sub(key, i))))
   end
   for i = #ipad + 1, 64 do
      ipad[i] = string.char(0x36)
      opad[i] = string.char(0x5c)
   end

   -- calc HMAC-md5
   return hash.md5(table.concat(opad) .. hash.md5bin(table.concat(ipad) .. msg))
end

---
-- Try to login using AUTH command using SASL/CRAM-MD5 method
--@param socket Socket connected to POP3 server
--@param user User string
--@param pw Password string
--@return Success as boolean and error code as in err table
function login_sasl_crammd5(socket, user, pw)

   socket:send("AUTH CRAM-MD5\r\n")
   
   status, line = socket:receive_lines(1)
   
   local challenge = base64.dec(string.sub(line, 3))

   local digest = hmacMD5(pw, challenge)
   local authStr = base64.enc(user .. " " .. digest)
   socket:send(authStr .. "\r\n")
      
   status, line = socket:receive_lines(1)
   
   if stat(line) then 
      return true, err.none
   else 
      return false, err.pwError
   end
end
